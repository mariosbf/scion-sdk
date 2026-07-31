//! Hummingbird path type and associated encoding.

use std::ops::Deref;
use std::sync::{Arc, Mutex};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::{DateTime, Utc};

use crate::{
    address::IsdAsn,
    hummingbird::{FlyoverMACs, Reservation},
    packet::{
        ByEndpoint, CommonHeader, DecodeError, InadequateBufferSize, NonEncodeError,
        NonScmpEncodeError,
    },
    path::{
        DataPlanePath, EncodedHopField, EncodedInfoField, EncodedSegment, EncodedSegments,
        EncodedStandardHopField, EncodedStandardPath, HopField, HopFieldIndex, InfoField,
        InfoFieldIndex, InfoFields, MetaHeader, MetaReserved, Path, PathProvider, SegmentLength,
        StandardHopField,
        hummingbird::{
            EncodedFlyoverHopField, FlyoverHopField, HummingbirdBaseTimestamp, HummingbirdCounter,
            HummingbirdHopField, HummingbirdHopFields, HummingbirdHopfieldIndex,
            HummingbirdInfoFieldIndex, HummingbirdMetaHeader, HummingbirdMetaReserved,
            HummingbirdMillisTimestamp, HummingbirdSegmentLength,
            flyover_mac_path::{
                generate_flyover_macs_from_reservations, packet_length_for_payload_with_flyovers,
            },
            reservation_tracker::{ReservationTracker, ReservationTrackerError},
        },
        metadata::{Metadata, PathInterface},
    },
    wire_encoding::{WireDecode, WireEncode},
};

/// The Hummingbird SCION path header.
///
/// Consists of a [`HummingbirdMetaHeader`] along with one or more info fields,
/// and hop fields/flyover hop fields.
#[derive(Debug, Clone, PartialEq)]
pub struct EncodedHummingbirdPath<T = Bytes> {
    /// The meta information about the stored path.
    pub(crate) meta_header: HummingbirdMetaHeader,
    /// The raw data containing the meta_header, info, and hop fields.
    pub(crate) encoded_path: T,
}

/// The Hummingbird path header with a mutable encoded path.
pub type EncodedHummingbirdPathMut = EncodedHummingbirdPath<BytesMut>;

impl<T> EncodedHummingbirdPath<T> {
    /// Returns the metadata about the stored path.
    pub fn meta_header(&self) -> &HummingbirdMetaHeader {
        &self.meta_header
    }
}

/// Type aliases for the segments of a Hummingbird path.
/// See [EncodedSegment] and [HummingbirdHopFields].
pub type EncodedHummingbirdSegment<'a> = EncodedSegment<'a, HummingbirdHopFields<'a>>;

/// Type alias for the segments of a Hummingbird path.
/// See [EncodedSegments] and [HummingbirdHopFields].
pub type EncodedHummingbirdSegments<'a> = EncodedSegments<'a, HummingbirdHopFields<'a>>;

impl<T> EncodedHummingbirdPath<T>
where
    T: Deref<Target = [u8]>,
{
    /// Returns the encoded raw path.
    pub fn raw(&self) -> &[u8] {
        &self.encoded_path
    }

    /// Creates new HummingbirdPath, backed by the provided buffer,
    /// by copying this one.
    ///
    /// # Panics
    ///
    /// Panics if the provided buffer does not have the same length as self.raw().
    pub fn copy_to_slice<'b>(&self, buffer: &'b mut [u8]) -> EncodedHummingbirdPath<&'b mut [u8]> {
        buffer.copy_from_slice(&self.encoded_path);
        EncodedHummingbirdPath {
            meta_header: self.meta_header,
            encoded_path: buffer,
        }
    }

    /// Returns the [`EncodedInfoField`] at the specified index, if within range.
    ///
    /// The index is the index into the path's info fields, and can be at most 3.
    pub fn info_field(&self, index: usize) -> Option<&EncodedInfoField> {
        if index < self.meta_header.info_fields_count() {
            let start = HummingbirdMetaHeader::info_field_offset(index);
            let slice = &self.encoded_path[start..(start + EncodedInfoField::LENGTH)];
            Some(EncodedInfoField::new(slice))
        } else {
            None
        }
    }

    /// Returns the segment at the specified index, if any.
    ///
    /// There are always at most 3 segments.
    pub fn segment(&self, segment_index: usize) -> Option<EncodedHummingbirdSegment<'_>> {
        let info_field = self.info_field(segment_index)?;

        // Get the byte offset of the first hop field in the segment.
        let hop_index: usize = self.meta_header().segment_lengths[..segment_index]
            .iter()
            .map(|seglen| seglen.length())
            .sum();

        let segment_len: usize = self.meta_header.segment_lengths[segment_index].length();
        debug_assert_ne!(segment_len, 0);

        let hop_data_start = HummingbirdMetaHeader::info_field_offset(0)
            + self.meta_header.info_fields_count() * EncodedInfoField::LENGTH;
        let start = hop_data_start + hop_index;
        let stop = start + segment_len;

        Some(EncodedSegment::new(
            info_field,
            HummingbirdHopFields::new(&self.encoded_path[start..stop]),
        ))
    }

    /// Returns an iterator over the segments of this path.
    pub fn segments(&self) -> EncodedHummingbirdSegments<'_> {
        EncodedSegments::new([self.segment(0), self.segment(1), self.segment(2)])
    }

    /// Returns the expiry time of the path.
    ///
    /// This is the minimum expiry time of each of its segments.
    pub fn expiry_time(&self) -> DateTime<Utc> {
        self.segments()
            .map(|seg| seg.expiry_time())
            .min()
            .expect("at least 1 segment")
    }

    /// Returns an iterator over all the [`EncodedInfoField`]s in the Hummingbird
    /// path.
    pub fn info_fields(&self) -> InfoFields<'_> {
        let start = HummingbirdMetaHeader::info_field_offset(0);
        let stop = start + self.meta_header.info_fields_count() * EncodedInfoField::LENGTH;

        InfoFields::new(&self.encoded_path[start..stop])
    }

    /// Returns an iterator over all of the [`EncodedHummingbirdHopField`]s in
    /// the path.
    pub fn hop_fields(&self) -> HummingbirdHopFields<'_> {
        let start = HummingbirdMetaHeader::info_field_offset(0)
            + self.meta_header.info_fields_count() * EncodedInfoField::LENGTH;
        let stop = self.meta_header.encoded_path_length();

        HummingbirdHopFields::new(&self.encoded_path[start..stop])
    }

    /// Returns the number of hop fields in the path.
    ///
    /// Note: This operation is more expensive than for regular SCION paths,
    /// since the number of hop fields cannot easily be determined from the length
    /// of the encoding of the path.
    pub fn hop_fields_count(&self) -> usize {
        self.hop_fields().count()
    }

    /// Returns an iterator over all of the [`EncodedFlyoverHopField`]s in the path.
    pub fn flyover_hop_fields(&self) -> impl Iterator<Item = &'_ EncodedFlyoverHopField> {
        self.hop_fields()
            .filter_map(|hop_field| hop_field.try_into().ok())
    }

    /// Returns an iterator over all of the [`EncodedHopField`]s in the path.
    pub fn regular_hop_fields(&self) -> impl Iterator<Item = &'_ EncodedStandardHopField> {
        self.hop_fields()
            .filter_map(|hop_field| hop_field.try_into().ok())
    }

    /// Returns the interface through which a packet originating in this path's
    /// first AS leaves that AS.
    ///
    /// See [`EncodedStandardPath::first_egress_interface`] for why this is not
    /// the first item of [`Self::iter_interfaces`].
    pub fn first_egress_interface(&self) -> Option<std::num::NonZeroU16> {
        let segment = self.segments().next()?;
        let hop_field = segment.hop_fields().next()?;

        if segment.info_field().is_constructed_dir() {
            hop_field.cons_egress_interface()
        } else {
            hop_field.cons_ingress_interface()
        }
    }

    /// Returns an iterator over the path's interfaces in order of traversal.
    pub fn iter_interfaces(&self) -> impl Iterator<Item = std::num::NonZeroU16> {
        self.segments().flat_map(|seg| {
            let info_field = seg.info_field();
            let cons_dir = info_field.is_constructed_dir();

            seg.hop_fields()
                .flat_map(move |hop_field| match cons_dir {
                    true => [
                        hop_field.cons_ingress_interface(),
                        hop_field.cons_egress_interface(),
                    ]
                    .into_iter(),
                    false => [
                        hop_field.cons_egress_interface(),
                        hop_field.cons_ingress_interface(),
                    ]
                    .into_iter(),
                })
                .flatten()
        })
    }

    /// Returns the length of the encoding of the reversed path.
    pub fn reversed_path_length(&self) -> usize {
        self.meta_header.encoded_path_length()
            - (HummingbirdMetaHeader::LENGTH - MetaHeader::LENGTH)
            - self.flyover_hop_fields().count()
                * (FlyoverHopField::ENCODED_SIZE - StandardHopField::ENCODED_SIZE)
    }

    /// Creates a new, reversed StandardPath obtained with the provided buffer.
    ///
    /// Indices are carried over to their current position in reverse.
    ///
    /// The resulting path is suitable for use by end hosts, if the MACs in all
    /// flyover hop fields are de-aggregated. This should be the case if the
    /// path was obtained from the header of an incoming SCION packet, since
    /// border routers are expected to de-aggregate flyover hop fields before
    /// forwarding the packet to an end-host.
    ///
    /// # Panics
    ///
    /// Panics if the provided buffer does not have the same length as the
    /// encoding of the reversed path. This may not be the same as the length of
    /// the original path, since flyover hop fields are replaced with regular hop
    /// fields in the reversed path, and these have different sizes. The length of
    /// the reversed path can be obtained with
    /// [reversed_path_length][Self::reversed_path_length].
    pub fn reverse_to_slice<'b>(&self, buffer: &'b mut [u8]) -> EncodedStandardPath<&'b mut [u8]> {
        let meta_header = self.reversed_meta_header();

        assert_eq!(
            buffer.len(),
            meta_header.encoded_path_length(),
            "buffer must have the same length as the encoded reversed path"
        );

        let mut buf_mut: &mut [u8] = buffer;

        meta_header.encode_to_unchecked(&mut buf_mut);
        self.write_reversed_info_fields_to(&mut buf_mut);
        self.write_reversed_hop_fields_to(&mut buf_mut);

        EncodedStandardPath {
            meta_header,
            encoded_path: buffer,
        }
    }

    /// Reverses both the raw path and the metadata.
    ///
    /// The resulting path is suitable for use from an end-host, if the MACs in
    /// all flyover hop fields are de-aggregated. This should be the case if the
    /// path was obtained from the header of an incoming SCION packet, since
    /// border routers are expected to de-aggregate flyover hop fields before
    /// forwarding the packet to an end-host.
    ///
    /// The current hop and info field indices of the reversed path are set to 0.
    pub fn to_reversed(&self) -> EncodedStandardPath<Bytes> {
        let mut buffer = vec![0u8; self.reversed_path_length()];
        let EncodedStandardPath { meta_header, .. } = self.reverse_to_slice(&mut buffer);

        EncodedStandardPath {
            meta_header,
            encoded_path: buffer.into(),
        }
    }

    /// Returns the number of hop fields in each of the three segments.
    fn segment_hop_field_counts(&self) -> [u8; 3] {
        let mut result = self
            .segments()
            .map(|seg| seg.hop_fields().count() as u8)
            .collect::<Vec<_>>();

        while result.len() < 3 {
            result.push(0);
        }

        result
            .try_into()
            .expect("segments() returns at most 3 segments")
    }

    fn reversed_meta_header(&self) -> MetaHeader {
        // Construct new meta header
        let meta_header = self.meta_header();
        let final_info_idx = meta_header.info_fields_count().saturating_sub(1) as u8;
        let reversed_info_idx = final_info_idx.saturating_sub(meta_header.current_info_field.get());
        let reversed_info_idx = InfoFieldIndex::new_unchecked(reversed_info_idx);

        // The current hop field index in the meta header is an offset (not a hop field count),
        // so we need to determine the index of the hop field it points to in order to reverse it.
        let mut curr_offset = 0;
        let mut curr_index = 0;
        for hop_field in self.hop_fields() {
            if curr_offset == meta_header.current_hop_field.byte_offset() {
                break;
            }

            if hop_field.is_flyover() {
                curr_offset += FlyoverHopField::ENCODED_SIZE;
            } else {
                curr_offset += StandardHopField::ENCODED_SIZE;
            }
            curr_index += 1;
        }

        let final_hop_idx = self.hop_fields_count().saturating_sub(1) as u8;
        let reversed_hop_idx = final_hop_idx.saturating_sub(curr_index);
        let reversed_hop_idx = HopFieldIndex::new_unchecked(reversed_hop_idx);

        MetaHeader {
            current_info_field: reversed_info_idx,
            current_hop_field: reversed_hop_idx,
            reserved: MetaReserved::default(),
            segment_lengths: match self.segment_hop_field_counts() {
                // UNCHECKED: A Hummingbird segment length field is 7 bits long, so it can never
                // exceed 127. Therefore, the length of the segment in bytes is at most 127 * 4 =
                // 508 bytes. This means that a Hummingbird segment cannot have more than
                // floor(508 / 12) = 42 hop fields (since each hop field is at least 12 bytes long).
                // The value 42 fits into the 6-bit segment length field of a regular SCION
                // path.
                [0, ..] => [SegmentLength::new_unchecked(0); 3],
                [s1, 0, ..] => [
                    SegmentLength::new_unchecked(s1),
                    SegmentLength::new_unchecked(0),
                    SegmentLength::new_unchecked(0),
                ],
                [s1, s2, 0] => [
                    SegmentLength::new_unchecked(s2),
                    SegmentLength::new_unchecked(s1),
                    SegmentLength::new_unchecked(0),
                ],
                [s1, s2, s3] => [
                    SegmentLength::new_unchecked(s3),
                    SegmentLength::new_unchecked(s2),
                    SegmentLength::new_unchecked(s1),
                ],
            },
        }
    }

    /// Writes the info fields to the provided buffer in reversed order.
    ///
    /// This also flips the "construction direction flag" for all info fields.
    fn write_reversed_info_fields_to(&self, buffer: &mut &mut [u8]) {
        for info_field in self.info_fields().rev() {
            let data = info_field.as_ref();
            buffer.put_u8(data[0] ^ InfoField::FLAGS_CONS_DIR);
            buffer.put_slice(&data[1..]);
        }
    }

    /// Writes the hop fields to the provided buffer in reversed order.
    ///
    /// Flyover hop fields are converted to standard hop fields by discarding the
    /// reservation-specific bytes (ResID, BW, ResStartOffset, ResDuration) and
    /// clearing the flyover bit.
    fn write_reversed_hop_fields_to(&self, buffer: &mut &mut [u8]) {
        self.hop_fields()
            .map(|hop_field| {
                let mut bytes = [0u8; StandardHopField::ENCODED_SIZE];
                bytes.copy_from_slice(hop_field.standard_hopfield_unchecked().as_ref());
                bytes[0] &= !FlyoverHopField::FLYOVER_BIT;
                bytes
            })
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .for_each(|bytes| buffer.put_slice(&bytes));
    }
}

impl EncodedHummingbirdPath {
    /// Converts a Hummingird path over an immutable reference to one over an
    /// mutable reference.
    ///
    /// This requires copying the encoded path.
    pub fn to_mut(&self) -> EncodedHummingbirdPathMut {
        let mut encoded_path = BytesMut::zeroed(self.encoded_path.len());
        encoded_path.copy_from_slice(self.encoded_path.as_ref());
        EncodedHummingbirdPath {
            meta_header: self.meta_header,
            encoded_path,
        }
    }
}

impl EncodedHummingbirdPathMut {
    /// Converts a Hummingbird path over a mutable reference to one over an
    /// immutable reference.
    pub fn freeze(self) -> EncodedHummingbirdPath {
        EncodedHummingbirdPath {
            meta_header: self.meta_header,
            encoded_path: self.encoded_path.freeze(),
        }
    }
}

impl<'b> EncodedHummingbirdPath<&'b mut [u8]> {
    /// Converts a Hummingbird path over a mutable reference to one over an
    /// immutable reference.
    pub fn freeze(self) -> EncodedHummingbirdPath<&'b [u8]> {
        EncodedHummingbirdPath {
            meta_header: self.meta_header,
            encoded_path: &*self.encoded_path,
        }
    }
}

impl EncodedHummingbirdPath<Bytes> {
    /// Creates a deep copy of this path.
    pub fn deep_copy(&self) -> Self {
        Self {
            meta_header: self.meta_header,
            encoded_path: Bytes::copy_from_slice(&self.encoded_path),
        }
    }

    /// Creates a new path using the Bytes of this path as backing storage
    pub fn to_slice_path(&self) -> EncodedHummingbirdPath<&[u8]> {
        EncodedHummingbirdPath {
            meta_header: self.meta_header,
            encoded_path: self.encoded_path.as_ref(),
        }
    }
}
impl<T: AsRef<[u8]>> EncodedHummingbirdPath<T> {
    /// Transforms the path to be backed by [`Bytes`].
    pub fn to_bytes_path(&self) -> EncodedHummingbirdPath<Bytes> {
        EncodedHummingbirdPath {
            meta_header: self.meta_header,
            encoded_path: Bytes::copy_from_slice(self.encoded_path.as_ref()),
        }
    }
}

impl WireDecode<Bytes> for EncodedHummingbirdPath {
    type Error = DecodeError;

    fn decode(data: &mut Bytes) -> Result<Self, Self::Error> {
        let mut view: &[u8] = data.as_ref();
        let meta_header = HummingbirdMetaHeader::decode(&mut view)?;

        if data.remaining() < meta_header.encoded_path_length() {
            Err(Self::Error::PacketEmptyOrTruncated)
        } else {
            let encoded_path = data.split_to(meta_header.encoded_path_length());
            Ok(Self {
                meta_header,
                encoded_path,
            })
        }
    }
}

/// Errors related to Hummingbird paths.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq, Copy)]
pub enum HummingbirdPathError {
    /// Error when trying to add too many segments to a path.
    #[error("A path can only be constructed with up to 3 segments")]
    TooManySegments,

    /// Error when trying to add a segment that is too long to be represented
    /// in the Hummingbird meta header segment length field.
    #[error("A Hummingbird segment can be at most 508 bytes long")]
    SegmentTooLong,

    /// Current hop field index is not valid, i.e., either not divisible
    /// by 4 or it the value is too large to fit in the allocated bits.
    #[error("Current hop field index is not valid")]
    InvalidHopFieldIndex,

    /// Raised if the buffer does not have sufficient capacity for encoding the SCION headers.
    #[error("The provided buffer did not have sufficient size")]
    InadequateBufferSize,

    /// Invalid base timestamp, i.e., base timestamp does not fit in the meta header field.
    #[error("Invalid base timestamp")]
    InvalidBaseTimestamp(i64),

    /// Invalid milliseconds timestamp, i.e., milliseconds timestamp does not fit in the meta
    /// header field.
    #[error("Invalid milliseconds timestamp")]
    InvalidMillisTimestamp(u32),

    /// Invalid Hummingbird counter, i.e. the counter value does not fit in
    /// the meta header's counter field.
    #[error("invalid counter")]
    InvalidCounter(u32),

    /// Payload to long.
    #[error("Payload too long")]
    PayloadTooLong,

    /// Decoding error
    #[error("Decoding error")]
    DecodeError(#[from] DecodeError),

    /// The `ases` slice provided to `decode` does not contain enough entries for
    /// the number of hop fields in the encoded path.
    #[error("Insufficient AS information: not enough ISD-AS entries for the encoded path")]
    InsufficientAsInfo,

    /// Raised when trying to use a reservation that is not currently valid,
    /// i.e., it is expired, or not yet valid.
    #[error("Trying to use a reservation that is not currently valid")]
    ReservationNotValid,

    /// The Hummingbird reservation has expired.
    #[error("reservation expired")]
    ReservationExpired,

    /// The reserved bandwidth has been exceeded.
    #[error("bandwidth exceeded")]
    BandwidthExceeded,

    /// The provided hop index does not correspond to any hop on the path.
    #[error("hop index out of range")]
    HopIndexOutOfRange,
}

impl NonEncodeError for HummingbirdPathError {}
impl NonScmpEncodeError for HummingbirdPathError {}

impl From<ReservationTrackerError> for HummingbirdPathError {
    fn from(e: ReservationTrackerError) -> Self {
        match e {
            ReservationTrackerError::ReservationExpired => Self::ReservationExpired,
            ReservationTrackerError::BandwidthExceeded => Self::BandwidthExceeded,
        }
    }
}

impl From<InadequateBufferSize> for HummingbirdPathError {
    fn from(_: InadequateBufferSize) -> Self {
        HummingbirdPathError::InadequateBufferSize
    }
}

/// A hop on a [`HummingbirdPath`], along with any reservations that apply to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HummingbirdPathHop {
    /// The standard hop field for this hop.
    hop_field: StandardHopField,
    /// Reservations that may be applied to this hop when encoding.
    reservations: Vec<Reservation>,
    /// The ISD-AS of this hop, if known.
    isd_asn: Option<IsdAsn>,
}

impl HummingbirdPathHop {
    /// Returns the standard hop field for this hop.
    pub fn hop_field(&self) -> &StandardHopField {
        &self.hop_field
    }

    /// Returns the reservations that may be applied to this hop when encoding.
    pub fn reservations(&self) -> &[Reservation] {
        &self.reservations
    }

    /// Returns the ISD-AS of this hop, if known.
    pub fn isd_asn(&self) -> Option<IsdAsn> {
        self.isd_asn
    }
}

/// A fully decoded Hummingbird data plane path. It can be used to build new paths
/// or to modify existing ones. If you only need to read information, use
/// [EncodedHummingbirdPath] instead for better performance.
#[derive(Clone)]
pub struct HummingbirdPath {
    /// Path meta data.
    path_meta: HummingbirdMetaHeader,

    /// Info fields of the path.
    info_fields: Vec<InfoField>,

    /// Segments of the path.
    segments: Vec<Vec<HummingbirdPathHop>>,

    /// Optional per-path reservation tracker for client-side bandwidth enforcement.
    reservation_tracker: Option<Arc<Mutex<ReservationTracker>>>,

    /// When `true`, encoding fails if any hop that has at least one matching reservation
    /// cannot be assigned one (e.g. all buckets are exhausted). When `false`, those hops
    /// silently fall back to standard hop fields.
    strict_reservation: bool,
}

impl HummingbirdPath {
    /// Creates a new HummingbirdPath a default counter.
    pub fn new() -> HummingbirdPath {
        Self::new_with_counter(HummingbirdCounter::default())
    }

    /// Creates a new HummingbirdPath with the given counter value.
    pub fn new_with_counter(counter: HummingbirdCounter) -> HummingbirdPath {
        let meta_header = HummingbirdMetaHeader {
            current_info_field: 0.into(),
            current_hop_field: HummingbirdHopfieldIndex::new_unchecked(0),
            reserved: HummingbirdMetaReserved::default(),
            segment_lengths: [HummingbirdSegmentLength::new_unchecked(0); 3],
            base_timestamp: 0.into(),
            millis_timestamp: 0.into(),
            counter,
        };

        HummingbirdPath {
            path_meta: meta_header,
            info_fields: vec![],
            segments: vec![],
            reservation_tracker: None,
            strict_reservation: false,
        }
    }

    /// Attach a [`ReservationTracker`] to this path.
    ///
    /// When set, every call to [`PathProvider::build`] selects a reservation with
    /// available bandwidth for each hop before encoding, and updates the
    /// available bandwidth for the chosen reservations.
    ///
    /// If `strict` is `true`, encoding fails with
    /// [`HummingbirdPathError::BandwidthExceeded`] whenever a hop has at least one
    /// matching reservation but none with sufficient available bandwidth. If
    /// `strict` is `false`, those hops silently fall back to standard hop fields.
    pub fn with_reservation_tracker(
        mut self,
        tracker: Arc<Mutex<ReservationTracker>>,
        strict: bool,
    ) -> Self {
        self.reservation_tracker = Some(tracker);
        self.strict_reservation = strict;
        self
    }

    /// Sets the [`ReservationTracker`] on this path.
    ///
    /// When set, every call to [`PathProvider::build`] selects a reservation with
    /// available bandwidth for each hop before encoding, and updates the
    /// available bandwidth for the chosen reservations.
    ///
    /// If `strict` is `true`, encoding fails with
    /// [`HummingbirdPathError::BandwidthExceeded`] whenever a hop has at least one
    /// matching reservation but none with sufficient available bandwidth. If
    /// `strict` is `false`, those hops silently fall back to standard hop fields.
    pub fn set_reservation_tracker(
        &mut self,
        tracker: Arc<Mutex<ReservationTracker>>,
        strict: bool,
    ) {
        self.reservation_tracker = Some(tracker);
        self.strict_reservation = strict;
    }

    /// Returns the maximum packet size (in bytes) that can be sent such that
    /// every hop with a matching reservation has a reservation that has enough  
    /// available bandwidth to be able to send the packet now.
    ///
    /// Returns `None` if no tracker is attached or if there are no reservations
    /// attached to this path.
    pub fn available_packet_size(&self) -> Option<usize> {
        let tracker = self.reservation_tracker.as_ref()?;
        let mut guard = tracker.lock().unwrap();

        let mut min_available: Option<usize> = None;

        for hop in self.hops() {
            let max_bytes = hop
                .reservations
                .iter()
                .map(|r| guard.available_bytes(&r.info))
                .max();

            if let Some(avail) = max_bytes {
                min_available = Some(min_available.map_or(avail, |m: usize| m.min(avail)));
            }
        }

        min_available
    }

    /// Returns the index of the current info field.
    pub fn current_info_field_index(&self) -> HummingbirdInfoFieldIndex {
        self.path_meta.current_info_field
    }

    /// Set the current info field index to the specified value.
    pub fn set_current_info_field_index(&mut self, index: HummingbirdInfoFieldIndex) {
        self.path_meta.current_info_field = index;
    }

    /// Returns the index of the current hop field field.
    pub fn current_hop_field_index(&self) -> HummingbirdHopfieldIndex {
        self.path_meta.current_hop_field
    }

    /// Set the current hop field index to the specified value.
    pub fn set_current_hop_field_index(&mut self, index: HummingbirdHopfieldIndex) {
        self.path_meta.current_hop_field = index;
    }

    /// Returns the counter of the path.
    pub fn counter(&self) -> HummingbirdCounter {
        self.path_meta.counter
    }

    /// Set the counter of the path to the specified value.
    pub fn set_counter(&mut self, counter: HummingbirdCounter) {
        self.path_meta.counter = counter;
    }

    /// Returns an iterator over the reservations added to this path.
    pub fn reservations(&self) -> impl Iterator<Item = &Reservation> {
        self.segments
            .iter()
            .flat_map(|s| s.iter())
            .flat_map(|h| h.reservations.iter())
    }

    /// Add a reservation to the hop at flat index `hop_idx`, counting hops
    /// across all segments in order (segment 0 first, then segment 1, ...).
    ///
    /// Unlike [`Self::try_add_reservation`], this does not match the reservation
    /// against the hop's interfaces — it is applied to the hop at `hop_idx`
    /// unconditionally.
    ///
    /// Returns [`HummingbirdPathError::HopIndexOutOfRange`] if `hop_idx` is not
    /// within the current number of hops on the path.
    pub fn add_reservation(
        &mut self,
        hop_idx: u8,
        reservation: Reservation,
    ) -> Result<(), HummingbirdPathError> {
        let hop = self
            .hops_mut()
            .nth(hop_idx as usize)
            .ok_or(HummingbirdPathError::HopIndexOutOfRange)?;

        hop.reservations.push(reservation);
        Ok(())
    }

    /// Add a reservation to use with this path. Reservations added using this
    /// method will be applied to all matching regular HopFields contained
    /// in the segments.
    ///
    /// Returns whether the reservation was added to any hop.
    pub fn try_add_reservation(&mut self, reservation: Reservation) -> bool {
        // TODO(mariosbf): might not be correct for paths with peering links
        let mut result = false;
        for seg_idx in 0..self.segments.len() {
            let next_segment = self.segments.get(seg_idx + 1);
            let next_info = self.info_fields.get(seg_idx + 1);
            let first_hop_of_next_segment_ifaces = next_segment
                .and_then(|s| s.first())
                .map(|h| h.hop_field.interfaces(next_info.unwrap().cons_dir));

            let segment = &mut self.segments[seg_idx];
            let segment_len = segment.len();
            let info = self.info_fields[seg_idx];

            for (hop_idx, hop) in segment.iter_mut().enumerate() {
                let is_last_hop_of_segment = hop_idx == segment_len - 1;
                let hop_field = &hop.hop_field;

                let (ingress, egress) = hop_field.interfaces(info.cons_dir);
                let egress = if is_last_hop_of_segment {
                    first_hop_of_next_segment_ifaces
                        .map(|v| v.1)
                        .unwrap_or(egress)
                } else {
                    egress
                };

                if reservation.info.ingress_interface == ingress
                    && reservation.info.egress_interface == egress
                    && hop.isd_asn.is_some_and(|ia| ia == reservation.info.isd_as)
                {
                    hop.reservations.push(reservation.clone());
                    result = true;
                }
            }
        }

        result
    }

    /// Return an iterator over the segments on this path.
    pub fn segments(&self) -> impl Iterator<Item = (&InfoField, &[HummingbirdPathHop])> {
        self.segments
            .iter()
            .zip(self.info_fields.iter())
            .map(|(segment, info_field)| (info_field, segment.as_slice()))
    }

    /// Add a segment to the path.
    pub fn add_segment(
        &mut self,
        info_field: InfoField,
        hops: Vec<(Option<IsdAsn>, StandardHopField)>,
    ) -> Result<(), HummingbirdPathError> {
        if self.info_fields.len() >= 3 {
            return Err(HummingbirdPathError::TooManySegments);
        }

        self.info_fields.push(info_field);
        self.segments.push(
            hops.into_iter()
                .map(|(isd_asn, hop_field)| HummingbirdPathHop {
                    isd_asn,
                    hop_field,
                    reservations: vec![],
                })
                .collect(),
        );

        Ok(())
    }

    /// The length if it were to be encoded now.
    ///
    /// Note that adding segments or reservations after calling this method
    /// may change the encoded length.
    pub fn encoded_length(&self) -> usize {
        let hops = self
            .hops_with_reservation(0, None, false)
            .expect("infallible: no tracker, not strict");
        self.path_header_len(&hops)
    }

    /// The length of the path header without applying any reservations,
    /// assuming a regular (non-Hummingbird) meta header and only standard
    /// hop fields — i.e. the length this path would have as a plain SCION
    /// path.
    ///
    /// Used as the shared baseline for [`Self::generate_flyover_macs`] and
    /// [`Self::packet_length_for_payload`], which each add the Hummingbird
    /// meta header delta and any flyover deltas on top (see
    /// `path_header_len_with_flyovers`).
    pub fn base_encoded_length(&self) -> usize {
        MetaHeader::LENGTH
            + self.info_fields_len()
            + self
                .hops()
                .map(|hop| hop.hop_field.encoded_length())
                .sum::<usize>()
    }

    fn info_fields_len(&self) -> usize {
        self.info_fields
            .iter()
            .map(|f| f.encoded_length())
            .sum::<usize>()
    }

    fn num_hopfields(&self) -> usize {
        self.segments.iter().map(|s| s.len()).sum::<usize>()
    }

    /// Returns each hop paired with the reservation to apply when encoding.
    ///
    /// When `tracker` is `Some`, the selection is bandwidth-aware:
    /// - Candidates for a hop are reservations that pass [`ReservationTracker::check_reservation`].
    /// - Among candidates, the one with the fewest available bytes (tightest bucket) is chosen,
    ///   preserving headroom in larger buckets for bigger packets.
    /// - If no candidate passes and `strict` is `true`, returns `BandwidthExceeded`.
    /// - If no candidate passes and `strict` is `false`, the hop falls back to standard.
    ///
    /// When `tracker` is `None`, the first reservation in the list is chosen (no bandwidth check).
    fn hops_with_reservation(
        &self,
        pkt_len: usize,
        mut tracker: Option<&mut ReservationTracker>,
        strict: bool,
    ) -> Result<Vec<(usize, usize, Option<Reservation>)>, HummingbirdPathError> {
        let mut hop_fields = Vec::with_capacity(self.num_hopfields());

        for (seg_idx, segment) in self.segments.iter().enumerate() {
            for (hop_idx, hop) in segment.iter().enumerate() {
                let reservations = &hop.reservations;
                let reservation = if let Some(ref mut t) = tracker
                    && !reservations.is_empty()
                {
                    let mut num_expired = 0;
                    let mut selected = None;

                    for r in reservations {
                        match t.check_reservation(&r.info, pkt_len) {
                            Err(ReservationTrackerError::BandwidthExceeded) => {
                                continue;
                            }
                            Err(ReservationTrackerError::ReservationExpired) => {
                                num_expired += 1;
                            }
                            Ok(()) => {
                                let available_bytes = t.available_bytes(&r.info);

                                if selected.is_none_or(|(_, bytes)| bytes > available_bytes) {
                                    selected = Some((r, available_bytes));
                                }
                            }
                        }
                    }

                    let all_expired = num_expired == reservations.len();

                    if all_expired && strict {
                        return Err(HummingbirdPathError::ReservationExpired);
                    }

                    if selected.is_none() && strict {
                        return Err(HummingbirdPathError::BandwidthExceeded);
                    }
                    selected.map(|v| v.0.clone())
                } else {
                    reservations.first().cloned()
                };
                hop_fields.push((seg_idx, hop_idx, reservation));
            }
        }

        Ok(hop_fields)
    }

    fn hops(&self) -> impl Iterator<Item = &HummingbirdPathHop> {
        self.segments.iter().flat_map(|s| s.iter())
    }

    fn hops_mut(&mut self) -> impl Iterator<Item = &mut HummingbirdPathHop> {
        self.segments.iter_mut().flat_map(|s| s.iter_mut())
    }

    /// Computes the length in bytes of the encoded path header (meta header +
    /// info fields + hop fields) that would result from encoding `hops`,
    /// where a hop paired with `Some` reservation becomes a flyover hop
    /// field and one paired with `None` stays a standard hop field.
    fn path_header_len(&self, hops: &[(usize, usize, Option<Reservation>)]) -> usize {
        let flyover_count = hops.iter().filter(|(_, _, res)| res.is_some()).count();

        HummingbirdMetaHeader::LENGTH
            + self.info_fields_len()
            + self
                .hops()
                .map(|hop| hop.hop_field.encoded_length())
                .sum::<usize>()
            + flyover_count * (FlyoverHopField::ENCODED_SIZE - StandardHopField::ENCODED_SIZE)
    }

    /// Apply reservations by turning applicable hop fields into flyover hop
    /// fields, adjusting segment lengths and current hop field index.
    fn apply_reservations(
        &self,
        destination: IsdAsn,
        payload_len: u16,
        address_header_len: u16,
    ) -> Result<(HummingbirdMetaHeader, Vec<HummingbirdHopField>), HummingbirdPathError> {
        // Create a copy of the meta header
        let mut meta_header = self.path_meta;

        // Set time in meta header
        let time = Utc::now();
        meta_header.base_timestamp = time
            .timestamp()
            .try_into()
            .ok()
            .and_then(HummingbirdBaseTimestamp::new)
            .ok_or(HummingbirdPathError::InvalidBaseTimestamp(time.timestamp()))?;

        meta_header.millis_timestamp = time
            .timestamp_subsec_millis()
            .try_into()
            .ok()
            .and_then(HummingbirdMillisTimestamp::new)
            .ok_or(HummingbirdPathError::InvalidMillisTimestamp(
                time.timestamp_subsec_millis(),
            ))?;

        // Conservative upper bound on path header length — all reservable hops as flyovers.
        // Used only for the bandwidth check; MAC computation uses the exact length below.
        let max_path_header_len = meta_header.encoded_length()
            + self.info_fields_len()
            + self.num_hopfields() * FlyoverHopField::ENCODED_SIZE;
        let estimated_pkt_len = max_path_header_len
            + CommonHeader::LENGTH
            + address_header_len as usize
            + payload_len as usize;

        // Lock the tracker once for the entire check → encode → deduct sequence.
        let mut tracker_guard = self.reservation_tracker.as_ref().map(|t| t.lock().unwrap());

        let hops = self.hops_with_reservation(
            estimated_pkt_len,
            tracker_guard.as_deref_mut(),
            self.strict_reservation,
        )?;

        // Compute the exact packet length based on the actual selection.
        let mut curr_hf_index = meta_header.current_hop_field.byte_offset();
        let path_header_len = self.path_header_len(&hops);

        let pkt_len = u16::try_from(path_header_len)
            .ok()
            .and_then(|v| v.checked_add(CommonHeader::LENGTH as u16))
            .and_then(|v| v.checked_add(address_header_len))
            .and_then(|v| v.checked_add(payload_len))
            .ok_or(HummingbirdPathError::PayloadTooLong)?;

        // Keep track of byte offset of hop fields as we iterate through them
        let mut hop_offset = 0;
        let mut seglens = [0; 3];
        let mut hop_fields = Vec::with_capacity(self.num_hopfields());

        // Collect reservation infos for deduction after encoding (while hop_fields is still alive).
        let deduct_infos: Vec<_> = hops
            .iter()
            .filter_map(|(_, _, res)| res.as_ref().map(|r| r.info.clone()))
            .collect();

        for (seg_idx, hop_idx, res) in hops {
            let hop = &self.segments[seg_idx][hop_idx].hop_field;
            let hop_field = if let Some(res) = res {
                // If the matched hop field is before the current hop field, the
                // current hop field's byte offset must be advanced by the size
                // difference between a flyover and a standard hop field.
                if hop_offset < meta_header.current_hop_field.byte_offset() {
                    curr_hf_index += FlyoverHopField::ENCODED_SIZE - StandardHopField::ENCODED_SIZE;
                }

                HummingbirdHopField::Flyover(hop.apply_reservation(
                    meta_header,
                    &res,
                    destination,
                    pkt_len,
                )?)
            } else {
                HummingbirdHopField::Standard(hop.clone())
            };

            // Advance hop offset
            hop_offset += hop_field.encoded_length();

            // Increase segment length counters for each segment the hop field is in.
            seglens[seg_idx] += hop_field.encoded_length();

            hop_fields.push(hop_field);
        }

        // Adjust segment lengths
        for (seg_idx, seg_len) in seglens.iter().enumerate() {
            meta_header.segment_lengths[seg_idx] = HummingbirdSegmentLength::new(*seg_len)
                .ok_or(HummingbirdPathError::SegmentTooLong)?;
        }

        // Adjust current hop field index in meta header.
        meta_header.current_hop_field = HummingbirdHopfieldIndex::new(curr_hf_index)
            .ok_or(HummingbirdPathError::InvalidHopFieldIndex)?;

        // Deduct bandwidth from the selected buckets (still under the same tracker lock).
        if let Some(ref mut guard) = tracker_guard {
            for info in &deduct_infos {
                guard.deduct_reservation(info, pkt_len as usize);
            }
        }

        Ok((meta_header, hop_fields))
    }

    /// Computes the total packet length that would result from combining
    /// `payload_len` bytes of payload with this path's header (given
    /// `address_header_len`) — the inverse of
    /// [`crate::hummingbird::FlyoverMACs::payload_length_suggestion`]. Feed
    /// the result into [`Self::generate_flyover_macs`] as `packet_length`
    /// when starting from a known payload size.
    ///
    /// Note that the term payload is used from the perspective of the SCION
    /// header, i.e., everything encapsulated inside the SCION header is
    /// considered payload.
    pub fn packet_length_for_payload(
        &self,
        payload_len: u16,
        address_header_len: u16,
    ) -> Result<u16, HummingbirdPathError> {
        let max_path_header_len = HummingbirdMetaHeader::LENGTH
            + self.info_fields_len()
            + self.num_hopfields() * FlyoverHopField::ENCODED_SIZE;
        let estimated_pkt_len = max_path_header_len
            + CommonHeader::LENGTH
            + address_header_len as usize
            + payload_len as usize;

        let mut tracker_guard = self.reservation_tracker.as_ref().map(|t| t.lock().unwrap());
        let hops = self.hops_with_reservation(
            estimated_pkt_len,
            tracker_guard.as_deref_mut(),
            self.strict_reservation,
        )?;

        let flyover_count = hops.iter().filter(|(_, _, res)| res.is_some()).count();
        let base_path_header_len = self.base_encoded_length();

        packet_length_for_payload_with_flyovers(
            payload_len,
            address_header_len,
            base_path_header_len,
            flyover_count,
        )
    }

    /// Generates a compact, transmittable set of flyover MACs for the
    /// reservations already attached to this path (see
    /// [`Self::add_reservation`]/[`Self::try_add_reservation`]), targeting a
    /// total packet of `packet_length` bytes.
    ///
    /// The resulting MACs are only valid for a packet of exactly this length. Use
    /// [`Self::packet_length_for_payload`] first if you have a target payload
    /// length.
    ///
    /// Parameters:
    /// - `destination`: destination ISD-AS, used for the flyover MAC
    ///   calculation.
    /// - `packet_length`: the target total packet length (e.g. path MTU).
    ///   Used directly in the MAC calculation (see
    ///   [`crate::hummingbird::Reservation::generate_flyover_mac`]) — the
    ///   resulting MACs are only valid for a packet of exactly this length.
    /// - `address_header_len`: not used by the MAC calculation itself —
    ///   needed solely to derive [`crate::hummingbird::FlyoverMACs::payload_length_suggestion`],
    pub fn generate_flyover_macs(
        &self,
        destination: IsdAsn,
        packet_length: u16,
        address_header_len: u16,
    ) -> Result<FlyoverMACs, HummingbirdPathError> {
        let mut tracker_guard = self.reservation_tracker.as_ref().map(|t| t.lock().unwrap());

        let hops = self.hops_with_reservation(
            packet_length as usize,
            tracker_guard.as_deref_mut(),
            self.strict_reservation,
        )?;

        let base_path_header_len = self.base_encoded_length();
        let reservations = hops
            .iter()
            .enumerate()
            .filter_map(|(flat_idx, (_, _, res))| res.as_ref().map(|r| (flat_idx as u8, r)));

        let macs = generate_flyover_macs_from_reservations(
            destination,
            packet_length,
            address_header_len,
            base_path_header_len,
            self.path_meta.counter(),
            reservations,
        )?;

        // Deduct bandwidth from the selected buckets, mirroring apply_reservations:
        // generating MACs for a packet commits to sending it.
        if let Some(ref mut guard) = tracker_guard {
            for (_, _, res) in &hops {
                if let Some(reservation) = res {
                    guard.deduct_reservation(&reservation.info, packet_length as usize);
                }
            }
        }

        Ok(macs)
    }

    /// Encode the path to a byte buffer, applying any reservations that have been added to
    /// the path. The reservations are applied by replacing regular hop fields with flyover hop
    /// fields.
    ///
    /// Parameters:
    /// - `destination`: The destination ISD-AS of the path, used for calculating the
    ///   flyover hop field MACs.
    /// - `payload_len`: the length of the payload contained in the packet
    ///   (number of bytes). Used for flyover MAC calculations.
    ///
    /// See [encoded_length][Self::encoded_length] for the length of the resulting encoding.
    pub fn encode_to<T: BufMut>(
        &self,
        destination: IsdAsn,
        payload_len: u16,
        address_header_len: u16,
        buffer: &mut T,
    ) -> Result<(), HummingbirdPathError> {
        let (meta_header, hops) =
            self.apply_reservations(destination, payload_len, address_header_len)?;

        // Encode fields to buffer
        meta_header.encode_to(buffer)?;
        for info in self.info_fields.iter() {
            info.encode_to(buffer)?;
        }
        for hop in hops {
            hop.encode_to(buffer)?;
        }

        Ok(())
    }

    /// Turn this path into an [EncodedHummingbirdPath].
    ///
    /// Parameters:
    /// - `destination`: The destination ISD-AS of the path, used for calculating the
    ///   flyover hop field MACs.
    /// - `payload_len`: the length of the payload contained in the packet
    ///   (number of bytes). Used for flyover MAC calculations.
    pub fn to_encoded(
        &self,
        destination: IsdAsn,
        payload_len: u16,
        address_header_len: u16,
    ) -> Result<EncodedHummingbirdPath<Bytes>, HummingbirdPathError> {
        let (meta_header, hops) =
            self.apply_reservations(destination, payload_len, address_header_len)?;

        let len = meta_header.encoded_length()
            + self.info_fields_len()
            + hops.iter().map(|hop| hop.encoded_length()).sum::<usize>();
        let mut buffer = vec![0u8; len];
        let mut slice: &mut [u8] = &mut buffer;

        meta_header.encode_to(&mut slice)?;
        for info in self.info_fields.iter() {
            info.encode_to(&mut slice)?;
        }
        for hop in hops {
            hop.encode_to(&mut slice)?;
        }

        Ok(EncodedHummingbirdPath {
            meta_header,
            encoded_path: buffer.into(),
        })
    }

    /// Encodes this path (applying reservations) and returns a [`Path<Bytes>`]
    /// ready for use in a SCION packet.
    ///
    /// Parameters:
    /// - `source`: The source ISD-AS of the path.
    /// - `destination`: The destination ISD-AS of the path, used for calculating the
    ///   flyover hop field MACs.
    /// - `payload_len`: the length of the payload contained in the packet
    ///   (number of bytes). Used for flyover MAC calculations.
    pub fn to_bytes_path(
        &self,
        isd_asn: ByEndpoint<IsdAsn>,
        payload_len: u16,
        address_header_len: u16,
    ) -> Result<Path<Bytes>, HummingbirdPathError> {
        // Build PathInterface list from segments
        let interfaces = if self.hops().all(|h| h.isd_asn.is_some()) {
            Some(
                self.segments()
                    .flat_map(|(info_field, hops)| {
                        let cons_dir = info_field.cons_dir;
                        hops.iter().flat_map(move |hop| {
                            let isd_asn = hop.isd_asn.unwrap();
                            let (ingress, egress) = hop.hop_field.interfaces(cons_dir);
                            [
                                (ingress != 0).then(|| PathInterface::new(isd_asn, ingress)),
                                (egress != 0).then(|| PathInterface::new(isd_asn, egress)),
                            ]
                            .into_iter()
                            .flatten()
                        })
                    })
                    .collect(),
            )
        } else {
            None
        };

        let encoded = self.to_encoded(isd_asn.destination, payload_len, address_header_len)?;

        let mut path = Path::new(DataPlanePath::Hummingbird(encoded), isd_asn, None);
        path.metadata = Some(Metadata {
            interfaces,
            ..Default::default()
        });

        Ok(path)
    }

    /// Decodes a Hummingbird path from the provided byte buffer and ISD-AS list.
    ///
    /// The resulting path is suitable for sending packets, if the MACs in all
    /// flyover hop fields are de-aggregated. This should be the case if the
    /// path was obtained from the header of an incoming SCION packet, since
    /// border routers are expected to de-aggregate flyover hop fields before
    /// forwarding the packet to an end host.
    ///
    /// The AS list needs to contain the ISD-AS numbers of each AS along the path,
    /// in the same order as they are traversed by the path. Hops whose ISD-AS
    /// cannot be determined from `ases` (e.g. because it does not contain enough
    /// entries to cover every hop field in the path) are left without one.
    ///
    /// Parameters:
    /// - `data`: byte buffer containing the encoded path. The buffer will be
    ///   modified by advancing it past the bytes that were decoded.
    /// - `ases`: list of ISD-AS numbers corresponding to the ASes along the path, in order.
    pub fn decode(data: &mut Bytes, ases: &[IsdAsn]) -> Result<Self, HummingbirdPathError> {
        let meta_header = HummingbirdMetaHeader::decode(data)?;

        let mut info_fields = Vec::new();
        let mut segments = Vec::new();

        for _ in 0..meta_header.info_fields_count() {
            let info_field = InfoField::decode(data)?;
            info_fields.push(info_field);
        }

        let mut as_idx = 0;
        for i in 0..3 {
            let mut seg_len = meta_header.segment_lengths[i as usize].length();
            if seg_len == 0 {
                continue;
            }

            let mut hop_fields = Vec::new();
            while seg_len > 0 {
                let hop_field = HummingbirdHopField::decode(data)?;
                let hop_field = match hop_field {
                    HummingbirdHopField::Standard(h) => h,
                    HummingbirdHopField::Flyover(h) => StandardHopField {
                        ingress_router_alert: h.ingress_router_alert,
                        egress_router_alert: h.egress_router_alert,
                        exp_time: h.exp_time,
                        cons_ingress: h.cons_ingress,
                        cons_egress: h.cons_egress,
                        // Note: This is where we need to assume that MACs are
                        // de-aggregated.
                        mac: h.aggregated_mac,
                    },
                };

                seg_len -= hop_field.encoded_length();

                let isd_asn = ases.get(as_idx).copied();
                hop_fields.push(HummingbirdPathHop {
                    hop_field,
                    reservations: vec![],
                    isd_asn,
                });

                if seg_len != 0 {
                    // Don't move to next ISD-AS after last hop of segment
                    // because the next hop will be in the same AS
                    as_idx += 1;
                }
            }
            segments.push(hop_fields);
        }

        Ok(HummingbirdPath {
            path_meta: meta_header,
            info_fields,
            segments,
            reservation_tracker: None,
            strict_reservation: false,
        })
    }
}

impl Default for HummingbirdPath {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for HummingbirdPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HummingbirdPath")
            .field("path_meta", &self.path_meta)
            .field("info_fields", &self.info_fields)
            .field("segments", &self.segments)
            .field("reservation_tracker", &self.reservation_tracker.is_some())
            .finish()
    }
}

impl PartialEq for HummingbirdPath {
    fn eq(&self, other: &Self) -> bool {
        self.path_meta == other.path_meta
            && self.info_fields == other.info_fields
            && self.segments == other.segments
    }
}

impl Eq for HummingbirdPath {}

impl PathProvider for HummingbirdPath {
    type Error = HummingbirdPathError;

    fn build(
        &self,
        isd_asn: ByEndpoint<IsdAsn>,
        payload_len: u16,
        address_header_len: u16,
    ) -> Result<Path, Self::Error> {
        // Bandwidth check and deduction happen inside apply_reservations (called by
        // to_bytes_path), so no separate tracker call is needed here.
        self.to_bytes_path(isd_asn, payload_len, address_header_len)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use super::*;
    use crate::{
        address::{Asn, Isd, IsdAsn},
        hummingbird::{Bandwidth, Reservation, ReservationInfo},
        packet::DecodeError,
        path::DataPlanePathErrorKind,
        wire_encoding::WireDecode,
    };
    use bytes::Bytes;

    // Helpers

    fn hb_meta_bytes(
        info: u8,
        hop: u8,
        seg0: u8,
        seg1: u8,
        seg2: u8,
        base_ts: u32,
        millis: u16,
        counter: u32,
    ) -> [u8; 12] {
        let f1 = ((info as u32) << 30)
            | ((hop as u32) << 22)
            | ((seg0 as u32) << 14)
            | ((seg1 as u32) << 7)
            | (seg2 as u32);
        let f3 = ((millis as u32) << 22) | counter;
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&f1.to_be_bytes());
        b[4..8].copy_from_slice(&base_ts.to_be_bytes());
        b[8..12].copy_from_slice(&f3.to_be_bytes());
        b
    }

    fn hb_path_bytes(meta: [u8; 12], info_fields: &[&[u8]], hop_fields: &[&[u8]]) -> Bytes {
        let mut v = Vec::from(meta);
        for i in info_fields {
            v.extend_from_slice(i);
        }
        for h in hop_fields {
            v.extend_from_slice(h);
        }
        Bytes::from(v)
    }

    // 1-segment test data
    // meta: info=0, hop=0, seg_len=[6,0,0], base_ts=0x1A2B3C4D
    //   encoded_path_length = 12 + 1*8 + 24 = 44 bytes
    // info field: cons_dir=true (FLAGS_CONS_DIR=0b01), timestamp=0xDEADBEEF
    // hop 1: cons_ingress=0x0A, cons_egress=0x0B
    // hop 2: cons_ingress=0x0C, cons_egress=0x0D
    fn one_segment_path() -> Bytes {
        hb_path_bytes(
            hb_meta_bytes(0, 0, 6, 0, 0, 0x1A2B3C4D, 0, 0),
            &[b"\x01\x00\x00\x00\xDE\xAD\xBE\xEF"],
            &[
                b"\x00\x00\x00\x0A\x00\x0B\x00\x00\x00\x00\x00\x00",
                b"\x00\x00\x00\x0C\x00\x0D\x00\x00\x00\x00\x00\x00",
            ],
        )
    }

    // 2-segment test data
    // meta: info=0, hop=0, seg_len=[6,6,0], base_ts=0
    //   encoded_path_length = 12 + 2*8 + 24 + 24 = 76 bytes
    // info1: cons_dir=true (FLAGS_CONS_DIR=0b01), timestamp=1
    // info2: cons_dir=false, timestamp=2
    // seg0 hop 1/2: cons_ingress=1,cons_egress=2 / cons_ingress=3,cons_egress=4
    // seg1 hop 1/2: cons_ingress=5,cons_egress=6 / cons_ingress=7,cons_egress=8

    fn two_segment_path() -> Bytes {
        hb_path_bytes(
            hb_meta_bytes(0, 0, 6, 6, 0, 0, 0, 0),
            &[
                b"\x01\x00\x00\x00\x00\x00\x00\x01",
                b"\x00\x00\x00\x00\x00\x00\x00\x02",
            ],
            &[
                // seg0
                b"\x00\x00\x00\x01\x00\x02\x00\x00\x00\x00\x00\x00",
                b"\x00\x00\x00\x03\x00\x04\x00\x00\x00\x00\x00\x00",
                // seg1
                b"\x00\x00\x00\x05\x00\x06\x00\x00\x00\x00\x00\x00",
                b"\x00\x00\x00\x07\x00\x08\x00\x00\x00\x00\x00\x00",
            ],
        )
    }

    // WireDecode — valid

    #[test]
    fn decode_single_segment() {
        let path = EncodedHummingbirdPath::decode(&mut one_segment_path()).expect("valid decode");
        let meta = path.meta_header();
        assert_eq!(meta.segment_lengths[0].encode(), 6);
        assert_eq!(meta.segment_lengths[1].encode(), 0);
        assert_eq!(meta.segment_lengths[2].encode(), 0);
        assert_eq!(meta.base_timestamp.get(), 0x1A2B3C4D);
    }

    #[test]
    fn decode_two_segments() {
        let path = EncodedHummingbirdPath::decode(&mut two_segment_path()).expect("valid decode");
        let meta = path.meta_header();
        assert_eq!(meta.segment_lengths[0].encode(), 6);
        assert_eq!(meta.segment_lengths[1].encode(), 6);
        assert_eq!(meta.segment_lengths[2].encode(), 0);
    }

    // WireDecode — errors

    #[test]
    fn decode_truncated() {
        let mut data = Bytes::from(vec![0u8; 3]);
        assert_eq!(
            EncodedHummingbirdPath::decode(&mut data),
            Err(DecodeError::PacketEmptyOrTruncated)
        );
    }

    #[test]
    fn decode_body_truncated() {
        // Valid meta header but body is only 1 byte instead of 24.
        let mut data = hb_path_bytes(
            hb_meta_bytes(0, 0, 6, 0, 0, 0, 0, 0),
            &[b"\x00\x00\x00\x00\x00\x00\x00\x00"],
            &[b"\x00"],
        );
        assert_eq!(
            EncodedHummingbirdPath::decode(&mut data),
            Err(DecodeError::PacketEmptyOrTruncated)
        );
    }

    #[test]
    fn decode_info_out_of_range() {
        // info=1 but only 1 segment → InfoFieldOutOfRange
        let mut data = hb_path_bytes(
            hb_meta_bytes(1, 0, 6, 0, 0, 0, 0, 0),
            &[b"\x00\x00\x00\x00\x00\x00\x00\x00"],
            &[
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
        );
        assert_eq!(
            EncodedHummingbirdPath::decode(&mut data),
            Err(DecodeError::InvalidPath(
                DataPlanePathErrorKind::InfoFieldOutOfRange
            ))
        );
    }

    // Iterator tests — 1-segment path

    #[test]
    fn one_segment_info_fields() {
        let path = EncodedHummingbirdPath::decode(&mut one_segment_path()).unwrap();
        let timestamps: Vec<i64> = path
            .info_fields()
            .map(|f| f.timestamp().timestamp())
            .collect();
        assert_eq!(timestamps, [0xDEAD_BEEF_i64]);
    }

    #[test]
    fn one_segment_hop_fields() {
        let path = EncodedHummingbirdPath::decode(&mut one_segment_path()).unwrap();
        let hops: Vec<(u16, u16)> = path
            .hop_fields()
            .map(|h| {
                (
                    h.cons_ingress_interface().map(NonZeroU16::get).unwrap_or(0),
                    h.cons_egress_interface().map(NonZeroU16::get).unwrap_or(0),
                )
            })
            .collect();
        assert_eq!(hops, [(0x0A, 0x0B), (0x0C, 0x0D)]);
    }

    #[test]
    fn one_segment_segments() {
        let path = EncodedHummingbirdPath::decode(&mut one_segment_path()).unwrap();
        let segments: Vec<_> = path.segments().collect();
        assert_eq!(segments.len(), 1);

        let seg = &segments[0];
        assert_eq!(seg.info_field().timestamp().timestamp(), 0xDEAD_BEEF_i64);

        let hops: Vec<(u16, u16)> = seg
            .hop_fields()
            .map(|h| {
                (
                    h.cons_ingress_interface().map(NonZeroU16::get).unwrap_or(0),
                    h.cons_egress_interface().map(NonZeroU16::get).unwrap_or(0),
                )
            })
            .collect();
        assert_eq!(hops, [(0x0A, 0x0B), (0x0C, 0x0D)]);
    }

    #[test]
    fn one_segment_iter_interfaces() {
        let path = EncodedHummingbirdPath::decode(&mut one_segment_path()).unwrap();
        // cons_dir=true → ingress then egress for each hop
        let ifaces: Vec<u16> = path.iter_interfaces().map(NonZeroU16::get).collect();
        assert_eq!(ifaces, [0x0A, 0x0B, 0x0C, 0x0D]);
    }

    #[test]
    fn two_segment_info_fields() {
        let path = EncodedHummingbirdPath::decode(&mut two_segment_path()).unwrap();
        let timestamps: Vec<i64> = path
            .info_fields()
            .map(|f| f.timestamp().timestamp())
            .collect();
        assert_eq!(timestamps, [1, 2]);
    }

    #[test]
    fn two_segment_hop_fields() {
        let path = EncodedHummingbirdPath::decode(&mut two_segment_path()).unwrap();
        let hops: Vec<(u16, u16)> = path
            .hop_fields()
            .map(|h| {
                (
                    h.cons_ingress_interface().map(NonZeroU16::get).unwrap_or(0),
                    h.cons_egress_interface().map(NonZeroU16::get).unwrap_or(0),
                )
            })
            .collect();
        assert_eq!(hops, [(1, 2), (3, 4), (5, 6), (7, 8),]);
    }

    #[test]
    fn two_segment_segments() {
        let path = EncodedHummingbirdPath::decode(&mut two_segment_path()).unwrap();
        let segments: Vec<_> = path.segments().collect();
        assert_eq!(segments.len(), 2);

        let seg0 = &segments[0];
        assert_eq!(seg0.info_field().timestamp().timestamp(), 1);
        let seg1 = &segments[1];
        assert_eq!(seg1.info_field().timestamp().timestamp(), 2);
    }

    #[test]
    fn two_segment_iter_interfaces() {
        let path = EncodedHummingbirdPath::decode(&mut two_segment_path()).unwrap();
        // seg0 cons_dir=true  → [ingress, egress] per hop → [1, 2, 3, 4]
        // seg1 cons_dir=false → [egress, ingress] per hop → [6, 5, 8, 7]
        let ifaces: Vec<u16> = path.iter_interfaces().map(NonZeroU16::get).collect();
        assert_eq!(ifaces, [1, 2, 3, 4, 6, 5, 8, 7]);
    }

    // ---------------------------------------------------------------------------
    // Helpers for reversal tests
    // ---------------------------------------------------------------------------

    // 2-segment path with unequal hop counts:
    //   seg0: 1 hop  (seg_len=3 → 12 bytes), cons_dir=true,  ts=1
    //   seg1: 2 hops (seg_len=6 → 24 bytes), cons_dir=false, ts=2
    fn asymmetric_two_segment_path() -> Bytes {
        hb_path_bytes(
            hb_meta_bytes(0, 0, 3, 6, 0, 0, 0, 0),
            &[
                b"\x01\x00\x00\x00\x00\x00\x00\x01",
                b"\x00\x00\x00\x00\x00\x00\x00\x02",
            ],
            &[
                b"\x00\x00\x00\x01\x00\x02\x00\x00\x00\x00\x00\x00", // seg0 hop:  (1,2)
                b"\x00\x00\x00\x03\x00\x04\x00\x00\x00\x00\x00\x00", // seg1 hop1: (3,4)
                b"\x00\x00\x00\x05\x00\x06\x00\x00\x00\x00\x00\x00", // seg1 hop2: (5,6)
            ],
        )
    }

    // 3-segment path:
    //   seg0: 1 hop  (seg_len=3 → 12 bytes), cons_dir=true,  ts=1
    //   seg1: 1 hop  (seg_len=3 → 12 bytes), cons_dir=false, ts=2
    //   seg2: 2 hops (seg_len=6 → 24 bytes), cons_dir=true,  ts=3
    fn three_segment_path() -> Bytes {
        hb_path_bytes(
            hb_meta_bytes(0, 0, 3, 3, 6, 0, 0, 0),
            &[
                b"\x01\x00\x00\x00\x00\x00\x00\x01",
                b"\x00\x00\x00\x00\x00\x00\x00\x02",
                b"\x01\x00\x00\x00\x00\x00\x00\x03",
            ],
            &[
                b"\x00\x00\x00\x01\x00\x02\x00\x00\x00\x00\x00\x00", // seg0 hop:  (1,2)
                b"\x00\x00\x00\x03\x00\x04\x00\x00\x00\x00\x00\x00", // seg1 hop:  (3,4)
                b"\x00\x00\x00\x05\x00\x06\x00\x00\x00\x00\x00\x00", // seg2 hop1: (5,6)
                b"\x00\x00\x00\x07\x00\x08\x00\x00\x00\x00\x00\x00", // seg2 hop2: (7,8)
            ],
        )
    }

    // Single-segment path with one flyover hop (20 B) followed by one standard hop (12 B).
    //   flyover: FLYOVER_BIT set, exp_time=5, cons_ingress=0x000A, cons_egress=0x000B
    //   standard: exp_time=6, cons_ingress=0x000C, cons_egress=0x000D
    //   seg_len = 32/4 = 8
    fn flyover_path() -> Bytes {
        let mut flyover = [0u8; 20];
        flyover[0] = 0x80; // FLYOVER_BIT
        flyover[1] = 0x05; // exp_time
        flyover[2..4].copy_from_slice(&0x000Au16.to_be_bytes()); // cons_ingress
        flyover[4..6].copy_from_slice(&0x000Bu16.to_be_bytes()); // cons_egress
        // bytes 6-19: AggMAC (6), ResID+BW (4), ResStartOffset (2), ResDuration (2) → all 0
        hb_path_bytes(
            hb_meta_bytes(0, 0, 8, 0, 0, 0, 0, 0),
            &[b"\x01\x00\x00\x00\x00\x00\x00\x01"],
            &[
                &flyover,
                b"\x00\x06\x00\x0C\x00\x0D\x00\x00\x00\x00\x00\x00",
            ],
        )
    }

    fn decode(mut data: Bytes) -> EncodedHummingbirdPath {
        EncodedHummingbirdPath::decode(&mut data).expect("valid decode")
    }

    fn hop_pairs(path: &EncodedStandardPath) -> Vec<(u16, u16)> {
        path.hop_fields()
            .map(|h| {
                (
                    h.cons_ingress_interface().map(NonZeroU16::get).unwrap_or(0),
                    h.cons_egress_interface().map(NonZeroU16::get).unwrap_or(0),
                )
            })
            .collect()
    }

    // ---------------------------------------------------------------------------
    // reversed_path_length
    // ---------------------------------------------------------------------------

    // Standard-only path: 4 (MetaHeader) + 1*8 (info) + 2*12 (hops) = 36 bytes.
    #[test]
    fn reversed_path_length_standard_only() {
        let path = decode(one_segment_path());
        assert_eq!(path.reversed_path_length(), 36);
    }

    // Flyover path: both hops become standard after reversal → still 36 bytes.
    #[test]
    fn reversed_path_length_with_flyover() {
        // Original path:
        // - Hummingbird meta header: 12 bytes
        // - 1 info field: 8 bytes
        // - 1 flyover hop field: 20 bytes
        // - 1 standard hop field: 12 bytes
        // Total: 12 + 8 + 20 + 12 = 52 bytes
        //
        // Reversed path:
        // - Standard meta header: 4 bytes
        // - 1 info field: 8 bytes
        // - 2 standard hop fields: 2 * 12 bytes
        // Total: 4 + 8 + 24 = 36 bytes
        let path = decode(flyover_path());
        assert_eq!(path.reversed_path_length(), 36);
    }

    // ---------------------------------------------------------------------------
    // to_reversed — single segment
    // ---------------------------------------------------------------------------

    #[test]
    fn to_reversed_single_segment_hop_order() {
        // Original: [(0x0A,0x0B), (0x0C,0x0D)].  Reversed: [(0x0C,0x0D), (0x0A,0x0B)].
        let rev = decode(one_segment_path()).to_reversed();
        assert_eq!(hop_pairs(&rev), [(0x0C, 0x0D), (0x0A, 0x0B)]);
    }

    #[test]
    fn to_reversed_single_segment_cons_dir_flipped() {
        // Original info field has cons_dir=true (bit 0 set).  After reversal it must be false.
        let rev = decode(one_segment_path()).to_reversed();
        let info_flags = rev.raw()[MetaHeader::LENGTH];
        assert_eq!(
            info_flags & InfoField::FLAGS_CONS_DIR,
            0,
            "cons_dir must be cleared"
        );
    }

    #[test]
    fn to_reversed_single_segment_meta() {
        // 2 hops → segment_lengths=[2,0,0].
        // current_info=0 (1 segment), current_hop=1 (pointing to last hop = original first hop).
        let rev = decode(one_segment_path()).to_reversed();
        let meta = rev.meta_header();
        assert_eq!(meta.segment_lengths[0].get(), 2);
        assert_eq!(meta.segment_lengths[1].get(), 0);
        assert_eq!(meta.segment_lengths[2].get(), 0);
        assert_eq!(meta.current_info_field.get(), 0);
        assert_eq!(meta.current_hop_field.get(), 1);
    }

    // ---------------------------------------------------------------------------
    // to_reversed — two segments
    // ---------------------------------------------------------------------------

    #[test]
    fn to_reversed_two_segments_segment_lengths_rotated() {
        // asymmetric path: seg0=1 hop, seg1=2 hops.
        // After reversal segment order is reversed: [2, 1, 0].
        let rev = decode(asymmetric_two_segment_path()).to_reversed();
        let meta = rev.meta_header();
        assert_eq!(meta.segment_lengths[0].get(), 2, "seg0 after reversal");
        assert_eq!(meta.segment_lengths[1].get(), 1, "seg1 after reversal");
        assert_eq!(meta.segment_lengths[2].get(), 0);
    }

    #[test]
    fn to_reversed_two_segments_info_fields_reversed() {
        // two_segment_path: info0 cons_dir=true ts=1, info1 cons_dir=false ts=2.
        // After reversal: [info1_flipped, info0_flipped].
        //   new info0: cons_dir=true  (was false), ts=2
        //   new info1: cons_dir=false (was true),  ts=1
        let rev = decode(two_segment_path()).to_reversed();
        let info0 = rev.info_field(0).unwrap();
        let info1 = rev.info_field(1).unwrap();
        assert_eq!(info0.timestamp().timestamp(), 2);
        assert_ne!(
            info0.as_ref()[0] & InfoField::FLAGS_CONS_DIR,
            0,
            "info0 cons_dir=true"
        );
        assert_eq!(info1.timestamp().timestamp(), 1);
        assert_eq!(
            info1.as_ref()[0] & InfoField::FLAGS_CONS_DIR,
            0,
            "info1 cons_dir=false"
        );
    }

    #[test]
    fn to_reversed_two_segments_hop_order() {
        // two_segment_path hops in order: (1,2),(3,4),(5,6),(7,8).
        // Reversed: (7,8),(5,6),(3,4),(1,2).
        let rev = decode(two_segment_path()).to_reversed();
        assert_eq!(hop_pairs(&rev), [(7, 8), (5, 6), (3, 4), (1, 2)]);
    }

    // ---------------------------------------------------------------------------
    // to_reversed — three segments
    // ---------------------------------------------------------------------------

    #[test]
    fn to_reversed_three_segments_segment_lengths_rotated() {
        // three_segment_path: hop counts [1,1,2].
        // After reversal: [s3,s2,s1] = [2,1,1].
        let rev = decode(three_segment_path()).to_reversed();
        let meta = rev.meta_header();
        assert_eq!(meta.segment_lengths[0].get(), 2);
        assert_eq!(meta.segment_lengths[1].get(), 1);
        assert_eq!(meta.segment_lengths[2].get(), 1);
    }

    // ---------------------------------------------------------------------------
    // to_reversed — flyover conversion (spec A.8)
    // ---------------------------------------------------------------------------

    #[test]
    fn to_reversed_flyover_bit_cleared() {
        // flyover_path: [flyover(0x0A,0x0B), standard(0x0C,0x0D)].
        // After reversal: [standard, converted_flyover].
        // The converted flyover (hop 1 in the output) must have FLYOVER_BIT cleared.
        // Hop 1 starts at: 4 (meta) + 8 (info) + 12 (hop 0) = 24.
        let rev = decode(flyover_path()).to_reversed();
        let raw = rev.raw();
        let hop1_flags = raw[MetaHeader::LENGTH + 8 + StandardHopField::ENCODED_SIZE];
        assert_eq!(
            hop1_flags & FlyoverHopField::FLYOVER_BIT,
            0,
            "flyover bit must be cleared"
        );
    }

    #[test]
    fn to_reversed_flyover_preserves_common_fields() {
        // The converted flyover hop must preserve exp_time, cons_ingress, cons_egress.
        let rev = decode(flyover_path()).to_reversed();
        let raw = rev.raw();
        let base = MetaHeader::LENGTH + 8 + StandardHopField::ENCODED_SIZE;
        assert_eq!(raw[base + 1], 0x05, "exp_time preserved");
        assert_eq!(
            &raw[base + 2..base + 4],
            &[0x00, 0x0A],
            "cons_ingress preserved"
        );
        assert_eq!(
            &raw[base + 4..base + 6],
            &[0x00, 0x0B],
            "cons_egress preserved"
        );
    }

    // ---------------------------------------------------------------------------
    // reverse_to_slice
    // ---------------------------------------------------------------------------

    #[test]
    fn reverse_to_slice_matches_to_reversed() {
        let path = decode(one_segment_path());
        let mut buf = vec![0u8; path.reversed_path_length()];
        path.reverse_to_slice(&mut buf);
        assert_eq!(path.to_reversed().raw(), buf.as_slice());
    }

    #[test]
    #[should_panic]
    fn reverse_to_slice_panics_wrong_buffer_size() {
        let path = decode(one_segment_path());
        let mut buf = vec![0u8; path.reversed_path_length() + 1];
        path.reverse_to_slice(&mut buf);
    }

    // ---------------------------------------------------------------------------
    // HummingbirdPath helpers
    // ---------------------------------------------------------------------------

    fn make_info(cons_dir: bool, timestamp: u32) -> InfoField {
        InfoField {
            peer: false,
            cons_dir,
            seg_id: 0,
            timestamp_epoch: timestamp,
        }
    }

    fn make_std_hop(cons_ingress: u16, cons_egress: u16) -> (Option<IsdAsn>, StandardHopField) {
        (
            Some(IsdAsn::new(Isd::new(1), Asn::new(1))),
            StandardHopField {
                ingress_router_alert: false,
                egress_router_alert: false,
                exp_time: 63,
                cons_ingress,
                cons_egress,
                mac: [0u8; 6],
            },
        )
    }

    fn make_reservation(
        ingress: u16,
        egress: u16,
        start_offset_secs: u32,
        duration: u16,
        bw_bytes_per_sec: u64,
    ) -> Reservation {
        // start_offset_secs = how many seconds ago the reservation started,
        // keeping (now - start) small enough to fit in u16.
        let start = DateTime::from_timestamp(
            (Utc::now().timestamp() as u32).saturating_sub(start_offset_secs) as i64,
            0,
        )
        .expect("valid timestamp");
        Reservation {
            info: ReservationInfo {
                isd_as: IsdAsn::new(Isd::new(1), Asn::new(1)),
                ingress_interface: ingress,
                egress_interface: egress,
                res_id: 42,
                bandwidth: Bandwidth::from_bytes_per_sec(bw_bytes_per_sec).unwrap(),
                start,
                duration,
            },
            reservation_key: [0u8; 16].into(),
        }
    }

    // ---------------------------------------------------------------------------
    // HummingbirdPath
    // ---------------------------------------------------------------------------

    // ---------------------------------------------------------------------------
    // add_segment
    // ---------------------------------------------------------------------------

    #[test]
    fn add_fourth_segment_returns_too_many_segments() {
        let mut path = HummingbirdPath::new();
        for i in 0..3u16 {
            path.add_segment(
                make_info(true, i as u32),
                vec![make_std_hop(i * 2, i * 2 + 1)],
            )
            .unwrap();
        }
        let result = path.add_segment(make_info(true, 99), vec![make_std_hop(10, 11)]);
        assert!(
            matches!(result, Err(HummingbirdPathError::TooManySegments)),
            "expected TooManySegments, got {result:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // path_header_len
    // ---------------------------------------------------------------------------

    #[test]
    fn path_header_len_counts_flyover_hops() {
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4)],
        )
        .unwrap();

        let hops_no_res: Vec<(usize, usize, Option<Reservation>)> =
            vec![(0, 0, None), (0, 1, None)];
        assert_eq!(path.path_header_len(&hops_no_res), 44);

        let res = make_reservation(1, 2, 1000, 200, 1024);
        let hops_with_res: Vec<(usize, usize, Option<Reservation>)> =
            vec![(0, 0, Some(res)), (0, 1, None)];
        assert_eq!(path.path_header_len(&hops_with_res), 52);
    }

    // ---------------------------------------------------------------------------
    // encoded_length
    // ---------------------------------------------------------------------------

    #[test]
    fn encoded_length_no_reservations() {
        // 12 (meta) + 8 (info) + 2×12 (hops) = 44 bytes.
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4)],
        )
        .unwrap();
        assert_eq!(path.encoded_length(), 44);
    }

    #[test]
    fn encoded_length_with_matching_reservation() {
        // Same path as above, but one standard hop (12 B) is replaced by a flyover
        // hop (20 B) → extra 8 bytes → 52 bytes total.
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4)],
        )
        .unwrap();
        // Reservation applies in cons_dir=true, so ingress/egress match cons_ingress/cons_egress.
        let res = make_reservation(1, 2, 1000, 200, 1024);
        path.try_add_reservation(res);
        assert_eq!(path.encoded_length(), 52);
    }

    #[test]
    fn encoded_length_with_matching_reservation_over_segment_boundary() {
        // Reservation that spans a segment boundary
        // => Turn first hop fields into flyover hop fields
        // => 8 extra bytes
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 0)],
        )
        .unwrap();
        path.add_segment(
            make_info(true, 2),
            vec![make_std_hop(0, 4), make_std_hop(7, 8)],
        )
        .unwrap();

        // Reservation applies in cons_dir=true, so ingress/egress match cons_ingress/cons_egress.
        let res = make_reservation(3, 4, 1000, 200, 1024);
        path.try_add_reservation(res);
        assert_eq!(path.encoded_length(), 84);
    }

    #[test]
    fn encoded_length_with_non_matching_reservation() {
        // Reservation doesn't match any hop field → no size change.
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4)],
        )
        .unwrap();
        let res = make_reservation(99, 100, 1000, 200, 1024); // wrong interfaces
        path.try_add_reservation(res);
        assert_eq!(path.encoded_length(), 44);
    }

    // ---------------------------------------------------------------------------
    // encode_to_unchecked → WireDecode roundtrip (no reservations)
    // ---------------------------------------------------------------------------

    /// Encodes `path` and returns the resulting bytes.
    fn encode_path(path: &mut HummingbirdPath, dst: IsdAsn) -> Bytes {
        let len = path.encoded_length();
        let mut buf = vec![0u8; len];
        let mut slice: &mut [u8] = &mut buf;
        path.encode_to(dst, 100, 100, &mut slice).unwrap();
        Bytes::from(buf)
    }

    #[test]
    fn encode_roundtrip_via_encoded_hummingbird_path() {
        // Build a path, encode it, decode it back via EncodedHummingbirdPath.
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(0x0A, 0x0B), make_std_hop(0x0C, 0x0D)],
        )
        .unwrap();

        let dst = IsdAsn::new(Isd::new(2), Asn::new(2));
        let mut encoded_bytes = encode_path(&mut path, dst);

        let decoded = EncodedHummingbirdPath::decode(&mut encoded_bytes).unwrap();
        let meta = decoded.meta_header();
        // 2 hops × 12 bytes = 24 bytes → seg_len = 6
        assert_eq!(meta.segment_lengths[0].encode(), 6);
        assert_eq!(meta.segment_lengths[1].encode(), 0);
        assert!(meta.base_timestamp.get() > 0);

        let hops: Vec<(u16, u16)> = decoded
            .hop_fields()
            .map(|h| {
                (
                    h.cons_ingress_interface().map(NonZeroU16::get).unwrap_or(0),
                    h.cons_egress_interface().map(NonZeroU16::get).unwrap_or(0),
                )
            })
            .collect();
        assert_eq!(hops, [(0x0A, 0x0B), (0x0C, 0x0D)]);
    }

    #[test]
    fn encode_no_reservation_produces_no_flyover_bits() {
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4)],
        )
        .unwrap();
        let dst = IsdAsn::new(Isd::new(1), Asn::new(1));
        let encoded_bytes = encode_path(&mut path, dst);
        let decoded = EncodedHummingbirdPath::decode(&mut encoded_bytes.clone()).unwrap();
        assert_eq!(decoded.flyover_hop_fields().count(), 0);
        assert_eq!(decoded.regular_hop_fields().count(), 2);
    }

    // ---------------------------------------------------------------------------
    // encode_to_unchecked with reservation
    // ---------------------------------------------------------------------------

    #[test]
    fn encode_with_matching_reservation_sets_flyover_bit() {
        // cons_dir=true: interfaces(true) = (cons_ingress, cons_egress)
        // Reservation with ingress=1, egress=2 should match the first hop.
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4)],
        )
        .unwrap();
        let res = make_reservation(1, 2, 1000, 200, 1024);
        path.try_add_reservation(res);

        let dst = IsdAsn::new(Isd::new(2), Asn::new(2));
        let encoded_bytes = encode_path(&mut path, dst);
        let decoded = EncodedHummingbirdPath::decode(&mut encoded_bytes.clone()).unwrap();

        assert_eq!(
            decoded.flyover_hop_fields().count(),
            1,
            "one flyover expected"
        );
        assert_eq!(
            decoded.regular_hop_fields().count(),
            1,
            "one standard hop expected"
        );
    }

    #[test]
    fn encode_with_matching_reservation_across_segment_boundary_sets_flyover_bit() {
        // cons_dir=true: interfaces(true) = (cons_ingress, cons_egress)
        // Reservation with ingress=3, egress=4 should match the first hop.
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 0)],
        )
        .unwrap();
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(0, 4), make_std_hop(5, 6)],
        )
        .unwrap();

        let res = make_reservation(3, 4, 1000, 200, 1024);
        path.try_add_reservation(res);

        let dst = IsdAsn::new(Isd::new(2), Asn::new(2));
        let encoded_bytes = encode_path(&mut path, dst);
        let decoded = EncodedHummingbirdPath::decode(&mut encoded_bytes.clone()).unwrap();

        assert_eq!(
            decoded.flyover_hop_fields().count(),
            1,
            "one flyover expected"
        );
        assert_eq!(
            decoded.regular_hop_fields().count(),
            3,
            "three standard hops expected"
        );
    }

    #[test]
    fn encode_flyover_hop_preserves_interfaces() {
        // After applying a reservation, the resulting flyover hop field must still
        // carry the original cons_ingress / cons_egress values.
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(0x0A, 0x0B), make_std_hop(0x0C, 0x0D)],
        )
        .unwrap();
        let res = make_reservation(0x0A, 0x0B, 1000, 200, 1024);
        path.try_add_reservation(res);

        let dst = IsdAsn::new(Isd::new(2), Asn::new(2));
        let encoded_bytes = encode_path(&mut path, dst);
        let decoded = EncodedHummingbirdPath::decode(&mut encoded_bytes.clone()).unwrap();

        let flyover = decoded.flyover_hop_fields().next().unwrap();
        assert_eq!(
            flyover
                .cons_ingress_interface()
                .map(NonZeroU16::get)
                .unwrap_or(0),
            0x0A
        );
        assert_eq!(
            flyover
                .cons_egress_interface()
                .map(NonZeroU16::get)
                .unwrap_or(0),
            0x0B
        );
    }

    #[test]
    fn encode_flyover_hop_encodes_reservation_metadata() {
        // The flyover hop field must encode the reservation start offset and duration.
        let mut path = HummingbirdPath::new();
        path.add_segment(make_info(true, 1), vec![make_std_hop(1, 2)])
            .unwrap();
        let reservation_start_offset = 900u32; // seconds before now
        let res = make_reservation(1, 2, reservation_start_offset, 300, 1024);
        path.try_add_reservation(res);

        let dst = IsdAsn::new(Isd::new(2), Asn::new(2));
        let encoded = path.to_encoded(dst, 100, 100).unwrap();
        // offset = now - (now - reservation_start_offset) = reservation_start_offset
        let expected_offset = reservation_start_offset as u16;

        // After the meta header (12 B) and one info field (8 B), the flyover hop starts at 20.
        // FlyoverHopField layout (flags[0], exp_time[1], cons_ingress[2..4], cons_egress[4..6],
        // agg_mac[6..12], res_id+bw[12..16]):
        //   ResStartOffset at bytes [16..18] → absolute offset 36.
        //   ResDuration at bytes [18..20] → absolute offset 38.
        let raw = encoded.raw();
        let res_start_offset = u16::from_be_bytes([raw[36], raw[37]]);
        let res_duration = u16::from_be_bytes([raw[38], raw[39]]);
        assert_eq!(
            res_start_offset, expected_offset,
            "res_start_offset = base_ts - start"
        );
        assert_eq!(res_duration, 300, "res_duration preserved");
    }

    #[test]
    fn encode_with_non_matching_reservation_no_flyover() {
        // A reservation that doesn't match any hop field must be silently ignored.
        let mut path = HummingbirdPath::new();
        path.add_segment(make_info(true, 1), vec![make_std_hop(1, 2)])
            .unwrap();
        let res = make_reservation(99, 100, 1000, 200, 1024); // wrong interfaces
        path.try_add_reservation(res);

        let dst = IsdAsn::new(Isd::new(2), Asn::new(2));
        let encoded_bytes = encode_path(&mut path, dst);
        let decoded = EncodedHummingbirdPath::decode(&mut encoded_bytes.clone()).unwrap();
        assert_eq!(decoded.flyover_hop_fields().count(), 0);
    }

    // ---------------------------------------------------------------------------
    // generate_flyover_macs
    // ---------------------------------------------------------------------------

    #[test]
    fn generate_flyover_macs_produces_entry_for_matching_reservation() {
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4)],
        )
        .unwrap();
        let res = make_reservation(1, 2, 1000, 200, 1024);
        path.add_reservation(0, res.clone()).unwrap();

        let dst = IsdAsn::new(Isd::new(2), Asn::new(2));
        // path_header_len with 1 flyover = 12 (meta) + 8 (info) + 12 (std) + 20 (flyover) = 52.
        let packet_length: u16 = CommonHeader::LENGTH as u16 + 100 + 52 + 200;
        let macs = path.generate_flyover_macs(dst, packet_length, 100).unwrap();

        assert_eq!(macs.dst_isd_asn, dst);
        assert_eq!(macs.packet_length, packet_length);
        assert_eq!(macs.payload_length_suggestion, 200);
        assert_eq!(macs.entries.len(), 1);
        assert_eq!(macs.entries[0].hop_index, 0);
        assert_eq!(macs.entries[0].res_id, res.info.res_id);
        assert_eq!(macs.entries[0].bandwidth, res.info.bandwidth);
        assert_eq!(macs.entries[0].res_duration, res.info.duration);
    }

    #[test]
    fn generate_flyover_macs_no_reservations_returns_empty_entries() {
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4)],
        )
        .unwrap();

        let dst = IsdAsn::new(Isd::new(2), Asn::new(2));
        // path_header_len with no flyovers = 12 (meta) + 8 (info) + 2×12 (std) = 44.
        let packet_length: u16 = CommonHeader::LENGTH as u16 + 100 + 44 + 200;
        let macs = path.generate_flyover_macs(dst, packet_length, 100).unwrap();

        assert!(macs.entries.is_empty());
        assert_eq!(macs.payload_length_suggestion, 200);
    }

    #[test]
    fn generate_flyover_macs_too_short_packet_length_errors() {
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4)],
        )
        .unwrap();

        let dst = IsdAsn::new(Isd::new(2), Asn::new(2));
        // path_header_len with no flyovers is 44; CommonHeader is 12; address_header_len is 100.
        // A packet_length of 100 cannot fit that overhead plus any payload.
        let result = path.generate_flyover_macs(dst, 100, 100);
        assert!(matches!(result, Err(HummingbirdPathError::PayloadTooLong)));
    }

    #[test]
    fn encode_segment_length_updated_after_applying_reservation() {
        // When a standard hop (12 B) is replaced by a flyover hop (20 B),
        // the segment length in the meta header must be updated accordingly.
        // 1 flyover + 1 standard = 20 + 12 = 32 bytes → seg_len = 8.
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4)],
        )
        .unwrap();
        let res = make_reservation(1, 2, 1000, 200, 1024);
        path.try_add_reservation(res);

        let dst = IsdAsn::new(Isd::new(2), Asn::new(2));
        let encoded_bytes = encode_path(&mut path, dst);
        let decoded = EncodedHummingbirdPath::decode(&mut encoded_bytes.clone()).unwrap();
        assert_eq!(decoded.meta_header().segment_lengths[0].encode(), 8);
    }

    // ---------------------------------------------------------------------------
    // encode_to_unchecked: current_hop_field adjustment when reservation is before
    // the current hop.
    // ---------------------------------------------------------------------------

    #[test]
    fn encode_current_hop_index_adjusted_when_reservation_before_current() {
        // Path with 3 hops; current_hop_field pointing to the third hop (offset 24).
        // A reservation applied to the FIRST hop (at offset 0) turns it into a flyover
        // (20 B instead of 12 B), shifting the third hop's offset by +8 to 32.
        // The encoded current_hop_field must be updated to reflect the new offset.
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4), make_std_hop(5, 6)],
        )
        .unwrap();
        // Point current_hop_field to the third hop (byte offset 24).
        path.path_meta.current_hop_field = HummingbirdHopfieldIndex::new_unchecked(24);
        let res = make_reservation(1, 2, 1000, 200, 1024);
        path.try_add_reservation(res);

        let dst = IsdAsn::new(Isd::new(2), Asn::new(2));
        let mut buf = vec![0u8; path.encoded_length()];
        let mut slice: &mut [u8] = &mut buf;
        path.encode_to(dst, 100, 100, &mut slice).unwrap();

        // Decode and check the current_hop_field in the encoded meta header.
        let mut bytes = Bytes::from(buf);
        let decoded = EncodedHummingbirdPath::decode(&mut bytes).unwrap();
        assert_eq!(
            decoded.meta_header().current_hop_field.byte_offset(),
            32,
            "current_hop_field must be advanced by 8 bytes (flyover - standard size)"
        );
    }

    #[test]
    fn encode_current_hop_index_not_adjusted_when_reservation_after_current() {
        // Path with 3 hops; current_hop_field = 0 (pointing to the first hop).
        // A reservation applied to the THIRD hop (at offset 24) is AFTER the current
        // hop, so current_hop_field must NOT be changed (stays 0).
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4), make_std_hop(5, 6)],
        )
        .unwrap();
        // current_hop_field = 0 (first hop).
        path.path_meta.current_hop_field = HummingbirdHopfieldIndex::new_unchecked(0);
        let res = make_reservation(5, 6, 1000, 200, 1024); // matches third hop
        path.try_add_reservation(res);

        let dst = IsdAsn::new(Isd::new(2), Asn::new(2));
        let mut buf = vec![0u8; path.encoded_length()];
        let mut slice: &mut [u8] = &mut buf;
        path.encode_to(dst, 100, 100, &mut slice).unwrap();

        let mut bytes = Bytes::from(buf);
        let decoded = EncodedHummingbirdPath::decode(&mut bytes).unwrap();
        assert_eq!(
            decoded.meta_header().current_hop_field.byte_offset(),
            0,
            "current_hop_field must not change when reservation is after current hop"
        );
    }

    // ---------------------------------------------------------------------------
    // add_reservation (direct by flat hop index)
    // ---------------------------------------------------------------------------

    #[test]
    fn add_reservation_applies_to_hop_at_index() {
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4)],
        )
        .unwrap();

        // Interfaces don't matter for add_reservation: it targets the hop by
        // index regardless of whether it would match by ingress/egress/isd_as.
        let res = make_reservation(99, 100, 1000, 200, 1024);
        path.add_reservation(1, res.clone()).unwrap();

        assert_eq!(path.segments[0][0].reservations, vec![]);
        assert_eq!(path.segments[0][1].reservations, vec![res]);
    }

    #[test]
    fn add_reservation_counts_hops_across_segments() {
        let mut path = HummingbirdPath::new();
        path.add_segment(make_info(true, 1), vec![make_std_hop(1, 2)])
            .unwrap();
        path.add_segment(
            make_info(true, 2),
            vec![make_std_hop(3, 4), make_std_hop(5, 6)],
        )
        .unwrap();

        // Flat index 2 is the second hop of the second segment.
        let res = make_reservation(1, 2, 1000, 200, 1024);
        path.add_reservation(2, res.clone()).unwrap();

        assert_eq!(path.segments[0][0].reservations, vec![]);
        assert_eq!(path.segments[1][0].reservations, vec![]);
        assert_eq!(path.segments[1][1].reservations, vec![res]);
    }

    #[test]
    fn add_reservation_out_of_range_returns_error() {
        let mut path = HummingbirdPath::new();
        path.add_segment(make_info(true, 1), vec![make_std_hop(1, 2)])
            .unwrap();

        let res = make_reservation(1, 2, 1000, 200, 1024);
        let result = path.add_reservation(1, res);
        assert!(
            matches!(result, Err(HummingbirdPathError::HopIndexOutOfRange)),
            "expected HopIndexOutOfRange, got {result:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // WireDecode for HummingbirdPath
    // ---------------------------------------------------------------------------

    #[test]
    fn hb_path_wire_decode_single_segment() {
        // Build → encode → decode via WireDecode for HummingbirdPath.
        // The decoded path should carry the same info fields and hop fields.
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 42),
            vec![make_std_hop(0x0A, 0x0B), make_std_hop(0x0C, 0x0D)],
        )
        .unwrap();

        let dst = IsdAsn::new(Isd::new(2), Asn::new(2));
        let mut encoded_bytes = encode_path(&mut path, dst);

        let ases = [
            IsdAsn::new(Isd::new(1), Asn::new(1)),
            IsdAsn::new(Isd::new(1), Asn::new(2)),
        ];
        let decoded = HummingbirdPath::decode(&mut encoded_bytes, &ases).unwrap();

        assert_eq!(decoded.info_fields.len(), 1);
        assert_eq!(decoded.info_fields[0].timestamp_epoch, 42);
        assert!(decoded.info_fields[0].cons_dir);

        assert_eq!(decoded.segments.len(), 1);
        assert_eq!(decoded.segments[0].len(), 2);

        let (ing0, eg0) = decoded.segments[0][0].hop_field.interfaces(true);
        assert_eq!((ing0, eg0), (0x0A, 0x0B));
        let (ing1, eg1) = decoded.segments[0][1].hop_field.interfaces(true);
        assert_eq!((ing1, eg1), (0x0C, 0x0D));
    }

    #[test]
    fn hb_path_wire_decode_two_segments() {
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 10),
            vec![make_std_hop(1, 2), make_std_hop(3, 4)],
        )
        .unwrap();
        path.add_segment(make_info(false, 20), vec![make_std_hop(5, 6)])
            .unwrap();

        let dst = IsdAsn::new(Isd::new(1), Asn::new(1));
        let mut encoded_bytes = encode_path(&mut path, dst);

        let ases = [
            IsdAsn::new(Isd::new(1), Asn::new(1)),
            IsdAsn::new(Isd::new(1), Asn::new(2)),
        ];
        let decoded = HummingbirdPath::decode(&mut encoded_bytes, &ases).unwrap();

        assert_eq!(decoded.info_fields.len(), 2);
        assert_eq!(decoded.info_fields[0].timestamp_epoch, 10);
        assert_eq!(decoded.info_fields[1].timestamp_epoch, 20);

        assert_eq!(decoded.segments.len(), 2);
        assert_eq!(decoded.segments[0].len(), 2);
        assert_eq!(decoded.segments[1].len(), 1);
    }

    #[test]
    fn hb_path_wire_decode_roundtrip() {
        // Encode via HummingbirdPath and decode back via HummingbirdPath::decode.
        let mut path = HummingbirdPath::new();
        path.add_segment(
            make_info(true, 77),
            vec![make_std_hop(11, 22), make_std_hop(33, 44)],
        )
        .unwrap();

        let dst = IsdAsn::new(Isd::new(1), Asn::new(1));
        let mut encoded_bytes = encode_path(&mut path, dst);

        let ases = [
            IsdAsn::new(Isd::new(1), Asn::new(1)),
            IsdAsn::new(Isd::new(1), Asn::new(2)),
        ];
        let decoded = HummingbirdPath::decode(&mut encoded_bytes, &ases).unwrap();

        assert_eq!(decoded.info_fields.len(), 1);
        assert_eq!(decoded.info_fields[0].timestamp_epoch, 77);
        assert_eq!(decoded.segments[0].len(), 2);
    }

    #[test]
    fn hb_path_wire_decode_preserves_base_timestamp() {
        // The base_timestamp set during encoding must survive the encode → wire-decode roundtrip.
        let mut path = HummingbirdPath::new();
        path.add_segment(make_info(true, 1), vec![make_std_hop(1, 2)])
            .unwrap();

        let dst = IsdAsn::new(Isd::new(1), Asn::new(1));
        let encoded = path.to_encoded(dst, 100, 100).unwrap();
        let expected_ts = encoded.meta_header().base_timestamp.get();
        assert!(
            expected_ts > 0,
            "base_timestamp must be set to current time during encoding"
        );

        let mut raw = Bytes::copy_from_slice(encoded.raw());
        let ases = [IsdAsn::new(Isd::new(1), Asn::new(1))];
        let decoded = HummingbirdPath::decode(&mut raw, &ases).unwrap();
        assert_eq!(decoded.path_meta.base_timestamp.get(), expected_ts);
    }
}
