use std::{ops::Deref, time::SystemTime};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::{DateTime, Utc};

use crate::{
    address::IsdAsn,
    hummingbird::Reservation,
    packet::{DecodeError, InadequateBufferSize},
    path::{
        EncodedHopField, EncodedInfoField, EncodedSegment, EncodedSegments,
        EncodedStandardHopField, EncodedStandardPath, HopField, HopFieldIndex, InfoField,
        InfoFieldIndex, InfoFields, MetaHeader, MetaReserved, SegmentLength, StandardHopField,
        hummingbird::{
            EncodedFlyoverHopField, FlyoverHopField, HummingbirdCounter, HummingbirdHopField,
            HummingbirdHopFields, HummingbirdHopfieldIndex, HummingbirdInfoFieldIndex,
            HummingbirdMetaHeader, HummingbirdMetaReserved, HummingbirdSegmentLength,
        },
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
    // TODO: Add Hummingbird-specific methods.

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

    /// Returns an iterator over all of the [`EncodedHummingbirdHopFields`]s in
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

/// Hummingbird path builder errors.
#[derive(Debug, thiserror::Error)]
pub enum HummingbirdPathBuilderError {
    /// Error when trying to add too many segments to a path.
    #[error("A path can only be constructed with up to 3 segments")]
    TooManySegments,

    /// Error when trying to add a segment that is too long to be represented
    /// in the Hummingbird meta header segment length field.
    #[error("A Hummingbird segment can be at most 508 bytes long")]
    SegmentTooLong,

    /// Invalid reservation start relative to path meta header, e.g. reservation
    /// starts in the future or start offset is too large to fit in the hop field.
    #[error("Invalid reservation start relative to path meta header")]
    InvalidReservationStart,

    /// Reservation is not applicable to any hop field in the path.
    /// A reservation is applicable to a hop field if the hop field is not
    /// a flyover hop field and the reservation's ingress and egress
    /// interfaces match the hop field's interfaces (in the appropriate
    /// direction).
    #[error("Reservation is not applicable to any hop field in the path")]
    ReservationNotApplicable,

    /// Current hop field index is not valid, i.e., either not divisible
    /// by 4 or it the value is too large to fit in the allocated bits.
    #[error("Current hop field index is not valid")]
    InvalidHopFieldIndex,

    /// Raised if the buffer does not have sufficient capacity for encoding the SCION headers.
    #[error("The provided buffer did not have sufficient size")]
    InadequateBufferSize,
}

impl From<InadequateBufferSize> for HummingbirdPathBuilderError {
    fn from(_: InadequateBufferSize) -> Self {
        HummingbirdPathBuilderError::InadequateBufferSize
    }
}

/// A fully decoded Hummingbird data plane path. It can be used to build new paths
/// or to modify existing ones. If you only need to read information, use
/// [EncodedHummingbirdPath] instead for better performance.
#[derive(Debug, Clone)]
pub struct HummingbirdPath {
    /// Path meta data.
    path_meta: HummingbirdMetaHeader,

    /// Info fields of the path.
    info_fields: Vec<InfoField>,

    /// Segments of the path.
    segments: Vec<Vec<HummingbirdHopField>>,

    /// Reservations to apply when encoding
    reservations: Vec<Reservation>,
}

impl HummingbirdPath {
    /// Creates a new HummingbirdPath with the current system time as the base  
    /// timestamp, a default counter and no reservations.   
    pub fn new() -> HummingbirdPath {
        Self::new_with_timestamp(SystemTime::now(), None)
    }

    /// Creates a new HummingbirdPath with the specified base timestamp, an optional
    /// counter, and no reservations. If the counter is not provided, the default
    /// value is picked.
    pub fn new_with_timestamp(
        timestamp: SystemTime,
        counter: Option<HummingbirdCounter>,
    ) -> HummingbirdPath {
        let millis = timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("current time is after UNIX epoch")
            .subsec_millis() as u16;

        let meta_header = HummingbirdMetaHeader {
            current_info_field: 0.into(),
            current_hop_field: HummingbirdHopfieldIndex::new_unchecked(0),
            reserved: HummingbirdMetaReserved::default(),
            segment_lengths: [HummingbirdSegmentLength::new_unchecked(0); 3],
            base_timestamp: timestamp.into(),
            millis_timestamp: millis.into(),
            counter: counter.unwrap_or_default(),
        };

        HummingbirdPath {
            path_meta: meta_header,
            info_fields: vec![],
            segments: vec![],
            reservations: vec![],
        }
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

    /// Returns the base timestamp of the path.
    pub fn base_timestamp(&self) -> u32 {
        self.path_meta.base_timestamp()
    }

    /// Returns the millis timestamp of the path.
    pub fn millis_timestamp(&self) -> u16 {
        self.path_meta.millis_timestamp()
    }

    /// Set the millis timestamp of the path to the specified value.
    pub fn set_millis_timestamp(&mut self, millis: u16) {
        self.path_meta.millis_timestamp = millis.into();
    }

    /// Returns the counter of the path.
    pub fn counter(&self) -> HummingbirdCounter {
        self.path_meta.counter
    }

    /// Set the counter of the path to the specified value.
    pub fn set_counter(&mut self, counter: HummingbirdCounter) {
        self.path_meta.counter = counter;
    }

    /// Returns an iterator over all hop fields in the path zipped
    /// with their corresponding info fields.
    fn hopfields_with_infofield(&self) -> impl Iterator<Item = (&InfoField, &HummingbirdHopField)> {
        self.segments
            .iter()
            .zip(self.info_fields.iter())
            .flat_map(|(segment, info_field)| {
                segment.iter().map(move |hop_field| (info_field, hop_field))
            })
    }

    /// Returns an iterator over the reservations added to this path.
    pub fn reservations(&self) -> impl Iterator<Item = &Reservation> {
        self.reservations.iter()
    }

    /// Add a reservation to use with this path. Reservations added using this
    /// method will be applied to all matching regular HopFields contained
    /// in the segments.
    pub fn add_reservation(
        &mut self,
        reservation: Reservation,
    ) -> Result<(), HummingbirdPathBuilderError> {
        if self.path_meta.base_timestamp() < reservation.info.start {
            // Reservation start is in the future, so it cannot be applied to this path.
            return Err(HummingbirdPathBuilderError::InvalidReservationStart);
        }

        self.reservations.push(reservation);

        Ok(())
    }

    fn applicable_hop_field(&self, reservation: &Reservation) -> Option<&HummingbirdHopField> {
        let ingress_iface = reservation.info.ingress_interface;
        let egress_iface = reservation.info.egress_interface;

        self.hopfields_with_infofield()
            .find(|(info, hop)| {
                // Note: The reservation is only applicable in one direction.
                !hop.is_flyover() && (ingress_iface, egress_iface) == hop.interfaces(info.cons_dir)
            })
            .map(|(_, hop)| hop)
    }

    fn applicable_reservations(&self) -> impl Iterator<Item = &Reservation> {
        self.reservations
            .iter()
            .filter(|r| self.applicable_hop_field(r).is_some())
    }

    /// Return an iterator over the segments on this path.
    pub fn segments(&self) -> impl Iterator<Item = (&InfoField, &[HummingbirdHopField])> {
        self.segments
            .iter()
            .zip(self.info_fields.iter())
            .map(|(segment, info_field)| (info_field, segment.as_slice()))
    }

    /// Add a segment to the path.
    pub fn add_segment(
        &mut self,
        info_field: InfoField,
        hop_fields: Vec<HummingbirdHopField>,
    ) -> Result<(), HummingbirdPathBuilderError> {
        if self.info_fields.len() >= 3 {
            return Err(HummingbirdPathBuilderError::TooManySegments);
        }

        let segment_len = hop_fields
            .iter()
            .map(WireEncode::encoded_length)
            .sum::<usize>();

        let segment_len = HummingbirdSegmentLength::new(segment_len)
            .ok_or(HummingbirdPathBuilderError::SegmentTooLong)?;

        let seg_idx = self.info_fields.len();
        self.path_meta.segment_lengths[seg_idx] = segment_len;
        self.info_fields.push(info_field);
        self.segments.push(hop_fields);

        Ok(())
    }

    /// The length if it were to be encoded now.
    pub fn encoded_length(&self) -> usize {
        self.path_meta.encoded_length()
            + self
                .info_fields
                .iter()
                .map(|f| f.encoded_length())
                .sum::<usize>()
            + self
                .segments
                .iter()
                .flat_map(|s| s.iter())
                .map(|f| f.encoded_length())
                .sum::<usize>()
            + self.applicable_reservations().count()
                * (FlyoverHopField::ENCODED_SIZE - StandardHopField::ENCODED_SIZE)
    }

    /// Apply reservations by turning applicable hop fields into flyover hop
    /// fields, adjusting segment lengths and current hop field index.
    ///
    /// If `unchecked` is true, then this method will not return an error.
    fn apply_reservations(
        &mut self,
        destination: IsdAsn,
        pkt_len: u16,
        unchecked: bool,
    ) -> Result<(), HummingbirdPathBuilderError> {
        let meta_header = self.path_meta;
        let mut curr_hf_index = meta_header.current_hop_field.byte_offset();

        // Apply reservations by replacing regular hop fields with flyover hop fields.
        self.reservations.iter().for_each(|r| {
            let ingress_iface = r.info.ingress_interface;
            let egress_iface = r.info.egress_interface;

            // Track the byte offset of each hop field as we scan, so that we can
            // determine whether the matched hop field is before the current hop
            // field index (and thus whether the index needs to be adjusted).
            let mut scanned_offset = 0usize;

            let found = self
                .segments
                .iter_mut()
                .zip(self.info_fields.iter())
                .flat_map(|(segment, info_field)| {
                    segment
                        .iter_mut()
                        .map(move |hop_field| (info_field, hop_field))
                })
                // Find the matching hop field while accumulating its byte offset.
                // A reservation is only ever applicable to one hop field per path.
                .find_map(|(info, hop)| {
                    let this_offset = scanned_offset;
                    scanned_offset += hop.encoded_length();
                    // Note: The reservation is only applicable in one direction.
                    if !hop.is_flyover()
                        && (ingress_iface, egress_iface) == hop.interfaces(info.cons_dir)
                    {
                        Some((hop, this_offset))
                    } else {
                        None
                    }
                });

            if let Some((hf, hop_offset)) = found {
                // If the matched hop field is before the current hop field, the
                // current hop field's byte offset must be advanced by the size
                // difference between a flyover and a standard hop field.
                let is_before = hop_offset < meta_header.current_hop_field.byte_offset();

                *hf = match hf {
                    HummingbirdHopField::Standard(standard_hop_field) => {
                        HummingbirdHopField::Flyover(standard_hop_field.apply_reservation(
                            meta_header,
                            r,
                            destination,
                            pkt_len,
                        ))
                    }
                    _ => unreachable!(),
                };

                if is_before {
                    curr_hf_index += FlyoverHopField::ENCODED_SIZE - StandardHopField::ENCODED_SIZE;
                }
            }
        });

        // Adjust segment lengths
        for (idx, segment) in self.segments.iter().enumerate() {
            let seg_len = segment
                .iter()
                .map(WireEncode::encoded_length)
                .sum::<usize>();

            if unchecked {
                self.path_meta.segment_lengths[idx] =
                    HummingbirdSegmentLength::new_unchecked(seg_len);
            } else {
                self.path_meta.segment_lengths[idx] = HummingbirdSegmentLength::new(seg_len)
                    .ok_or(HummingbirdPathBuilderError::SegmentTooLong)?;
            }
        }

        // Adjust current hop field index in meta header.
        if unchecked {
            self.path_meta.current_hop_field =
                HummingbirdHopfieldIndex::new_unchecked(curr_hf_index);
        } else {
            self.path_meta.current_hop_field = HummingbirdHopfieldIndex::new(curr_hf_index)
                .ok_or(HummingbirdPathBuilderError::InvalidHopFieldIndex)?;
        }

        Ok(())
    }

    /// Encode the path to a byte buffer, applying any reservations that have been added to
    /// the path. The reservations are applied by replacing regular hop fields with flyover hop
    /// fields.
    ///
    /// Parameters:
    /// - `destination`: The destination ISD-AS of the path, used for calculating the
    ///   flyover hop field MACs.
    /// - `pkt_len`: The length of the packet for which the path is being encoded
    ///   (including the header) used for calculating the flyover hop field MACs.
    ///
    /// See [encoded_length][Self::encoded_length] for the length of the resulting encoding.
    pub fn encode_to<T: BufMut>(
        &mut self,
        destination: IsdAsn,
        pkt_len: u16,
        buffer: &mut T,
    ) -> Result<(), HummingbirdPathBuilderError> {
        self.apply_reservations(destination, pkt_len, false)?;

        // Encode fields to buffer
        self.path_meta.encode_to_unchecked(buffer);
        for info in self.info_fields.iter() {
            info.encode_to(buffer)?;
        }
        for hop_field in self.segments.iter().flat_map(|s| s.iter()) {
            hop_field.encode_to(buffer)?;
        }

        Ok(())
    }

    /// Encode the path to a byte buffer, applying any reservations that have been added to
    /// the path. The reservations are applied by replacing regular hop fields with flyover hop
    /// fields. Does not perform any correctness checks, such as ensuring that
    /// the hop fields are encoded correctly or that segments are not too long.
    ///
    /// Parameters:
    /// - `destination`: The destination ISD-AS of the path, used for calculating the
    ///   flyover hop field MACs.
    /// - `pkt_len`: The length of the packet for which the path is being encoded
    ///   (including the header) used for calculating the flyover hop field MACs.
    ///
    /// See [encoded_length][Self::encoded_length] for the length of the resulting encoding.
    pub fn encode_to_unchecked<T: BufMut>(
        &mut self,
        destination: IsdAsn,
        pkt_len: u16,
        buffer: &mut T,
    ) {
        self.apply_reservations(destination, pkt_len, true)
            .expect("applying reservations should succeed in unchecked mode");

        // Encode fields to buffer
        self.path_meta.encode_to_unchecked(buffer);
        for info in self.info_fields.iter() {
            info.encode_to_unchecked(buffer);
        }
        for hop_field in self.segments.iter().flat_map(|s| s.iter()) {
            hop_field.encode_to_unchecked(buffer);
        }
    }

    /// Turn this path into an [EncodedHummingbirdPath].
    ///
    /// Parameters:
    /// - `destination`: The destination ISD-AS of the path, used for calculating the
    ///   flyover hop field MACs.
    /// - `pkt_len`: The length of the packet for which the path is being encoded
    ///   (including the header) used for calculating the flyover hop field MACs.
    pub fn to_encoded(
        &mut self,
        destination: IsdAsn,
        pkt_len: u16,
    ) -> Result<EncodedHummingbirdPath<Bytes>, HummingbirdPathBuilderError> {
        let mut buffer = vec![0u8; self.encoded_length()];
        self.encode_to(destination, pkt_len, &mut buffer)?;

        Ok(EncodedHummingbirdPath {
            meta_header: self.path_meta,
            encoded_path: buffer.into(),
        })
    }
}

impl Default for HummingbirdPath {
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<EncodedHummingbirdPath> for HummingbirdPath {
    type Error = DecodeError;

    fn try_from(mut value: EncodedHummingbirdPath) -> Result<Self, Self::Error> {
        Self::decode(&mut value.encoded_path)
    }
}

impl WireDecode<Bytes> for HummingbirdPath {
    type Error = DecodeError;

    fn decode(data: &mut Bytes) -> Result<Self, Self::Error> {
        let meta_header = HummingbirdMetaHeader::decode(data)?;

        let mut info_fields = Vec::new();
        let mut segments = Vec::new();

        for _ in 0..meta_header.info_fields_count() {
            let info_field = InfoField::decode(data)?;
            info_fields.push(info_field);
        }

        for i in 0..3 {
            let mut seg_len = meta_header.segment_lengths[i as usize].length();
            if seg_len == 0 {
                continue;
            }

            let mut hop_fields = Vec::new();
            while seg_len > 0 {
                let hop_field = HummingbirdHopField::decode(data)?;
                seg_len -= hop_field.encoded_length();
                hop_fields.push(hop_field);
            }
            segments.push(hop_fields);
        }

        Ok(HummingbirdPath {
            path_meta: meta_header,
            info_fields,
            segments,
            reservations: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        num::NonZeroU16,
        time::{Duration, UNIX_EPOCH},
    };

    use bytes::Bytes;

    use super::*;
    use crate::{
        address::{Asn, Isd, IsdAsn},
        hummingbird::{Bandwidth, Reservation, ReservationInfo},
        packet::DecodeError,
        path::DataPlanePathErrorKind,
        wire_encoding::WireDecode,
    };

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
        let f3 = ((millis as u32) << 22) | (counter as u32);
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

    fn epoch_plus(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn make_info(cons_dir: bool, timestamp: u32) -> InfoField {
        InfoField {
            peer: false,
            cons_dir,
            seg_id: 0,
            timestamp_epoch: timestamp,
        }
    }

    fn make_std_hop(cons_ingress: u16, cons_egress: u16) -> HummingbirdHopField {
        HummingbirdHopField::Standard(StandardHopField {
            ingress_router_alert: false,
            egress_router_alert: false,
            exp_time: 63,
            cons_ingress,
            cons_egress,
            mac: [0u8; 6],
        })
    }

    fn make_reservation(
        ingress: u16,
        egress: u16,
        start: u32,
        duration: u16,
        bw_kbps: u64,
    ) -> Reservation {
        Reservation {
            info: ReservationInfo {
                isd_as: IsdAsn::new(Isd::new(1), Asn::new(1)),
                ingress_interface: ingress,
                egress_interface: egress,
                res_id: 42,
                bandwidth: Bandwidth::from_kbps(bw_kbps).unwrap(),
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
    fn add_single_segment_updates_meta() {
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4)],
        )
        .unwrap();

        assert_eq!(path.info_fields.len(), 1);
        assert_eq!(path.segments.len(), 1);
        assert_eq!(path.segments[0].len(), 2);
        // 2 standard hops × 12 bytes = 24 bytes → seg_len = 24/4 = 6
        assert_eq!(path.path_meta.segment_lengths[0].encode(), 6);
        assert_eq!(path.path_meta.segment_lengths[1].encode(), 0);
        assert_eq!(path.path_meta.segment_lengths[2].encode(), 0);
    }

    #[test]
    fn add_three_segments_succeeds() {
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
        for i in 0..3u16 {
            path.add_segment(
                make_info(true, i as u32),
                vec![make_std_hop(i * 2, i * 2 + 1)],
            )
            .unwrap();
        }
        assert_eq!(path.segments.len(), 3);
        // Each segment has 1 standard hop → 12 bytes → seg_len = 3
        for seg in &path.path_meta.segment_lengths {
            assert_eq!(seg.encode(), 3);
        }
    }

    #[test]
    fn add_fourth_segment_returns_too_many_segments() {
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
        for i in 0..3u16 {
            path.add_segment(
                make_info(true, i as u32),
                vec![make_std_hop(i * 2, i * 2 + 1)],
            )
            .unwrap();
        }
        let result = path.add_segment(make_info(true, 99), vec![make_std_hop(10, 11)]);
        assert!(
            matches!(result, Err(HummingbirdPathBuilderError::TooManySegments)),
            "expected TooManySegments, got {result:?}"
        );
    }

    #[test]
    fn add_segment_too_long_returns_error() {
        // HummingbirdSegmentLength::new() caps at 508 bytes (127 * 4).
        // 43 standard hops × 12 bytes = 516 bytes > 508 → SegmentTooLong.
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
        let hops: Vec<HummingbirdHopField> = (0..43u16).map(|i| make_std_hop(i, i + 1)).collect();
        let result = path.add_segment(make_info(true, 1), hops);
        assert!(
            matches!(result, Err(HummingbirdPathBuilderError::SegmentTooLong)),
            "expected SegmentTooLong, got {result:?}"
        );
    }

    // ---------------------------------------------------------------------------
    // add_reservation
    // ---------------------------------------------------------------------------

    #[test]
    fn add_reservation_with_start_before_base_ts_succeeds() {
        // base_timestamp = 1000; reservation.start = 900 → start is in the past → OK.
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
        path.add_segment(make_info(true, 1), vec![make_std_hop(1, 2)])
            .unwrap();
        let res = make_reservation(1, 2, 900, 200, 1024);
        assert!(path.add_reservation(res).is_ok());
    }

    #[test]
    fn add_reservation_with_start_equal_base_ts_succeeds() {
        // Reservation starts exactly at the base timestamp → offset = 0, valid.
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
        path.add_segment(make_info(true, 1), vec![make_std_hop(1, 2)])
            .unwrap();
        let res = make_reservation(1, 2, 1000, 200, 1024);
        assert!(path.add_reservation(res).is_ok());
    }

    #[test]
    fn add_reservation_with_start_after_base_ts_fails() {
        // Reservation start is in the future relative to the path base timestamp.
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
        path.add_segment(make_info(true, 1), vec![make_std_hop(1, 2)])
            .unwrap();
        let res = make_reservation(1, 2, 1001, 200, 1024);
        assert!(
            matches!(
                path.add_reservation(res),
                Err(HummingbirdPathBuilderError::InvalidReservationStart)
            ),
            "should reject reservation whose start is after base_timestamp"
        );
    }

    // ---------------------------------------------------------------------------
    // encoded_length
    // ---------------------------------------------------------------------------

    #[test]
    fn encoded_length_no_reservations() {
        // 12 (meta) + 8 (info) + 2×12 (hops) = 44 bytes.
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
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
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4)],
        )
        .unwrap();
        // Reservation applies in cons_dir=true, so ingress/egress match cons_ingress/cons_egress.
        let res = make_reservation(1, 2, 1000, 200, 1024);
        path.add_reservation(res).unwrap();
        assert_eq!(path.encoded_length(), 52);
    }

    #[test]
    fn encoded_length_with_non_matching_reservation() {
        // Reservation doesn't match any hop field → no size change.
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4)],
        )
        .unwrap();
        let res = make_reservation(99, 100, 1000, 200, 1024); // wrong interfaces
        path.add_reservation(res).unwrap();
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
        path.encode_to_unchecked(dst, 100, &mut slice);
        Bytes::from(buf)
    }

    #[test]
    fn encode_roundtrip_via_encoded_hummingbird_path() {
        // Build a path, encode it, decode it back via EncodedHummingbirdPath.
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
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
        assert_eq!(meta.base_timestamp.get(), 1000);

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
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
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
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4)],
        )
        .unwrap();
        let res = make_reservation(1, 2, 1000, 200, 1024);
        path.add_reservation(res).unwrap();

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
    fn encode_flyover_hop_preserves_interfaces() {
        // After applying a reservation, the resulting flyover hop field must still
        // carry the original cons_ingress / cons_egress values.
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(0x0A, 0x0B), make_std_hop(0x0C, 0x0D)],
        )
        .unwrap();
        let res = make_reservation(0x0A, 0x0B, 1000, 200, 1024);
        path.add_reservation(res).unwrap();

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
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
        path.add_segment(make_info(true, 1), vec![make_std_hop(1, 2)])
            .unwrap();
        // start=900 → res_start_offset = base_ts - start = 1000 - 900 = 100
        let res = make_reservation(1, 2, 900, 300, 1024);
        path.add_reservation(res).unwrap();

        let dst = IsdAsn::new(Isd::new(2), Asn::new(2));
        let mut buf = vec![0u8; path.encoded_length()];
        let mut slice: &mut [u8] = &mut buf;
        path.encode_to_unchecked(dst, 100, &mut slice);

        // After the meta header (12) and one info field (8), the flyover hop starts at 20.
        // FlyoverHopField layout (after flags[0], exp_time[1], cons_ingress[2..4], cons_egress[4..6],
        // agg_mac[6..12], res_id+bw[12..16]):
        //   ResStartOffset is at bytes [16..18] of the flyover hop → absolute offset 36.
        //   ResDuration is at bytes [18..20] of the flyover hop → absolute offset 38.
        let res_start_offset = u16::from_be_bytes([buf[36], buf[37]]);
        let res_duration = u16::from_be_bytes([buf[38], buf[39]]);
        assert_eq!(res_start_offset, 100, "res_start_offset = base_ts - start");
        assert_eq!(res_duration, 300, "res_duration preserved");
    }

    #[test]
    fn encode_with_non_matching_reservation_no_flyover() {
        // A reservation that doesn't match any hop field must be silently ignored.
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
        path.add_segment(make_info(true, 1), vec![make_std_hop(1, 2)])
            .unwrap();
        let res = make_reservation(99, 100, 1000, 200, 1024); // wrong interfaces
        path.add_reservation(res).unwrap();

        let dst = IsdAsn::new(Isd::new(2), Asn::new(2));
        let encoded_bytes = encode_path(&mut path, dst);
        let decoded = EncodedHummingbirdPath::decode(&mut encoded_bytes.clone()).unwrap();
        assert_eq!(decoded.flyover_hop_fields().count(), 0);
    }

    #[test]
    fn encode_segment_length_updated_after_applying_reservation() {
        // When a standard hop (12 B) is replaced by a flyover hop (20 B),
        // the segment length in the meta header must be updated accordingly.
        // 1 flyover + 1 standard = 20 + 12 = 32 bytes → seg_len = 8.
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4)],
        )
        .unwrap();
        let res = make_reservation(1, 2, 1000, 200, 1024);
        path.add_reservation(res).unwrap();

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
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4), make_std_hop(5, 6)],
        )
        .unwrap();
        // Point current_hop_field to the third hop (byte offset 24).
        path.path_meta.current_hop_field = HummingbirdHopfieldIndex::new_unchecked(24);
        let res = make_reservation(1, 2, 1000, 200, 1024);
        path.add_reservation(res).unwrap();

        let dst = IsdAsn::new(Isd::new(2), Asn::new(2));
        let mut buf = vec![0u8; path.encoded_length()];
        let mut slice: &mut [u8] = &mut buf;
        path.encode_to_unchecked(dst, 100, &mut slice);

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
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
        path.add_segment(
            make_info(true, 1),
            vec![make_std_hop(1, 2), make_std_hop(3, 4), make_std_hop(5, 6)],
        )
        .unwrap();
        // current_hop_field = 0 (first hop).
        path.path_meta.current_hop_field = HummingbirdHopfieldIndex::new_unchecked(0);
        let res = make_reservation(5, 6, 1000, 200, 1024); // matches third hop
        path.add_reservation(res).unwrap();

        let dst = IsdAsn::new(Isd::new(2), Asn::new(2));
        let mut buf = vec![0u8; path.encoded_length()];
        let mut slice: &mut [u8] = &mut buf;
        path.encode_to_unchecked(dst, 100, &mut slice);

        let mut bytes = Bytes::from(buf);
        let decoded = EncodedHummingbirdPath::decode(&mut bytes).unwrap();
        assert_eq!(
            decoded.meta_header().current_hop_field.byte_offset(),
            0,
            "current_hop_field must not change when reservation is after current hop"
        );
    }

    // ---------------------------------------------------------------------------
    // WireDecode for HummingbirdPath
    // ---------------------------------------------------------------------------

    #[test]
    fn hb_path_wire_decode_single_segment() {
        // Build → encode → decode via WireDecode for HummingbirdPath.
        // The decoded path should carry the same info fields and hop fields.
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
        path.add_segment(
            make_info(true, 42),
            vec![make_std_hop(0x0A, 0x0B), make_std_hop(0x0C, 0x0D)],
        )
        .unwrap();

        let dst = IsdAsn::new(Isd::new(2), Asn::new(2));
        let mut encoded_bytes = encode_path(&mut path, dst);

        let decoded = HummingbirdPath::decode(&mut encoded_bytes).unwrap();

        assert_eq!(decoded.info_fields.len(), 1);
        assert_eq!(decoded.info_fields[0].timestamp_epoch, 42);
        assert!(decoded.info_fields[0].cons_dir);

        assert_eq!(decoded.segments.len(), 1);
        assert_eq!(decoded.segments[0].len(), 2);

        let (ing0, eg0) = decoded.segments[0][0].interfaces(true);
        assert_eq!((ing0, eg0), (0x0A, 0x0B));
        let (ing1, eg1) = decoded.segments[0][1].interfaces(true);
        assert_eq!((ing1, eg1), (0x0C, 0x0D));
    }

    #[test]
    fn hb_path_wire_decode_two_segments() {
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(5000), None);
        path.add_segment(
            make_info(true, 10),
            vec![make_std_hop(1, 2), make_std_hop(3, 4)],
        )
        .unwrap();
        path.add_segment(make_info(false, 20), vec![make_std_hop(5, 6)])
            .unwrap();

        let dst = IsdAsn::new(Isd::new(1), Asn::new(1));
        let mut encoded_bytes = encode_path(&mut path, dst);

        let decoded = HummingbirdPath::decode(&mut encoded_bytes).unwrap();

        assert_eq!(decoded.info_fields.len(), 2);
        assert_eq!(decoded.info_fields[0].timestamp_epoch, 10);
        assert_eq!(decoded.info_fields[1].timestamp_epoch, 20);

        assert_eq!(decoded.segments.len(), 2);
        assert_eq!(decoded.segments[0].len(), 2);
        assert_eq!(decoded.segments[1].len(), 1);
    }

    #[test]
    fn hb_path_wire_decode_preserves_base_timestamp() {
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(9999), None);
        path.add_segment(make_info(true, 1), vec![make_std_hop(1, 2)])
            .unwrap();

        let dst = IsdAsn::new(Isd::new(1), Asn::new(1));
        let mut encoded_bytes = encode_path(&mut path, dst);

        let decoded = HummingbirdPath::decode(&mut encoded_bytes).unwrap();
        assert_eq!(decoded.path_meta.base_timestamp(), 9999);
    }

    #[test]
    fn hb_path_try_from_encoded_roundtrip() {
        // Encode via HummingbirdPath and decode via TryFrom<EncodedHummingbirdPath>.
        let mut path = HummingbirdPath::new_with_timestamp(epoch_plus(1000), None);
        path.add_segment(
            make_info(true, 77),
            vec![make_std_hop(11, 22), make_std_hop(33, 44)],
        )
        .unwrap();

        let dst = IsdAsn::new(Isd::new(1), Asn::new(1));
        let mut encoded_bytes = encode_path(&mut path, dst);

        // Decode via EncodedHummingbirdPath first, then convert.
        let encoded = EncodedHummingbirdPath::decode(&mut encoded_bytes).unwrap();
        let decoded = HummingbirdPath::try_from(encoded).unwrap();

        assert_eq!(decoded.info_fields.len(), 1);
        assert_eq!(decoded.info_fields[0].timestamp_epoch, 77);
        assert_eq!(decoded.segments[0].len(), 2);
    }
}
