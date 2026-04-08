use std::ops::Deref;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::{DateTime, Utc};

use crate::{
    packet::DecodeError,
    path::{
        EncodedHopField, EncodedInfoField, EncodedSegment, EncodedSegments,
        EncodedStandardHopField, EncodedStandardPath, HopFieldIndex, InfoField, InfoFieldIndex,
        InfoFields, MetaHeader, MetaReserved, SegmentLength, StandardHopField,
        hummingbird::{
            EncodedFlyoverHopField, FlyoverHopField, HummingbirdHopFields, HummingbirdMetaHeader,
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
            meta_header: self.meta_header.clone(),
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

        let final_hop_idx = self.hop_fields_count().saturating_sub(1) as u8;
        let reversed_hop_idx = final_hop_idx.saturating_sub(meta_header.current_hop_field.get());
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
            meta_header: self.meta_header.clone(),
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
            meta_header: self.meta_header.clone(),
            encoded_path: Bytes::copy_from_slice(&self.encoded_path),
        }
    }

    /// Creates a new path using the Bytes of this path as backing storage
    pub fn to_slice_path(&self) -> EncodedHummingbirdPath<&[u8]> {
        EncodedHummingbirdPath {
            meta_header: self.meta_header.clone(),
            encoded_path: self.encoded_path.as_ref(),
        }
    }
}
impl<T: AsRef<[u8]>> EncodedHummingbirdPath<T> {
    /// Transforms the path to be backed by [`Bytes`].
    pub fn to_bytes_path(&self) -> EncodedHummingbirdPath<Bytes> {
        EncodedHummingbirdPath {
            meta_header: self.meta_header.clone(),
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

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use bytes::Bytes;

    use super::*;
    use crate::{packet::DecodeError, path::DataPlanePathErrorKind, wire_encoding::WireDecode};

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
        let f1 = (info as u32)
            | ((hop as u32) << 2)
            | ((seg0 as u32) << 11)
            | ((seg1 as u32) << 18)
            | ((seg2 as u32) << 25);
        let f3 = (millis as u32) | (counter << 10);
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
        assert_eq!(meta.segment_lengths[0].get(), 6);
        assert_eq!(meta.segment_lengths[1].get(), 0);
        assert_eq!(meta.segment_lengths[2].get(), 0);
        assert_eq!(meta.base_timestamp.get(), 0x1A2B3C4D);
    }

    #[test]
    fn decode_two_segments() {
        let path = EncodedHummingbirdPath::decode(&mut two_segment_path()).expect("valid decode");
        let meta = path.meta_header();
        assert_eq!(meta.segment_lengths[0].get(), 6);
        assert_eq!(meta.segment_lengths[1].get(), 6);
        assert_eq!(meta.segment_lengths[2].get(), 0);
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

    #[test]
    fn decode_hop_out_of_range() {
        // hop=1 but max_hop_fields=1 (seg_len=6 → (24-12)/12 = 1) → HopFieldOutOfRange
        let mut data = hb_path_bytes(
            hb_meta_bytes(0, 1, 6, 0, 0, 0, 0, 0),
            &[b"\x00\x00\x00\x00\x00\x00\x00\x00"],
            &[
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
        );
        assert_eq!(
            EncodedHummingbirdPath::decode(&mut data),
            Err(DecodeError::InvalidPath(
                DataPlanePathErrorKind::HopFieldOutOfRange
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
        assert_eq!(info_flags & InfoField::FLAGS_CONS_DIR, 0, "cons_dir must be cleared");
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
        assert_ne!(info0.as_ref()[0] & InfoField::FLAGS_CONS_DIR, 0, "info0 cons_dir=true");
        assert_eq!(info1.timestamp().timestamp(), 1);
        assert_eq!(info1.as_ref()[0] & InfoField::FLAGS_CONS_DIR, 0, "info1 cons_dir=false");
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
        assert_eq!(hop1_flags & FlyoverHopField::FLYOVER_BIT, 0, "flyover bit must be cleared");
    }

    #[test]
    fn to_reversed_flyover_preserves_common_fields() {
        // The converted flyover hop must preserve exp_time, cons_ingress, cons_egress.
        let rev = decode(flyover_path()).to_reversed();
        let raw = rev.raw();
        let base = MetaHeader::LENGTH + 8 + StandardHopField::ENCODED_SIZE;
        assert_eq!(raw[base + 1], 0x05, "exp_time preserved");
        assert_eq!(&raw[base + 2..base + 4], &[0x00, 0x0A], "cons_ingress preserved");
        assert_eq!(&raw[base + 4..base + 6], &[0x00, 0x0B], "cons_egress preserved");
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
}
