use std::ops::Deref;

use bytes::{Buf, Bytes, BytesMut};
use chrono::{DateTime, Utc};

use crate::{
    packet::DecodeError,
    path::{
        EncodedHopField, EncodedInfoField, EncodedSegment, EncodedSegments,
        EncodedStandardHopField, InfoFields,
        hummingbird::{
            EncodedFlyoverHopField, HummingbirdHopFields, HummingbirdMetaHeader,
        },
    },
    wire_encoding::WireDecode,
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
    use crate::{
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
        let path =
            EncodedHummingbirdPath::decode(&mut one_segment_path()).expect("valid decode");
        let meta = path.meta_header();
        assert_eq!(meta.segment_lengths[0].get(), 6);
        assert_eq!(meta.segment_lengths[1].get(), 0);
        assert_eq!(meta.segment_lengths[2].get(), 0);
        assert_eq!(meta.base_timestamp.get(), 0x1A2B3C4D);
    }

    #[test]
    fn decode_two_segments() {
        let path =
            EncodedHummingbirdPath::decode(&mut two_segment_path()).expect("valid decode");
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
        let path = EncodedHummingbirdPath::decode(&mut two_segment_path()).unwrap
        ();
        let hops: Vec<(u16, u16)> = path
            .hop_fields()
            .map(|h| {
                (
                    h.cons_ingress_interface().map(NonZeroU16::get).unwrap_or(0),
                    h.cons_egress_interface().map(NonZeroU16::get).unwrap_or(0),
                )
            })
            .collect();
        assert_eq!(
            hops,
            [
                (1, 2),
                (3, 4),
                (5, 6),
                (7, 8),
            ]
        );
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
}
