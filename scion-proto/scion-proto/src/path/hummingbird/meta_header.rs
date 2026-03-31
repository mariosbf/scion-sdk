//! A Hummingbird path meta header.

use std::{mem, ops::Add, time::Duration};

use bytes::{Buf, BufMut};

use crate::{
    packet::{DecodeError, InadequateBufferSize},
    path::DataPlanePathErrorKind,
    wire_encoding::{self, WireDecode, WireEncode},
};

wire_encoding::bounded_uint! {
    /// A 2-bit index into the info fields.
    #[derive(Default)]
    pub struct HummingbirdInfoFieldIndex(u8 : 2);
}

wire_encoding::bounded_uint! {
    /// A 8-bit index into the hop fields.
    #[derive(Default)]
    pub struct HummingbirdHopfieldIndex(u8 : 8);
}

#[derive(Default, Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
/// A 7-bit encoding of the number of hop fields in a Hummingbird path segment.
/// Note that the length of the segment is encoded by the number of bytes in the
/// segment divided by 4.
pub struct HummingbirdSegmentLength(u8);

impl HummingbirdSegmentLength {
    /// The number of bits useable for an instance of this type.
    pub const BITS: u32 = 7;

    /// The maximum possible value for an instance of this type.
    pub const MAX: Self = Self((1 << 7) - 1);

    /// Create a new instance if the value is at most `Self::MAX.value()`.
    /// The `length` parameter is the number of bytes in the segment.
    pub const fn new(segment_length: u16) -> Option<Self> {
        if segment_length <= (Self::MAX.0 as u16) * 4 {
            Some(Self((segment_length / 4) as u8))
        } else {
            None
        }
    }

    /// Create a new instance with the provided value.
    /// The value is assumed to already be the encoding of the segment length,
    /// i.e., the number of bytes in the segment divided by 4.
    ///
    /// # Safety
    ///
    /// The value should be at most `Self::MAX.value()`.
    pub const fn new_unchecked(value: u8) -> Self {
        debug_assert!(value <= Self::MAX.0);
        Self(value)
    }

    /// Create a new instance from the number of bytes in the segment, without
    /// checking that the value is at most `Self::MAX.value()`.
    /// The value is calculated as the number of bytes in the segment divided by 4.
    ///
    /// # Safety
    /// The `segment_length` should be at most `Self::MAX.value() * 4`.
    pub const fn from_u16_unchecked(segment_length: u16) -> Self {
        debug_assert!(segment_length <= (Self::MAX.0 as u16) * 4);
        Self((segment_length / 4) as u8)
    }

    /// Get the value of this instance as its underlying type.
    #[inline]
    pub const fn get(&self) -> u8 {
        self.0
    }
}

impl From<u8> for HummingbirdSegmentLength {
    fn from(value: u8) -> Self {
        Self::new_unchecked(value)
    }
}

impl TryFrom<u16> for HummingbirdSegmentLength {
    type Error = &'static str;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value).ok_or("segment length exceeds maximum encodable length")
    }
}

impl HummingbirdSegmentLength {
    /// Gets the indicated length of the Hummingbird segment as a usize.
    pub const fn length(&self) -> usize {
        self.0 as usize * 4
    }
}

wire_encoding::bounded_uint! {
    /// A unix timestamp (1-second granularity) that is used as a base to
    /// calculate start times for flyovers and the high granularity
    /// [`HummingbirdMillisTimestamp`].
    #[derive(Default)]
    pub struct HummingbirdBaseTimestamp(u32 : 32);
}

impl From<std::time::SystemTime> for HummingbirdBaseTimestamp {
    /// Creates a new HummingbirdBaseTimestamp from the given SystemTime by
    /// calculating the duration since the UNIX epoch and using its seconds as
    /// the timestamp value.
    ///
    /// Does not check for overflows.
    ///
    /// # Panics
    /// Panics if the provided SystemTime is before the UNIX epoch.
    fn from(system_time: std::time::SystemTime) -> Self {
        let duration_since_epoch = system_time
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before unix epoch");
        Self(duration_since_epoch.as_secs() as u32)
    }
}

impl Add<Duration> for HummingbirdBaseTimestamp {
    type Output = Self;

    /// Adds the given duration to this timestamp, returning a new timestamp.
    /// The addition is performed by adding the duration in seconds to the
    /// timestamp's value, and does not check for overflow.
    fn add(self, rhs: Duration) -> Self::Output {
        let total_seconds = self.0 as u64 + rhs.as_secs();
        Self(total_seconds as u32)
    }
}

wire_encoding::bounded_uint! {
    /// A millisecond granularity timestamp as offset from
    /// [`HummingbirdBaseTimestamp`].
    #[derive(Default)]
    pub struct HummingbirdMillisTimestamp(u16 : 10);
}

impl From<Duration> for HummingbirdMillisTimestamp {
    /// Creates a new HummingbirdMillisTimestamp from the given Duration by
    /// calculating the total duration in milliseconds and using that as the
    /// timestamp value.
    ///
    /// Does not check for overflows.
    fn from(duration: Duration) -> Self {
        let total_millis = duration.as_millis() as u64;
        Self(total_millis as u16)
    }
}

wire_encoding::bounded_uint! {
    /// An 8-bit counter for each packet that is sent by the source to ensure that
    /// the tuple consisting of ([`HummingbirdBaseTimestamp`],
    /// [`HummingbirdMillisTimestamp`], [`HummingbirdCounter`]) is unique
    /// for each packet.
    /// Used for the (optional) duplicate suppression.
    #[derive(Default)]
    pub struct HummingbirdCounter(u32 : 26);
}

wire_encoding::bounded_uint! {
    /// A 1-bit reserved field within the [`HummingbirdMetaHeader`].
    #[derive(Default)]
    pub struct HummingbirdMetaReserved(u8 : 1);
}

/// Meta information about the Hummingbird SCION path contained in a
/// [`HummingbirdPath`].
///
/// Note: Some of the functionality availalble in [MetaHeader] is not implemented
/// for HummingbirdMetaHeader. This is primarily because the Hummingbird path
/// encoding diffuses the relationship between segment length and number of hop
/// fields.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HummingbirdMetaHeader {
    /// An index to the current info field for the packet on its way through the
    /// network.
    ///
    /// This must be smaller than [`Self::info_fields_count`].
    pub current_info_field: HummingbirdInfoFieldIndex,

    /// An index to the current (flyover) hop field within the segment pointed to
    /// by the info field.
    ///
    /// For valid SCION packets, this should point at a hop field associated with
    /// the current info field.
    ///
    /// This must be smaller than [`Self::hop_fields_count`].
    pub current_hop_field: HummingbirdHopfieldIndex,

    /// Unused bits in the Hummingbird path meta header.
    pub reserved: HummingbirdMetaReserved,

    /// The length of each of the segments in bytes.
    ///
    /// Note: In a regular SCION meta header, the segment length fields are  
    /// the number of hop fields in the segment. In contrast, in the Hummingbird 
    /// meta header, the segment length fields are the number of bytes in the 
    /// segment divided by 4.
    ///
    ///
    /// For valid SCION packets, the SegmentLengths at indices 1 and 2 should be
    /// non-zero only if all the preceding SegmentLengths are non-zero.
    pub segment_lengths: [HummingbirdSegmentLength; 3],

    /// The base timestamp for the path, used for calculating flyover start times.
    pub base_timestamp: HummingbirdBaseTimestamp,

    /// The millisecond offset from the base timestamp, used for calculating
    /// flyover start times.
    pub millis_timestamp: HummingbirdMillisTimestamp,

    /// A counter to ensure uniqueness of the timestamp tuple for (optional)
    /// duplicate suppression.
    pub counter: HummingbirdCounter,
}

impl HummingbirdMetaHeader {
    /// The length of a Hummingbird path meta header in bytes.
    pub const LENGTH: usize = 12;
    /// The length of an info field in bytes (same as for regular SCION paths).
    pub const INFO_FIELD_LENGTH: usize = 8;
    /// The length of a hop field in bytes.
    pub const HOP_FIELD_LENGTH: usize = 12;
    /// The length of a flyover hop field in bytes.
    pub const FLYOVER_HOP_FIELD_LENGTH: usize = 20;

    /// The number of info fields.
    pub const fn info_fields_count(&self) -> usize {
        match &self.segment_lengths {
            [HummingbirdSegmentLength(0), ..] => 0,
            [_, HummingbirdSegmentLength(0), _] => 1,
            [.., HummingbirdSegmentLength(0)] => 2,
            _ => 3,
        }
    }

    /// Returns the index of the current info field.
    pub fn info_field_index(&self) -> usize {
        self.current_info_field.get().into()
    }

    /// Returns the index of the current hop field.
    pub fn hop_field_index(&self) -> usize {
        self.current_hop_field.get().into()
    }

    /// Returns the base timestamp.
    pub fn base_timestamp(&self) -> u32 {
        self.base_timestamp.0
    }

    /// Returns the base timestamp as a SystemTime.
    pub fn base_timestamp_as_system_time(&self) -> std::time::SystemTime {
        std::time::UNIX_EPOCH + Duration::from_secs(self.base_timestamp.get() as u64)
    }

    /// Returns the millisecond timestamp.
    pub fn millis_timestamp(&self) -> u16 {
        self.millis_timestamp.0
    }

    /// Returns the counter value.
    pub fn counter(&self) -> u32 {
        self.counter.0
    }

    /// Returns the complete timestamp (base timestamp + millisecond offset).
    pub fn timestamp(&self) -> std::time::SystemTime {
        self.base_timestamp_as_system_time()
            + Duration::from_millis(self.millis_timestamp.get() as u64)
    }

    /// Returns index of segment that contains the current hop field.
    ///
    /// If hop is out of range, this returns None.
    pub fn segment_index(&self) -> Option<usize> {
        let hop_index = self.hop_field_index();
        let seg0 = self.segment_lengths[0].length();
        let seg1 = self.segment_lengths[1].length();
        let seg2 = self.segment_lengths[2].length();

        if hop_index < seg0 {
            Some(0)
        } else if hop_index < seg0 + seg1 {
            Some(1)
        } else if hop_index < seg0 + seg1 + seg2 {
            Some(2)
        } else {
            // Hop index is out of range
            None
        }
    }

    /// The length of the corresponding encoded path in bytes.
    pub(super) fn encoded_path_length(&self) -> usize {
        Self::LENGTH
            + self.info_fields_count() * Self::INFO_FIELD_LENGTH
            + self.segment_lengths
                .iter()
                .map(|seg_len| seg_len.length())
                .sum::<usize>()
    }

    /// Returns the offset in bytes of the given info field.
    pub fn info_field_offset(info_field_index: usize) -> usize {
        Self::LENGTH + Self::INFO_FIELD_LENGTH * info_field_index
    }
}

impl WireEncode for HummingbirdMetaHeader {
    type Error = InadequateBufferSize;

    #[inline]
    fn encoded_length(&self) -> usize {
        Self::LENGTH
    }

    #[inline]
    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        let fields1: u32 = (self.current_info_field.get() as u32)
            | ((self.current_hop_field.get() as u32) << 2)
            | ((self.reserved.get() as u32) << 10)
            | ((self.segment_lengths[0].get() as u32) << 11)
            | ((self.segment_lengths[1].get() as u32) << 18)
            | ((self.segment_lengths[2].get() as u32) << 25);
        let fields2: u32 = self.base_timestamp.get();
        let fields3: u32 = (self.millis_timestamp.get() as u32) | (self.counter.get() << 10);
        buffer.put_u32(fields1);
        buffer.put_u32(fields2);
        buffer.put_u32(fields3);
    }
}

impl<T: Buf> WireDecode<T> for HummingbirdMetaHeader {
    type Error = DecodeError;

    fn decode(data: &mut T) -> Result<Self, Self::Error> {
        if data.remaining() < mem::size_of::<u32>() {
            return Err(Self::Error::PacketEmptyOrTruncated);
        }
        let fields1 = data.get_u32();
        let fields2 = data.get_u32();
        let fields3 = data.get_u32();

        let meta = Self {
            current_info_field: HummingbirdInfoFieldIndex(field::<0, 2>(fields1) as u8),
            current_hop_field: HummingbirdHopfieldIndex(field::<2, 10>(fields1) as u8),
            reserved: HummingbirdMetaReserved(field::<10, 11>(fields1) as u8),
            segment_lengths: [
                HummingbirdSegmentLength(field::<11, 18>(fields1) as u8),
                HummingbirdSegmentLength(field::<18, 25>(fields1) as u8),
                HummingbirdSegmentLength(field::<25, 32>(fields1) as u8),
            ],
            base_timestamp: HummingbirdBaseTimestamp(fields2),
            millis_timestamp: HummingbirdMillisTimestamp(field::<0, 10>(fields3) as u16),
            counter: HummingbirdCounter(field::<10, 32>(fields3)),
        };

        if meta.segment_lengths[2].get() > 0 && meta.segment_lengths[1].get() == 0
            || meta.segment_lengths[1].get() > 0 && meta.segment_lengths[0].get() == 0
            || meta.segment_lengths[0].get() == 0
        {
            return Err(DataPlanePathErrorKind::InvalidSegmentLengths.into());
        }

        if meta.info_field_index() >= meta.info_fields_count() {
            return Err(DataPlanePathErrorKind::InfoFieldOutOfRange.into());
        }
        // Above errs also when info_fields_index() is 4, since info_fields_count() is at most 3
        debug_assert!(meta.info_field_index() <= 3);

        let fallback_seg_index = 255; // Will never match and thus always return OutOfRange

        // Sanity check: check that the hop field index is reasonable.
        // We cannot compute the exact number of hop fields from the meta header,
        // but we can compute an upper bound.
        let segment_lengths_sum: usize = meta
            .segment_lengths
            .iter()
            .map(|seg_len| seg_len.length())
            .sum();
        let max_hop_fields = (segment_lengths_sum - HummingbirdMetaHeader::LENGTH)
            / HummingbirdMetaHeader::HOP_FIELD_LENGTH;

        if meta.hop_field_index() >= max_hop_fields
            || meta.segment_index().unwrap_or(fallback_seg_index) != meta.info_field_index()
        {
            return Err(DataPlanePathErrorKind::HopFieldOutOfRange.into());
        }

        Ok(meta)
    }
}

/// Return the sequence of bits from `fields` from `START` (inclusive) to `END`
/// (exclusive).
#[inline]
const fn field<const START: usize, const END: usize>(fields: u32) -> u32 {
    let mask: u32 = (1 << (END - START)) - 1;
    (fields >> START) & mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    /// Build a 12-byte wire representation from three big-endian u32 words.
    fn encode_fields(fields1: u32, fields2: u32, fields3: u32) -> [u8; 12] {
        let mut data = [0u8; 12];
        data[0..4].copy_from_slice(&fields1.to_be_bytes());
        data[4..8].copy_from_slice(&fields2.to_be_bytes());
        data[8..12].copy_from_slice(&fields3.to_be_bytes());
        data
    }

    /// Encode the fields1 word from its component parts.
    fn fields1(info: u8, hop: u8, seg0: u8, seg1: u8, seg2: u8) -> u32 {
        (info as u32)
            | ((hop as u32) << 2)
            | ((seg0 as u32) << 11)
            | ((seg1 as u32) << 18)
            | ((seg2 as u32) << 25)
    }

    // ---------------------------------------------------------------------------
    // HummingbirdSegmentLength
    // ---------------------------------------------------------------------------

    #[test]
    fn segment_length_new_valid() {
        assert_eq!(
            HummingbirdSegmentLength::new(12),
            Some(HummingbirdSegmentLength::new_unchecked(3))
        );
    }

    #[test]
    fn segment_length_new_zero() {
        assert_eq!(
            HummingbirdSegmentLength::new(0),
            Some(HummingbirdSegmentLength::new_unchecked(0))
        );
    }

    #[test]
    fn segment_length_new_max() {
        let max_bytes = (HummingbirdSegmentLength::MAX.get() as u16) * 4;
        assert!(HummingbirdSegmentLength::new(max_bytes).is_some());
    }

    #[test]
    fn segment_length_new_too_large() {
        let over_max = (HummingbirdSegmentLength::MAX.get() as u16) * 4 + 4;
        assert_eq!(HummingbirdSegmentLength::new(over_max), None);
    }

    #[test]
    fn segment_length_length() {
        assert_eq!(HummingbirdSegmentLength::new_unchecked(6).length(), 24);
        assert_eq!(HummingbirdSegmentLength::new_unchecked(0).length(), 0);
        assert_eq!(HummingbirdSegmentLength::new_unchecked(1).length(), 4);
    }

    #[test]
    fn segment_length_try_from_u16_valid() {
        assert_eq!(
            HummingbirdSegmentLength::try_from(8_u16),
            Ok(HummingbirdSegmentLength::new_unchecked(2))
        );
    }

    #[test]
    fn segment_length_try_from_u16_too_large() {
        let over_max = (HummingbirdSegmentLength::MAX.get() as u16) * 4 + 4;
        assert!(HummingbirdSegmentLength::try_from(over_max).is_err());
    }

    #[test]
    fn segment_length_from_u8() {
        let s = HummingbirdSegmentLength::from(5_u8);
        assert_eq!(s.get(), 5);
    }

    // ---------------------------------------------------------------------------
    // HummingbirdBaseTimestamp
    // ---------------------------------------------------------------------------

    #[test]
    fn base_timestamp_from_system_time() {
        let system_time = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let ts = HummingbirdBaseTimestamp::from(system_time);
        assert_eq!(ts.get(), 1_000_000);
    }

    #[test]
    fn base_timestamp_add_duration() {
        let ts = HummingbirdBaseTimestamp(1_000);
        let result = ts + Duration::from_secs(500);
        assert_eq!(result.get(), 1_500);
    }

    // ---------------------------------------------------------------------------
    // HummingbirdMillisTimestamp
    // ---------------------------------------------------------------------------

    #[test]
    fn millis_timestamp_from_duration() {
        let ts = HummingbirdMillisTimestamp::from(Duration::from_millis(500));
        assert_eq!(ts.get(), 500);
    }

    // ---------------------------------------------------------------------------
    // HummingbirdMetaHeader — methods
    // ---------------------------------------------------------------------------

    #[test]
    fn info_fields_count_zero() {
        let header = HummingbirdMetaHeader {
            segment_lengths: [
                HummingbirdSegmentLength::new_unchecked(0),
                HummingbirdSegmentLength::new_unchecked(0),
                HummingbirdSegmentLength::new_unchecked(0),
            ],
            ..Default::default()
        };
        assert_eq!(header.info_fields_count(), 0);
    }

    #[test]
    fn info_fields_count_one() {
        let header = HummingbirdMetaHeader {
            segment_lengths: [
                HummingbirdSegmentLength::new_unchecked(3),
                HummingbirdSegmentLength::new_unchecked(0),
                HummingbirdSegmentLength::new_unchecked(0),
            ],
            ..Default::default()
        };
        assert_eq!(header.info_fields_count(), 1);
    }

    #[test]
    fn info_fields_count_two() {
        let header = HummingbirdMetaHeader {
            segment_lengths: [
                HummingbirdSegmentLength::new_unchecked(3),
                HummingbirdSegmentLength::new_unchecked(3),
                HummingbirdSegmentLength::new_unchecked(0),
            ],
            ..Default::default()
        };
        assert_eq!(header.info_fields_count(), 2);
    }

    #[test]
    fn info_fields_count_three() {
        let header = HummingbirdMetaHeader {
            segment_lengths: [
                HummingbirdSegmentLength::new_unchecked(3),
                HummingbirdSegmentLength::new_unchecked(3),
                HummingbirdSegmentLength::new_unchecked(3),
            ],
            ..Default::default()
        };
        assert_eq!(header.info_fields_count(), 3);
    }

    #[test]
    fn segment_index_in_seg0() {
        // segment_lengths[i].length() = get() * 4; each segment covers 12 bytes.
        let header = HummingbirdMetaHeader {
            segment_lengths: [
                HummingbirdSegmentLength::new_unchecked(3), // length = 12
                HummingbirdSegmentLength::new_unchecked(3),
                HummingbirdSegmentLength::new_unchecked(3),
            ],
            current_hop_field: HummingbirdHopfieldIndex(5),
            ..Default::default()
        };
        assert_eq!(header.segment_index(), Some(0));
    }

    #[test]
    fn segment_index_in_seg1() {
        let header = HummingbirdMetaHeader {
            segment_lengths: [
                HummingbirdSegmentLength::new_unchecked(3), // length = 12
                HummingbirdSegmentLength::new_unchecked(3),
                HummingbirdSegmentLength::new_unchecked(3),
            ],
            current_hop_field: HummingbirdHopfieldIndex(12),
            ..Default::default()
        };
        assert_eq!(header.segment_index(), Some(1));
    }

    #[test]
    fn segment_index_in_seg2() {
        let header = HummingbirdMetaHeader {
            segment_lengths: [
                HummingbirdSegmentLength::new_unchecked(3), // length = 12
                HummingbirdSegmentLength::new_unchecked(3),
                HummingbirdSegmentLength::new_unchecked(3),
            ],
            current_hop_field: HummingbirdHopfieldIndex(24),
            ..Default::default()
        };
        assert_eq!(header.segment_index(), Some(2));
    }

    #[test]
    fn segment_index_out_of_range() {
        let header = HummingbirdMetaHeader {
            segment_lengths: [
                HummingbirdSegmentLength::new_unchecked(3), // length = 12
                HummingbirdSegmentLength::new_unchecked(3),
                HummingbirdSegmentLength::new_unchecked(3),
            ],
            current_hop_field: HummingbirdHopfieldIndex(36),
            ..Default::default()
        };
        assert_eq!(header.segment_index(), None);
    }

    #[test]
    fn info_field_offset() {
        assert_eq!(HummingbirdMetaHeader::info_field_offset(0), 12);
        assert_eq!(HummingbirdMetaHeader::info_field_offset(1), 20);
        assert_eq!(HummingbirdMetaHeader::info_field_offset(2), 28);
    }

    #[test]
    fn timestamp_combines_base_and_millis() {
        let header = HummingbirdMetaHeader {
            base_timestamp: HummingbirdBaseTimestamp(1_000_000),
            millis_timestamp: HummingbirdMillisTimestamp(500),
            ..Default::default()
        };
        let expected = UNIX_EPOCH + Duration::from_secs(1_000_000) + Duration::from_millis(500);
        assert_eq!(header.timestamp(), expected);
    }

    // ---------------------------------------------------------------------------
    // WireDecode — valid
    // ---------------------------------------------------------------------------

    #[test]
    fn decode_single_segment_minimal() {
        // seg_len[0]=6 → length=24, max_hop_fields=(24-12)/12=1, hop=0 valid.
        let data = encode_fields(fields1(0, 0, 6, 0, 0), 0, 0);
        let header = HummingbirdMetaHeader::decode(&mut data.as_slice()).expect("valid decode");

        assert_eq!(header.current_info_field, HummingbirdInfoFieldIndex(0));
        assert_eq!(header.current_hop_field, HummingbirdHopfieldIndex(0));
        assert_eq!(
            header.segment_lengths[0],
            HummingbirdSegmentLength::new_unchecked(6)
        );
        assert_eq!(
            header.segment_lengths[1],
            HummingbirdSegmentLength::new_unchecked(0)
        );
        assert_eq!(
            header.segment_lengths[2],
            HummingbirdSegmentLength::new_unchecked(0)
        );
        assert_eq!(header.base_timestamp, HummingbirdBaseTimestamp(0));
        assert_eq!(header.millis_timestamp, HummingbirdMillisTimestamp(0));
        assert_eq!(header.counter, HummingbirdCounter(0));
    }

    #[test]
    fn decode_with_nonzero_timestamps_and_counter() {
        // seg_len[0]=12 → length=48, max_hop_fields=3, hop=2 valid.
        let f3 = 500_u32 | (1234_u32 << 10); // millis=500, counter=1234
        let data = encode_fields(fields1(0, 2, 12, 0, 0), 1_000_000, f3);
        let header = HummingbirdMetaHeader::decode(&mut data.as_slice()).expect("valid decode");

        assert_eq!(header.current_hop_field, HummingbirdHopfieldIndex(2));
        assert_eq!(
            header.segment_lengths[0],
            HummingbirdSegmentLength::new_unchecked(12)
        );
        assert_eq!(header.base_timestamp, HummingbirdBaseTimestamp(1_000_000));
        assert_eq!(header.millis_timestamp, HummingbirdMillisTimestamp(500));
        assert_eq!(header.counter, HummingbirdCounter(1234));
    }

    // ---------------------------------------------------------------------------
    // WireDecode — error cases
    // ---------------------------------------------------------------------------

    #[test]
    fn decode_truncated() {
        let data = [0u8; 3];
        assert_eq!(
            HummingbirdMetaHeader::decode(&mut data.as_slice()),
            Err(DecodeError::PacketEmptyOrTruncated)
        );
    }

    #[test]
    fn decode_invalid_seg0_zero() {
        // seg_len[0]=0 is always rejected.
        let data = encode_fields(fields1(0, 0, 0, 0, 0), 0, 0);
        assert_eq!(
            HummingbirdMetaHeader::decode(&mut data.as_slice()),
            Err(DecodeError::InvalidPath(
                DataPlanePathErrorKind::InvalidSegmentLengths
            ))
        );
    }

    #[test]
    fn decode_invalid_seg1_nonzero_seg0_zero() {
        // seg_len[0]=0 with seg_len[1]>0 is also rejected.
        let data = encode_fields(fields1(0, 0, 0, 6, 0), 0, 0);
        assert_eq!(
            HummingbirdMetaHeader::decode(&mut data.as_slice()),
            Err(DecodeError::InvalidPath(
                DataPlanePathErrorKind::InvalidSegmentLengths
            ))
        );
    }

    #[test]
    fn decode_invalid_seg2_nonzero_seg1_zero() {
        // seg_len[0]=6, seg_len[1]=0, seg_len[2]=6 is rejected.
        let data = encode_fields(fields1(0, 0, 6, 0, 6), 0, 0);
        assert_eq!(
            HummingbirdMetaHeader::decode(&mut data.as_slice()),
            Err(DecodeError::InvalidPath(
                DataPlanePathErrorKind::InvalidSegmentLengths
            ))
        );
    }

    #[test]
    fn decode_info_field_out_of_range() {
        // 1 segment → info_fields_count=1, info_field_index=1 is out of range.
        let data = encode_fields(fields1(1, 0, 6, 0, 0), 0, 0);
        assert_eq!(
            HummingbirdMetaHeader::decode(&mut data.as_slice()),
            Err(DecodeError::InvalidPath(
                DataPlanePathErrorKind::InfoFieldOutOfRange
            ))
        );
    }

    #[test]
    fn decode_hop_field_out_of_range() {
        // seg_len[0]=6 → max_hop_fields=1; hop=1 is out of range.
        let data = encode_fields(fields1(0, 1, 6, 0, 0), 0, 0);
        assert_eq!(
            HummingbirdMetaHeader::decode(&mut data.as_slice()),
            Err(DecodeError::InvalidPath(
                DataPlanePathErrorKind::HopFieldOutOfRange
            ))
        );
    }

    // ---------------------------------------------------------------------------
    // WireEncode + WireDecode roundtrip
    // ---------------------------------------------------------------------------

    #[test]
    fn encode_decode_roundtrip() {
        let original = HummingbirdMetaHeader {
            current_info_field: HummingbirdInfoFieldIndex(0),
            current_hop_field: HummingbirdHopfieldIndex(2),
            reserved: HummingbirdMetaReserved(0),
            segment_lengths: [
                HummingbirdSegmentLength::new_unchecked(12), // length=48, max_hop_fields=3
                HummingbirdSegmentLength::new_unchecked(0),
                HummingbirdSegmentLength::new_unchecked(0),
            ],
            base_timestamp: HummingbirdBaseTimestamp(1_000_000),
            millis_timestamp: HummingbirdMillisTimestamp(500),
            counter: HummingbirdCounter(1234),
        };

        let mut buf = Vec::new();
        original.encode_to_unchecked(&mut buf);
        assert_eq!(buf.len(), HummingbirdMetaHeader::LENGTH);

        let decoded = HummingbirdMetaHeader::decode(&mut buf.as_slice())
            .expect("roundtrip decode must succeed");
        assert_eq!(decoded, original);
    }
}
