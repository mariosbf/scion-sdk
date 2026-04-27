//! SCION Hummingbird path models

use std::time::SystemTime;

use tinyvec::TinyVec;

use crate::{
    core::{
        encode::{InvalidStructureError, WireEncode},
        write::unchecked_bit_range_be_write,
    },
    path::{
        hbird::{
            layout::{FlyoverHopFieldLayout, HbirdPathDataLayout, HbirdPathMetaLayout},
            types::HbirdHopFieldFlags,
            view::{FlyoverHopFieldView, HbirdHopFieldView, HbirdPathView},
        },
        standard::{
            layout::InfoFieldLayout,
            model::{HopField, InfoField},
            types::{HopFieldMac, InfoFieldFlags, StdHopFieldFlags},
            view::HopFieldView,
        },
    },
};

/// Represents a Hummingbird SCION path
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HummingbirdPath {
    /// The current info field index
    pub current_info_field: u8,
    /// The current hop field index
    pub current_hop_field: u8,
    /// The segments of the path
    pub segments: Vec<HbirdSegment>,
    /// The base timestamp of the path.
    pub base_timestamp: u32,
    /// The millisecond timetamp of the path. This is a millisecond offset from
    /// the base timestamp. Note that this field is only 10-bits wide in the
    /// wire format, so the maximum value is 1023 milliseconds.
    pub millis_timestamp: u16,
    /// The counter value of the path. Note that this field is only 22-bits wide
    /// in the wire format, so the maximum value is 4,194,303.
    pub counter: u32,
}

impl HummingbirdPath {
    /// Constructs a `HumingbirdPath` from a `HummingbirdPathView`
    pub fn from_view(view: &HbirdPathView) -> Self {
        let info_fields = view.info_fields();
        let mut hop_fields = view.hop_fields();
        let segment_sizes = [
            view.seg0_len() as u16 * 4,
            view.seg1_len() as u16 * 4,
            view.seg2_len() as u16 * 4,
        ];

        let mut segments = Vec::with_capacity(info_fields.len());

        for (info_field, segment_size) in info_fields.iter().zip(segment_sizes.iter()) {
            let mut hop_fields_in_segment = TinyVec::new();

            let mut hop_field_bytes_taken = 0;
            while hop_field_bytes_taken < *segment_size {
                let hop_field_view = hop_fields.next();
                if hop_field_view.is_none() {
                    break;
                }

                let hop_field_view = hop_field_view.unwrap();
                hop_field_bytes_taken += hop_field_view.size_bytes() as u16;
                hop_fields_in_segment.push(HbirdHopField::from_view(hop_field_view));
            }

            let segment = HbirdSegment {
                info_field: InfoField::from_view(info_field),
                hop_fields: hop_fields_in_segment,
            };

            segments.push(segment);
        }

        HummingbirdPath {
            current_info_field: view.curr_info_field(),
            current_hop_field: view.curr_hop_field(),
            base_timestamp: view.base_timestamp(),
            millis_timestamp: view.millis_timestamp(),
            counter: view.counter(),
            segments,
        }
    }
}

// Utility
impl HummingbirdPath {
    /// Returns the total number of hop fields in the path
    pub fn hop_field_count(&self) -> usize {
        self.segments
            .iter()
            .map(|segment| segment.hop_fields.len())
            .sum()
    }

    /// Returns the total number of info fields in the path
    pub fn info_field_count(&self) -> usize {
        self.segments.len()
    }

    /// Returns the lengths of each segment in the path as a tuple
    /// The lengths of a segment is the number of hop fields in the segment here.
    pub fn segment_lengths(&self) -> (u8, u8, u8) {
        let seg0 = self.segments.first().map_or(0, |s| s.hop_fields.len()) as u8;
        let seg1 = self.segments.get(1).map_or(0, |s| s.hop_fields.len()) as u8;
        let seg2 = self.segments.get(2).map_or(0, |s| s.hop_fields.len()) as u8;
        (seg0, seg1, seg2)
    }

    /// Returns the lengths of each segment in the path as a tuple
    /// The lengths of a segment is the number of hop fields in the segment here.
    pub fn segment_lengths_bytes(&self) -> (usize, usize, usize) {
        let seg0 = self.segments.first().map_or(0, |s| {
            s.hop_fields
                .iter()
                .map(|hf| hf.required_size())
                .sum::<usize>()
        });
        let seg1 = self.segments.get(1).map_or(0, |s| {
            s.hop_fields
                .iter()
                .map(|hf| hf.required_size())
                .sum::<usize>()
        });
        let seg2 = self.segments.get(2).map_or(0, |s| {
            s.hop_fields
                .iter()
                .map(|hf| hf.required_size())
                .sum::<usize>()
        });
        (seg0, seg1, seg2)
    }

    /// Returns an iterator over all hop fields in the path
    pub fn iter_hop_fields(&self) -> impl Iterator<Item = &HbirdHopField> {
        self.segments
            .iter()
            .flat_map(|segment| segment.hop_fields.iter())
    }

    /// Returns an iterator over all info fields in the path
    pub fn iter_info_fields(&self) -> impl Iterator<Item = &InfoField> {
        self.segments.iter().map(|segment| &segment.info_field)
    }

    /// Returns the timestamp of the path as a `SystemTime` object.
    /// The timestamp is calculated by adding the `base_timestamp` and
    /// `millis_timestamp` fields together.
    pub fn timestamp(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH
            + std::time::Duration::from_secs(self.base_timestamp as u64)
            + std::time::Duration::from_millis(self.millis_timestamp as u64)
    }
}

impl WireEncode for HummingbirdPath {
    fn required_size(&self) -> usize {
        HbirdPathMetaLayout::SIZE_BYTES
            + self
                .iter_hop_fields()
                .map(|hf| hf.required_size())
                .sum::<usize>()
            + self
                .iter_info_fields()
                .map(|ifield| ifield.required_size())
                .sum::<usize>()
    }

    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        // curr_hop_field stores byte_offset / 4; verify it falls within the hop fields
        let total_hop_bytes: usize = self.iter_hop_fields().map(|hf| hf.required_size()).sum();
        if total_hop_bytes > 0 && self.current_hop_field as usize * 4 >= total_hop_bytes {
            return Err("curr_hop_field byte offset exceeds total hop field bytes".into());
        }

        // Current info field index
        if self.current_info_field != 0
            && self.current_info_field as usize >= self.info_field_count()
        {
            return Err("current_info_field exceeds total number of info fields".into());
        }

        // Validate millis timestamp
        if self.millis_timestamp > 1023 {
            return Err("millis_timestamp exceeds maximum value of 1023".into());
        }

        // Validate counter
        if self.counter > 4_194_303 {
            return Err("counter exceeds maximum value of 4,194,303".into());
        }

        // Validate segments
        if self.segments.is_empty() {
            return Err("Hummingbird path must contain at least one segment".into());
        }

        for segment in &self.segments {
            let segment_bytes = segment
                .hop_fields
                .iter()
                .map(|hf| hf.required_size())
                .sum::<usize>();

            if segment_bytes > HbirdPathMetaLayout::MAX_SEGMENT_BYTES {
                return Err("Length of segment exceeds maximum allowed length".into());
            }

            if segment.hop_fields.is_empty() {
                return Err("Segment must contain at least one hop field".into());
            }

            // Validate info field
            segment.info_field.wire_valid()?;

            // Validate hop fields
            for hop_field in &segment.hop_fields {
                hop_field.wire_valid()?;
            }
        }

        Ok(())
    }

    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        use HbirdPathMetaLayout as HML;

        let segment_lengths = self
            .segments
            .iter()
            .map(|s| {
                s.hop_fields
                    .iter()
                    .map(|hf| hf.required_size() / 4)
                    .sum::<usize>() as u8
            })
            .collect::<Vec<_>>();

        let seg0 = *segment_lengths.first().unwrap_or(&0);
        let seg1 = *segment_lengths.get(1).unwrap_or(&0);
        let seg2 = *segment_lengths.get(2).unwrap_or(&0);

        // Encode standard path meta information
        unsafe {
            unchecked_bit_range_be_write(buf, HML::CURR_INFO_FIELD_RNG, self.current_info_field);
            unchecked_bit_range_be_write(buf, HML::CURR_HOP_FIELD_RNG, self.current_hop_field);
            unchecked_bit_range_be_write(buf, HML::SEG0_LEN_RNG, seg0);
            unchecked_bit_range_be_write(buf, HML::SEG1_LEN_RNG, seg1);
            unchecked_bit_range_be_write(buf, HML::SEG2_LEN_RNG, seg2);
            unchecked_bit_range_be_write(buf, HML::BASE_TIMESTAMP_RNG, self.base_timestamp);
            unchecked_bit_range_be_write(buf, HML::MILLIS_TIMESTAMP_RNG, self.millis_timestamp);
            unchecked_bit_range_be_write(buf, HML::COUNTER_RNG, self.counter);
        }

        // Advance offset to path data
        let data_buf = unsafe { buf.get_unchecked_mut(HML::SIZE_BYTES..) };
        let data_layout =
            HbirdPathDataLayout::new(seg0 as usize * 4, seg1 as usize * 4, seg2 as usize * 4);

        // Encode standard path data
        // Encode info fields
        for (i, info_field) in self.iter_info_fields().enumerate() {
            let range = data_layout.info_field_range(i).aligned_byte_range();
            unsafe {
                let info_field_buf = data_buf.get_unchecked_mut(range);
                info_field.encode_unchecked(info_field_buf);
            }
        }

        // Encode hop fields
        let mut byte_offset = 0;
        for hop_field in self.iter_hop_fields() {
            let range = data_layout
                .hop_field_range(byte_offset, hop_field.is_flyover())
                .aligned_byte_range();
            byte_offset += hop_field.required_size();
            unsafe {
                let hop_field_buf = data_buf.get_unchecked_mut(range);
                hop_field.encode_unchecked(hop_field_buf);
            }
        }

        HML::SIZE_BYTES + self.info_field_count() * InfoFieldLayout::SIZE_BYTES + byte_offset
    }
}

/// Represents a segment in a standard SCION path
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HbirdSegment {
    /// Info field containing metadata about the segment
    pub info_field: InfoField,
    /// Hop fields representing the hops in the segment
    pub hop_fields: TinyVec<[HbirdHopField; 12]>,
}

impl Default for HbirdSegment {
    fn default() -> Self {
        HbirdSegment {
            info_field: InfoField {
                flags: InfoFieldFlags::empty(),
                segment_id: 0,
                timestamp: 0,
            },
            hop_fields: TinyVec::new(),
        }
    }
}

/// Represents a hop field in a Hummingbird SCION path
///
/// Hummingbird paths can contain both standard hop fields and flyover hop fields.
///
/// Hop fields contain information about individual hops in a SCION path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HbirdHopField {
    /// A standard hop field.
    Standard(HopField),
    /// A Hummingbird flyover hop field.
    Flyover(FlyoverHopField),
}

impl Default for HbirdHopField {
    fn default() -> Self {
        HbirdHopField::Standard(HopField::default())
    }
}

impl HbirdHopField {
    /// Constructs a `HbirdHopField` from a `HbirdHopFieldView`
    pub fn from_view(view: HbirdHopFieldView<&HopFieldView, &FlyoverHopFieldView>) -> Self {
        match view {
            HbirdHopFieldView::Standard(v) => Self::from_standard_view(v),
            HbirdHopFieldView::Flyover(v) => Self::from_flyover_view(v),
        }
    }

    /// Constructs a `HbirdHopField` from a `FlyoverHopFieldView`
    pub fn from_flyover_view(view: &FlyoverHopFieldView) -> Self {
        HbirdHopField::Flyover(FlyoverHopField::from_view(view))
    }

    /// Constructs a `HbirdHopField` from a `HopFieldView`
    pub fn from_standard_view(view: &HopFieldView) -> Self {
        HbirdHopField::Standard(HopField::from_view(view))
    }

    /// Returns true if the hop field is a flyover hop field, false if it is a standard hop field
    pub fn is_flyover(&self) -> bool {
        matches!(self, HbirdHopField::Flyover(_))
    }
}

impl WireEncode for HbirdHopField {
    fn required_size(&self) -> usize {
        match self {
            HbirdHopField::Standard(hf) => hf.required_size(),
            HbirdHopField::Flyover(fhf) => fhf.required_size(),
        }
    }

    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        // All values are full range, so always valid
        Ok(())
    }

    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        unsafe {
            match self {
                HbirdHopField::Standard(hf) => hf.encode_unchecked(buf),
                HbirdHopField::Flyover(fhf) => fhf.encode_unchecked(buf),
            }
        }
    }
}

/// Represents a hop field in a standard SCION path
///
/// Hop fields contain information about individual hops in a SCION path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlyoverHopField {
    /// Hop field flags
    pub flags: StdHopFieldFlags,
    /// Hop field expiration units
    ///
    /// The expiration time of a hop field is determined by multiplying the value in this field
    /// by [`EXP_TIME_UNIT`](super::types::EXP_TIME_UNIT)
    ///
    /// After this duration has passed since the segment creation time (found in the info
    /// field), the hop field is considered expired and may not be used for forwarding.
    pub expiration_units: u8,
    /// Hop field construction ingress interface
    ///
    /// A value of 0 indicates that the hop is at the start of the path segment.
    /// The interface number corresponds to the ingress interface used when constructing the
    /// path.
    ///
    /// The construction always starts at a Core router and proceeds towards the Child.
    ///
    /// When traversing the path in the reverse direction from construction (e.g. in a UP
    /// segment to a Core router), this field indicates the egress interface instead.
    pub cons_ingress: u16,
    /// Hop field construction egress interface
    ///
    /// A value of 0 indicates that the hop is at the end of the path segment.
    /// The interface number corresponds to the egress interface used when constructing the
    /// path.
    ///
    /// The construction always starts at a Core router and proceeds towards the Child.
    ///
    /// When traversing the path in the reverse direction from construction (e.g. in a UP
    /// segment to a Core router), this field indicates the ingress interface instead.
    pub cons_egress: u16,
    /// Hop field message authentication code (MAC).
    ///
    /// This is an aggregated MAC field calculated by XORing the standard hop
    /// field MAC with the flyover MAC.
    ///
    /// The MAC is used to ensure the integrity and authenticity of the hop field.
    /// It is computed when a segment is created and verified at each hop.
    /// It is also used to check that the flyover hop field is using a valid
    /// reservation.
    pub mac: HopFieldMac,
    /// ID of the Hummingbird reservation being used.
    ///
    /// The reservation ID is 22 bits long, i.e., the 10 most significant bits of
    /// the reservation ID are masked out when encoding.
    pub res_id: u32,
    /// Bandwidth of the Hummingbird reservation being used.
    ///
    /// The bandwidth is a 10-bit value (6 most significant bits of the u16 are unused).
    /// The 5 most significant bits of the 10-bit value are the `significand` and the
    /// remaining 5 bits are the `exponent`.
    /// The bandwidth of the reservation is then
    /// - `significand` if `exponent = 0`, and
    /// - `(32 + significand) << (exponent - 1)` otherwise.
    pub bw: u16,
    /// Reservation start offset. The offset between the `BaseTimestamp` in the
    /// path meta header and the start of the reservation (in seconds).
    pub res_start_offset: u16,
    /// Duration of the reservation, i.e., the difference between the timestamps
    /// of the start and expiration time of the reservation.
    pub res_duration: u16,
}

impl FlyoverHopField {
    /// Constructs a `FlyoverHopField` from a `FlyoverHopFieldView`
    pub fn from_view(view: &FlyoverHopFieldView) -> Self {
        FlyoverHopField {
            flags: view.flags(),
            expiration_units: view.exp_time(),
            cons_ingress: view.cons_ingress(),
            cons_egress: view.cons_egress(),
            mac: view.mac(),
            res_id: view.res_id(),
            bw: view.res_bw(),
            res_start_offset: view.res_start_offset(),
            res_duration: view.res_duration(),
        }
    }
}

impl WireEncode for FlyoverHopField {
    fn required_size(&self) -> usize {
        FlyoverHopFieldLayout::SIZE_BYTES
    }

    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        // All values are full range, so always valid
        Ok(())
    }

    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        unsafe {
            use FlyoverHopFieldLayout as FHFL;

            unchecked_bit_range_be_write(
                buf,
                FHFL::FLAGS_RNG,
                // Ensure flyover bit is set
                self.flags.bits() | HbirdHopFieldFlags::FLYOVER.bits(),
            );
            unchecked_bit_range_be_write(buf, FHFL::EXP_TIME_RNG, self.expiration_units);
            unchecked_bit_range_be_write(buf, FHFL::CONS_INGRESS_RNG, self.cons_ingress);
            unchecked_bit_range_be_write(buf, FHFL::CONS_EGRESS_RNG, self.cons_egress);
            buf.get_unchecked_mut(FHFL::MAC_RNG.aligned_byte_range())
                .copy_from_slice(&self.mac.0);
            unchecked_bit_range_be_write(buf, FHFL::RES_ID_RNG, self.res_id);
            unchecked_bit_range_be_write(buf, FHFL::BW_RANGE, self.bw);
            unchecked_bit_range_be_write(buf, FHFL::RES_START_OFFSET_RNG, self.res_start_offset);
            unchecked_bit_range_be_write(buf, FHFL::RES_DURATION_RNG, self.res_duration);
        }
        self.required_size()
    }
}

/// Support for [`proptest::arbitrary`].
#[cfg(feature = "proptest")]
pub mod ptest {
    use ::proptest::prelude::*;
    use tinyvec::TinyVec;

    use super::*;

    /// Configuration for generating arbitrary [`HummingbirdPath`] values.
    #[derive(Debug, Clone, Default)]
    pub struct ArbitraryHbirdPathContext {
        /// Weight for generating flyover hop fields in the path.
        pub flyover_hop_field: u32,
        /// Weight for generating standard hop fields in the path.
        pub standard_hop_field: u32,
    }

    impl Arbitrary for HummingbirdPath {
        type Parameters = ArbitraryHbirdPathContext;
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(ctx: Self::Parameters) -> Self::Strategy {
            (
                any::<u8>(),
                any::<u32>(),
                any::<u16>(),
                any::<u32>(),
                prop::collection::vec(HbirdSegment::arbitrary_with(ctx), 1..=3),
            )
                .prop_map(
                    |(curr_hop, base_timestamp, millis_timestamp, counter, mut segments): (
                        u8,
                        u32,
                        u16,
                        u32,
                        Vec<HbirdSegment>,
                    )| {
                        // A Hummingbird path can have at most 80 segments
                        // The HdrLen field in the common header allows for a packet
                        // length of up to 1020 bytes. That includes the common header (12 bytes),
                        // the address header (16 bytes plus 8 bytes for IPv4),
                        // the path meta header (12 bytes for Hummingbird) and
                        // at least one info field (8 bytes). That leaves 964 bytes
                        // for the hop fields (assuming IPv4 addresses in the address
                        // header).
                        //
                        // Here we ensure that the number of bytes for hop fields
                        // is at most 900 bytes.
                        let mut total_hop_size = segments
                            .iter()
                            .map(|s| {
                                s.hop_fields
                                    .iter()
                                    .map(|hf| hf.required_size())
                                    .sum::<usize>()
                            })
                            .sum::<usize>();
                        let mut seg_idx = 0;
                        while total_hop_size > 900 {
                            if let Some(seg) = segments.get_mut(seg_idx) {
                                let hf = seg.hop_fields.pop();
                                total_hop_size -= hf.map_or(0, |hf| hf.required_size());
                                if seg.hop_fields.is_empty() {
                                    segments.remove(seg_idx);
                                }
                            }
                            seg_idx = (seg_idx + 1) % segments.len();
                        }

                        // current_hop must be in range of total hops
                        let total_hops: usize = segments.iter().map(|s| s.hop_fields.len()).sum();
                        let curr_hop = match total_hops {
                            0 => 0,
                            _ => curr_hop % (total_hops as u8),
                        };

                        // current_info_field is defined by which segment the current_hop_field is in
                        let mut hop_count = 0;
                        let mut curr_info = 0;
                        for (i, seg) in segments.iter().enumerate() {
                            hop_count += seg.hop_fields.len();
                            if (curr_hop as usize) < hop_count {
                                curr_info = i as u8;
                                break;
                            }
                        }

                        let segments = segments.into_iter().collect();

                        HummingbirdPath {
                            current_info_field: curr_info,
                            current_hop_field: curr_hop,
                            segments,
                            base_timestamp,
                            millis_timestamp: millis_timestamp & 0x3FF,
                            counter: counter & 0x3F_FF_FF,
                        }
                    },
                )
                .boxed()
        }
    }

    impl Arbitrary for HbirdSegment {
        type Parameters = ArbitraryHbirdPathContext;
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_ctx: Self::Parameters) -> Self::Strategy {
            (
                any::<InfoField>(),
                prop::collection::vec(any::<HbirdHopField>(), 1..=42),
            )
                .prop_map(|(info_field, hop_fields)| {
                    // Ensure segment is not too long
                    let hop_fields = hop_fields
                        .into_iter()
                        .scan(0, |acc, hf| {
                            *acc += hf.required_size();
                            if *acc <= HbirdPathMetaLayout::MAX_SEGMENT_BYTES {
                                Some(hf)
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>();

                    HbirdSegment {
                        info_field,
                        hop_fields: TinyVec::Heap(hop_fields),
                    }
                })
                .boxed()
        }
    }

    impl Arbitrary for HbirdHopField {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                any::<HopField>().prop_map(HbirdHopField::Standard),
                any::<FlyoverHopField>().prop_map(HbirdHopField::Flyover),
            ]
            .boxed()
        }
    }

    impl Arbitrary for FlyoverHopField {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            (
                any::<StdHopFieldFlags>(),
                any::<u8>(),
                any::<u16>(),
                any::<u16>(),
                any::<[u8; 6]>(),
                any::<u32>(),
                any::<u16>(),
                any::<u16>(),
                any::<u16>(),
            )
                .prop_map(
                    |(
                        flags,
                        expiration_units,
                        cons_ingress,
                        cons_egress,
                        mac_bytes,
                        res_id,
                        bw,
                        res_start_offset,
                        res_duration,
                    )| FlyoverHopField {
                        // Mask out everything
                        // and is stripped on decode, so it can't roundtrip.
                        flags,
                        expiration_units,
                        cons_ingress,
                        cons_egress,
                        mac: HopFieldMac(mac_bytes),
                        res_id: res_id & 0x3F_FF_FF,
                        bw: bw & 0x3FF,
                        res_start_offset,
                        res_duration,
                    },
                )
                .boxed()
        }
    }
}
