// Copyright 2026 Mario San-Bento Furtado
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Hummingbird path header layout calculations
//!
//! See [`Layout`](crate::core::layout) for more information about layouts in general.

use crate::{
    core::{
        debug::Annotations,
        layout::{BitRange, Layout, LayoutParseError, macros::gen_bitrange_const},
        view::{View, ViewConversionError},
    },
    dataplane_path::{
        hbird::view::HbirdPathView,
        standard::layout::{HopFieldLayout, InfoFieldLayout},
    },
};

/// Layout for the Hummingbird SCION path, composed of a meta header and data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HbirdPathLayout {
    /// Layout of the path meta header
    pub meta: HbirdPathMetaLayout,
    /// Layout of the path data
    pub data: HbirdPathDataLayout,
}

impl HbirdPathLayout {
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           PathMeta                            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           PathData                            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    /// Attempts to parse the Hummingbird SCION path layout from the given buffer
    pub fn from_slice(buf: &[u8]) -> Result<Self, LayoutParseError> {
        // Check Meta header
        let (meta_buf, _rest) = HbirdPathMetaLayout.split_off_checked(buf).ok_or_else(|| {
            LayoutParseError::BufferTooSmall {
                at: "HbirdPathMeta",
                required: HbirdPathMetaLayout.size_bytes(),
                actual: buf.len(),
            }
        })?;

        let meta_view = unsafe { HbirdPathView::from_slice_unchecked(meta_buf) };
        let seg0_len = meta_view.seg0_len() as usize * 4;
        let seg1_len = meta_view.seg1_len() as usize * 4;
        let seg2_len = meta_view.seg2_len() as usize * 4;

        // Check data is contained
        let data_layout = HbirdPathDataLayout::new(seg0_len, seg1_len, seg2_len);
        let required_size = HbirdPathMetaLayout.size_bytes() + data_layout.size_bytes();

        if buf.len() < required_size {
            return Err(LayoutParseError::BufferTooSmall {
                at: "HbirdPathData",
                required: required_size,
                actual: buf.len(),
            });
        }

        Ok(Self {
            meta: HbirdPathMetaLayout,
            data: data_layout,
        })
    }
}

impl Layout for HbirdPathLayout {
    #[inline]
    fn size_bytes(&self) -> usize {
        self.meta.size_bytes() + self.data.size_bytes()
    }
}

impl TryFrom<&[u8]> for HbirdPathLayout {
    type Error = ViewConversionError;

    #[inline]
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(buf).map_err(ViewConversionError::from)
    }
}

/// Layout for the Hummingbird SCION path meta header
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HbirdPathMetaLayout;
impl HbirdPathMetaLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |CI |    CurrHF     |R|   Seg0Len   |   Seg1Len   |   Seg2Len   |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                        BaseTimestamp                          |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |  MillisTimestamp  |                 Counter                   |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    gen_bitrange_const!(CURR_INFO_FIELD_RNG, 0, 2);
    gen_bitrange_const!(CURR_HOP_FIELD_RNG, 2, 8);
    gen_bitrange_const!(RSV_RNG, 10, 1);
    gen_bitrange_const!(SEG0_LEN_RNG, 11, 7);
    gen_bitrange_const!(SEG1_LEN_RNG, 18, 7);
    gen_bitrange_const!(SEG2_LEN_RNG, 25, 7);
    gen_bitrange_const!(BASE_TIMESTAMP_RNG, 32, 32);
    gen_bitrange_const!(MILLIS_TIMESTAMP_RNG, 64, 10);
    gen_bitrange_const!(COUNTER_RNG, 74, 22);
    gen_bitrange_const!(TOTAL_RNG, 0, 96);

    /// Size of meta header in bytes
    pub const SIZE_BYTES: usize = Self::TOTAL_RNG.end / 8;

    /// Maximum length of a path segment in bytes: the 127 lines a 7-bit line count reaches.
    ///
    /// Counting lines rather than hop fields is what lets one segment mix the 12-byte standard
    /// hop field with the 20-byte flyover.
    pub const MAX_SEGMENT_BYTES: usize = 508;
}

impl HbirdPathMetaLayout {
    /// Returns annotations for the common header fields
    pub fn annotations(&self) -> Annotations {
        let ann = vec![
            (HbirdPathMetaLayout::CURR_INFO_FIELD_RNG, "curr_info_field"),
            (HbirdPathMetaLayout::CURR_HOP_FIELD_RNG, "curr_hop_field"),
            (HbirdPathMetaLayout::RSV_RNG, "rsv"),
            (HbirdPathMetaLayout::SEG0_LEN_RNG, "seg0_len"),
            (HbirdPathMetaLayout::SEG1_LEN_RNG, "seg1_len"),
            (HbirdPathMetaLayout::SEG2_LEN_RNG, "seg2_len"),
            (HbirdPathMetaLayout::BASE_TIMESTAMP_RNG, "base_timestamp"),
            (
                HbirdPathMetaLayout::MILLIS_TIMESTAMP_RNG,
                "millis_timestamp",
            ),
            (HbirdPathMetaLayout::COUNTER_RNG, "counter"),
        ];

        Annotations::new_with("HummingbirdPathMetaHeader".to_string(), ann)
    }
}
impl Layout for HbirdPathMetaLayout {
    #[inline]
    fn size_bytes(&self) -> usize {
        Self::SIZE_BYTES
    }
}

/// Layout for the Hummingbird SCION path data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HbirdPathDataLayout {
    /// Lengths of the three path segments in bytes.
    pub segment_lengths_in_bytes: (usize, usize, usize),
}

impl HbirdPathDataLayout {
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           InfoField                           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                              ...                              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           InfoField                           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           HopField                            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           HopField                            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                              ...                              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    /// Creates a new HbirdPathDataLayout with the given segment lengths
    /// The segment lengths are in bytes.
    #[inline]
    pub const fn new(seg0len: usize, seg1len: usize, seg2len: usize) -> Self {
        Self {
            segment_lengths_in_bytes: (seg0len, seg1len, seg2len),
        }
    }

    /// Returns the number of info fields
    #[inline]
    pub const fn info_field_count(&self) -> usize {
        (self.segment_lengths_in_bytes.0 > 0) as usize
            + (self.segment_lengths_in_bytes.1 > 0) as usize
            + (self.segment_lengths_in_bytes.2 > 0) as usize
    }

    /// Returns the bit range for the info field at the given index
    #[inline]
    pub fn info_field_range(&self, index: usize) -> BitRange {
        InfoFieldLayout::TOTAL_RNG.shift(index * InfoFieldLayout.size_bytes())
    }

    /// Returns the bit range for the hop field at the given byte offset.
    /// The byte offset is relative to the start of the hop fields, i.e., byte
    /// offset 0 points to the first byte of the first hop field.
    #[inline]
    pub fn hop_field_range(&self, byte_offset: usize, is_flyover: bool) -> BitRange {
        let base = self.info_fields_range().size_bytes();
        if is_flyover {
            FlyoverHopFieldLayout::TOTAL_RNG.shift(base + byte_offset)
        } else {
            HopFieldLayout::TOTAL_RNG.shift(base + byte_offset)
        }
    }

    /// Returns the bit range for all info fields
    #[inline]
    pub fn info_fields_range(&self) -> BitRange {
        let info_field_count = self.info_field_count();
        BitRange {
            start: 0,
            end: info_field_count * InfoFieldLayout.size_bits(),
        }
    }

    /// Returns the bit range for all hop fields
    #[inline]
    pub fn hop_fields_range(&self) -> BitRange {
        let info_fields_end = self.info_fields_range().end;

        let hop_fields_bits = (self.segment_lengths_in_bytes.0
            + self.segment_lengths_in_bytes.1
            + self.segment_lengths_in_bytes.2)
            * 8;
        BitRange {
            start: info_fields_end,
            end: info_fields_end + hop_fields_bits,
        }
    }
}
impl HbirdPathDataLayout {
    /// Returns annotations for all info and hop fields
    pub fn annotations(&self) -> Annotations {
        let mut annotations = Annotations::new();

        for _ in 0..self.info_field_count() {
            annotations.extend(InfoFieldLayout.annotations());
        }

        // Annotate first segment
        let start = 0;
        let end = self.segment_lengths_in_bytes.0 * 8;
        annotations.extend(Annotations::new_with(
            "Seg0".to_string(),
            vec![(BitRange { start, end }, "segment")],
        ));

        // Annotate second segment
        let start = end;
        let end = start + self.segment_lengths_in_bytes.1 * 8;
        annotations.extend(Annotations::new_with(
            "Seg1".to_string(),
            vec![(BitRange { start, end }, "segment")],
        ));

        // Annotate third segment
        let start = end;
        let end = start + self.segment_lengths_in_bytes.2 * 8;
        annotations.extend(Annotations::new_with(
            "Seg2".to_string(),
            vec![(BitRange { start, end }, "segment")],
        ));

        annotations
    }
}

impl Layout for HbirdPathDataLayout {
    #[inline]
    fn size_bytes(&self) -> usize {
        self.info_field_count() * InfoFieldLayout.size_bytes()
            + self.segment_lengths_in_bytes.0
            + self.segment_lengths_in_bytes.1
            + self.segment_lengths_in_bytes.2
    }
}

/// Layout for a SCION Hummingbird path hop field.
pub enum HummingbirdHopFieldLayout {
    /// Standard hop field, as defined in the SCION specification.
    Standard(HopFieldLayout),
    /// Flyover hop field, which includes additional fields for reservation information.
    Flyover(FlyoverHopFieldLayout),
}

/// Layout for a SCION Hummingbird path hop field
impl HummingbirdHopFieldLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |F r r r r r I E|    ExpTime    |           ConsIngress         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |        ConsEgress             |                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    // |                              MAC                              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //
    // For flyover hop fiels, we additionally have:
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                   ResID                   |        BW         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |        ResStartOffset         |         ResDuration           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    gen_bitrange_const!(FLAGS_RNG, 0, 8);
    gen_bitrange_const!(EXP_TIME_RNG, 8, 8);
    gen_bitrange_const!(CONS_INGRESS_RNG, 16, 16);
    gen_bitrange_const!(CONS_EGRESS_RNG, 32, 16);
    gen_bitrange_const!(MAC_RNG, 48, 48);
}

impl From<HopFieldLayout> for HummingbirdHopFieldLayout {
    fn from(layout: HopFieldLayout) -> Self {
        HummingbirdHopFieldLayout::Standard(layout)
    }
}

impl From<FlyoverHopFieldLayout> for HummingbirdHopFieldLayout {
    fn from(layout: FlyoverHopFieldLayout) -> Self {
        HummingbirdHopFieldLayout::Flyover(layout)
    }
}

/// Layout for a SCION Hummingbird path flyover hop field
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlyoverHopFieldLayout;
impl FlyoverHopFieldLayout {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |F r r r r r I E|    ExpTime    |           ConsIngress         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |        ConsEgress             |                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    // |                              MAC                              |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                   ResID                   |        BW         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |        ResStartOffset         |         ResDuration           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    gen_bitrange_const!(FLAGS_RNG, 0, 8);
    gen_bitrange_const!(EXP_TIME_RNG, 8, 8);
    gen_bitrange_const!(CONS_INGRESS_RNG, 16, 16);
    gen_bitrange_const!(CONS_EGRESS_RNG, 32, 16);
    gen_bitrange_const!(MAC_RNG, 48, 48);
    gen_bitrange_const!(RES_ID_RNG, 96, 22);
    gen_bitrange_const!(BW_RANGE, 118, 10);
    gen_bitrange_const!(RES_START_OFFSET_RNG, 128, 16);
    gen_bitrange_const!(RES_DURATION_RNG, 144, 16);
    gen_bitrange_const!(TOTAL_RNG, 0, 160);

    /// Size of hop field in bytes
    pub const SIZE_BYTES: usize = Self::TOTAL_RNG.end / 8;
}

impl FlyoverHopFieldLayout {
    /// Returns annotations for the hop field
    pub fn annotations(&self) -> Annotations {
        let ann = vec![
            (FlyoverHopFieldLayout::FLAGS_RNG, "flags"),
            (FlyoverHopFieldLayout::EXP_TIME_RNG, "exp_time"),
            (FlyoverHopFieldLayout::CONS_INGRESS_RNG, "cons_ingress"),
            (FlyoverHopFieldLayout::CONS_EGRESS_RNG, "cons_egress"),
            (FlyoverHopFieldLayout::MAC_RNG, "mac"),
            (FlyoverHopFieldLayout::RES_ID_RNG, "res_id"),
            (FlyoverHopFieldLayout::BW_RANGE, "bw"),
            (
                FlyoverHopFieldLayout::RES_START_OFFSET_RNG,
                "res_start_offset",
            ),
            (FlyoverHopFieldLayout::RES_DURATION_RNG, "res_duration"),
        ];

        Annotations::new_with("FlyoverHopField".to_string(), ann)
    }
}
impl Layout for FlyoverHopFieldLayout {
    #[inline]
    fn size_bytes(&self) -> usize {
        Self::SIZE_BYTES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Constants from the Go reference implementation, pkg/slayers/path/hummingbird:
    // base.go `MetaLen = 12`, flyoverhopfield.go `FlyoverLines = 5` with `LineLen = 4`.
    const GO_META_LEN: usize = 12;
    const GO_FLYOVER_LEN: usize = 20;

    #[test]
    fn meta_layout_matches_the_go_meta_length() {
        assert_eq!(HbirdPathMetaLayout::SIZE_BYTES, GO_META_LEN);
        assert_eq!(
            HbirdPathMetaLayout::SIZE_BYTES,
            HbirdPathMetaLayout::TOTAL_RNG.end / 8
        );
    }

    #[test]
    fn meta_field_ranges_tile_the_header_without_gaps_or_overlap() {
        let ranges = [
            HbirdPathMetaLayout::CURR_INFO_FIELD_RNG,
            HbirdPathMetaLayout::CURR_HOP_FIELD_RNG,
            HbirdPathMetaLayout::RSV_RNG,
            HbirdPathMetaLayout::SEG0_LEN_RNG,
            HbirdPathMetaLayout::SEG1_LEN_RNG,
            HbirdPathMetaLayout::SEG2_LEN_RNG,
            HbirdPathMetaLayout::BASE_TIMESTAMP_RNG,
            HbirdPathMetaLayout::MILLIS_TIMESTAMP_RNG,
            HbirdPathMetaLayout::COUNTER_RNG,
        ];

        let mut cursor = 0;
        for range in ranges {
            assert_eq!(range.start, cursor, "gap or overlap before {range:?}");
            cursor = range.end;
        }
        assert_eq!(cursor, HbirdPathMetaLayout::TOTAL_RNG.end);
    }

    #[test]
    fn counter_is_22_bits_and_millis_is_10() {
        // The Go router recovers the millisecond part as `HighResTS >> 22`, so the split of the
        // third meta line is 10 bits of milliseconds over 22 bits of counter.
        let millis = HbirdPathMetaLayout::MILLIS_TIMESTAMP_RNG;
        let counter = HbirdPathMetaLayout::COUNTER_RNG;

        assert_eq!(millis.end - millis.start, 10);
        assert_eq!(counter.end - counter.start, 22);
        assert_eq!(millis.end, counter.start);
    }

    #[test]
    fn flyover_hop_field_matches_the_go_flyover_length() {
        assert_eq!(FlyoverHopFieldLayout::SIZE_BYTES, GO_FLYOVER_LEN);
        const { assert!(FlyoverHopFieldLayout::SIZE_BYTES > HopFieldLayout::SIZE_BYTES) };
    }

    #[test]
    fn flyover_hop_field_extends_the_standard_one_in_place() {
        // A flyover hop field is a standard hop field with reservation fields appended, so every
        // shared field must sit at the same offset. The Go decoder relies on this: it calls the
        // standard HopField decoder on the same buffer before reading the extra fields.
        assert_eq!(
            FlyoverHopFieldLayout::FLAGS_RNG,
            HopFieldLayout::FLAGS_RNG,
            "flags"
        );
        assert_eq!(
            FlyoverHopFieldLayout::EXP_TIME_RNG,
            HopFieldLayout::EXP_TIME_RNG,
            "exp_time"
        );
        assert_eq!(
            FlyoverHopFieldLayout::CONS_INGRESS_RNG,
            HopFieldLayout::CONS_INGRESS_RNG,
            "cons_ingress"
        );
        assert_eq!(
            FlyoverHopFieldLayout::CONS_EGRESS_RNG,
            HopFieldLayout::CONS_EGRESS_RNG,
            "cons_egress"
        );
        assert_eq!(
            FlyoverHopFieldLayout::MAC_RNG,
            HopFieldLayout::MAC_RNG,
            "mac"
        );
    }

    #[test]
    fn reservation_field_ranges_match_the_go_decoder() {
        // Go reads: ResID from `BigEndian.Uint32(raw[12:16]) >> 10`, Bw from
        // `BigEndian.Uint16(raw[14:16]) & 0x03ff`, ResStartTime from raw[16:18] and Duration
        // from raw[18:20].
        assert_eq!(FlyoverHopFieldLayout::RES_ID_RNG.start, 12 * 8);
        assert_eq!(FlyoverHopFieldLayout::RES_ID_RNG.end - 12 * 8, 22);
        assert_eq!(FlyoverHopFieldLayout::BW_RANGE.start, 12 * 8 + 22);
        assert_eq!(FlyoverHopFieldLayout::BW_RANGE.end, 16 * 8);
        assert_eq!(FlyoverHopFieldLayout::RES_START_OFFSET_RNG.start, 16 * 8);
        assert_eq!(FlyoverHopFieldLayout::RES_START_OFFSET_RNG.end, 18 * 8);
        assert_eq!(FlyoverHopFieldLayout::RES_DURATION_RNG.start, 18 * 8);
        assert_eq!(FlyoverHopFieldLayout::RES_DURATION_RNG.end, 20 * 8);
    }

    #[test]
    fn segment_lengths_are_byte_counts_not_hop_field_counts() {
        // This is the structural difference from the standard path: a Hummingbird segment mixes
        // 12-byte and 20-byte hop fields, so its size cannot be derived by multiplying a hop
        // field count. The meta header counts 4-byte lines, which the layout stores as bytes.
        let one_standard_one_flyover =
            HopFieldLayout::SIZE_BYTES + FlyoverHopFieldLayout::SIZE_BYTES;
        let layout = HbirdPathDataLayout::new(one_standard_one_flyover, 0, 0);

        assert_eq!(layout.info_field_count(), 1);
        assert_eq!(
            layout.size_bytes(),
            InfoFieldLayout::SIZE_BYTES + one_standard_one_flyover
        );
        assert_eq!(
            layout.hop_fields_range().size_bytes(),
            one_standard_one_flyover
        );
    }

    #[test]
    fn hop_field_range_accounts_for_preceding_flyovers() {
        // Walking the hop fields is offset-driven, not index-driven: the second hop field starts
        // 20 bytes in when the first is a flyover, and 12 bytes in when it is not.
        let layout = HbirdPathDataLayout::new(64, 0, 0);
        let info_bytes = InfoFieldLayout::SIZE_BYTES;

        let after_flyover = layout.hop_field_range(FlyoverHopFieldLayout::SIZE_BYTES, false);
        assert_eq!(
            after_flyover.start / 8,
            info_bytes + FlyoverHopFieldLayout::SIZE_BYTES
        );

        let after_standard = layout.hop_field_range(HopFieldLayout::SIZE_BYTES, true);
        assert_eq!(
            after_standard.start / 8,
            info_bytes + HopFieldLayout::SIZE_BYTES
        );
        assert_eq!(
            after_standard.size_bytes(),
            FlyoverHopFieldLayout::SIZE_BYTES
        );
    }

    #[test]
    fn info_field_count_follows_the_populated_segments() {
        assert_eq!(HbirdPathDataLayout::new(0, 0, 0).info_field_count(), 0);
        assert_eq!(HbirdPathDataLayout::new(12, 0, 0).info_field_count(), 1);
        assert_eq!(HbirdPathDataLayout::new(12, 12, 0).info_field_count(), 2);
        assert_eq!(HbirdPathDataLayout::new(12, 12, 12).info_field_count(), 3);
    }
}
