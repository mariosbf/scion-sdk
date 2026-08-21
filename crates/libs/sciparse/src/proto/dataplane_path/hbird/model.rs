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

//! SCION Hummingbird path models

use std::time::SystemTime;

use tinyvec::TinyVec;

use crate::{
    core::{
        convert::{FromView, TryFromModel},
        encode::{InvalidStructureError, WireEncode},
        model::Model,
        write::unchecked_bit_range_be_write,
    },
    dataplane_path::{
        hbird::{
            layout::{FlyoverHopFieldLayout, HbirdPathDataLayout, HbirdPathMetaLayout},
            types::HbirdHopFieldFlags,
            view::{FlyoverHopFieldView, HbirdHopFieldView, HbirdPathView},
        },
        standard::{
            layout::InfoFieldLayout,
            model::{HopField, InfoField, Segment, StandardPath},
            types::{HopFieldFlags, HopFieldMac, InfoFieldFlags},
            view::HopFieldView,
        },
    },
    hummingbird::{
        Reservation,
        crypto::{flyover_mac, xor_in_place},
    },
    identifier::isd_asn::IsdAsn,
};

/// Why a Hummingbird path could not be encoded for a particular packet.
///
/// Distinct from [`InvalidStructureError`] because these describe a path that is well-formed but
/// cannot be laid out this way: with this reservation material, or with this many hops widened
/// into flyovers. The same path may encode perfectly a moment later, or for a different packet,
/// or with fewer flyovers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HbirdEncodeError {
    /// The reservation did not start before the packet's base timestamp, or started so long
    /// before it that the offset does not fit its 16-bit field.
    #[error("the reservation is not valid for this packet's base timestamp")]
    ReservationNotValid,

    /// A segment grew past the 7-bit line count the meta header can express. Reachable only on a
    /// long segment with many flyovers, since each one widens a hop by two lines.
    #[error("segment {segment} is {bytes} bytes, over the {max} the meta header can express", max = HbirdPathMetaLayout::MAX_SEGMENT_BYTES)]
    SegmentTooLong {
        /// Which of the path's segments overflowed.
        segment: usize,
        /// The length it would have needed, in bytes.
        bytes: usize,
    },

    /// A hop encoded as a standard hop field set the bit that Hummingbird reads as the flyover
    /// discriminator.
    ///
    /// The bit is merely reserved in a standard SCION path, so such a path is well-formed; it just
    /// cannot be carried by Hummingbird, where the field would be written as 12 bytes and read
    /// back as a 20-byte one that swallows its successor.
    #[error("hop {hop} is not a flyover but sets the flyover bit")]
    FlyoverBitInStandardHopField {
        /// Which of the path's hops, counting across all segments in order.
        hop: usize,
    },

    /// The current hop field landed past the 8-bit line offset the meta header can express, or at
    /// an offset that is not a whole number of lines.
    #[error("a current hop field at byte {bytes} cannot be addressed by the meta header")]
    CurrentHopFieldUnaddressable {
        /// The offset it would have needed, in bytes from the start of the hop fields.
        bytes: usize,
    },
}

/// Width of the 4-byte line the meta header counts segment lengths and hop field offsets in.
pub const LINE_BYTES: usize = 4;

/// The meta-header fields fixed for one packet.
///
/// Carried separately from [`HummingbirdPath`] because per-packet resolution never builds a path
/// model: it holds these six fields and a set of hop decisions, and writes the result straight
/// into the packet buffer.
///
/// `current_hop_field` and `segment_lengths` are in 4-byte lines, as they appear on the wire. Hop
/// fields vary in width, so a line offset rather than an index is what the meta header can
/// express.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct HbirdMetaFields {
    /// Index of the current info field.
    pub current_info_field: u8,
    /// Offset of the current hop field, in 4-byte lines.
    pub current_hop_field: u8,
    /// Length of each segment, in 4-byte lines.
    pub segment_lengths: [u8; 3],
    /// Whole-second send time.
    pub base_timestamp: u32,
    /// Millisecond offset from `base_timestamp`. Ten bits on the wire.
    pub millis_timestamp: u16,
    /// Packet counter. Twenty-two bits on the wire.
    pub counter: u32,
}

impl HbirdMetaFields {
    /// Offset of the current hop field from the start of the hop fields, in bytes.
    pub fn current_hop_field_bytes(&self) -> usize {
        self.current_hop_field as usize * LINE_BYTES
    }

    /// Points the meta header at the hop field that starts `bytes` into the hop fields.
    ///
    /// Fails when that offset is not a whole number of lines, or is past the 255 lines the 8-bit
    /// field can express.
    pub fn set_current_hop_field_bytes(&mut self, bytes: usize) -> Result<(), HbirdEncodeError> {
        let lines = bytes / LINE_BYTES;
        if !bytes.is_multiple_of(LINE_BYTES) || lines > u8::MAX as usize {
            return Err(HbirdEncodeError::CurrentHopFieldUnaddressable { bytes });
        }

        self.current_hop_field = lines as u8;
        Ok(())
    }

    /// Records the length of each segment, given in bytes.
    ///
    /// Fails on the first segment past [`HbirdPathMetaLayout::MAX_SEGMENT_BYTES`], the largest a
    /// 7-bit line count reaches.
    pub fn set_segment_lengths_bytes(&mut self, bytes: [usize; 3]) -> Result<(), HbirdEncodeError> {
        for (segment, &len) in bytes.iter().enumerate() {
            if !len.is_multiple_of(LINE_BYTES) || len > HbirdPathMetaLayout::MAX_SEGMENT_BYTES {
                return Err(HbirdEncodeError::SegmentTooLong {
                    segment,
                    bytes: len,
                });
            }
            self.segment_lengths[segment] = (len / LINE_BYTES) as u8;
        }

        Ok(())
    }

    /// Number of info fields the segment lengths imply, one per non-empty segment.
    pub fn info_field_count(&self) -> usize {
        self.segment_lengths.iter().filter(|&&len| len > 0).count()
    }

    /// Total encoded size of the path header these fields describe.
    pub fn encoded_len(&self) -> usize {
        HbirdPathMetaLayout::SIZE_BYTES
            + self.info_field_count() * InfoFieldLayout::SIZE_BYTES
            + self
                .segment_lengths
                .iter()
                .map(|&len| len as usize)
                .sum::<usize>()
                * LINE_BYTES
    }
}

impl WireEncode for HbirdMetaFields {
    fn required_size(&self) -> usize {
        HbirdPathMetaLayout::SIZE_BYTES
    }

    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        if self.millis_timestamp > 1023 {
            return Err("millis_timestamp exceeds maximum value of 1023".into());
        }

        if self.counter > 4_194_303 {
            return Err("counter exceeds maximum value of 4,194,303".into());
        }

        // Seven bits per segment length, so 127 lines and 508 bytes.
        if self.segment_lengths.iter().any(|&len| len > 127) {
            return Err("segment length exceeds the 7-bit line count field".into());
        }

        Ok(())
    }

    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        use HbirdPathMetaLayout as HML;

        unsafe {
            unchecked_bit_range_be_write(buf, HML::CURR_INFO_FIELD_RNG, self.current_info_field);
            unchecked_bit_range_be_write(buf, HML::CURR_HOP_FIELD_RNG, self.current_hop_field);
            unchecked_bit_range_be_write(buf, HML::SEG0_LEN_RNG, self.segment_lengths[0]);
            unchecked_bit_range_be_write(buf, HML::SEG1_LEN_RNG, self.segment_lengths[1]);
            unchecked_bit_range_be_write(buf, HML::SEG2_LEN_RNG, self.segment_lengths[2]);
            unchecked_bit_range_be_write(buf, HML::BASE_TIMESTAMP_RNG, self.base_timestamp);
            unchecked_bit_range_be_write(buf, HML::MILLIS_TIMESTAMP_RNG, self.millis_timestamp);
            unchecked_bit_range_be_write(buf, HML::COUNTER_RNG, self.counter);
        }

        self.required_size()
    }
}

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

impl Model for HummingbirdPath {
    type ViewType = HbirdPathView;
}
impl TryFromModel for HbirdPathView {
    type ModelType = HummingbirdPath;
}
impl FromView for HummingbirdPath {
    type ViewType = HbirdPathView;

    fn from_view(view: &Self::ViewType) -> Self {
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
            current_info_field: view.curr_info_field_idx(),
            current_hop_field: view.curr_hop_field_line(),
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

    /// Converts this path into the standard SCION path over the same hops.
    ///
    /// Every flyover hop field is replaced by the standard hop field it extends, dropping the
    /// reservation fields.
    ///
    /// The resulting path's hop field MACs are those carried by this path. For a path taken from
    /// a received packet they are plain standard MACs, because border routers de-aggregate the
    /// flyover MAC out of each hop field before forwarding it onward. For a path assembled
    /// locally with aggregated MACs they are not, and the result will not forward.
    pub fn to_standard_path(&self) -> StandardPath {
        StandardPath {
            current_info_field: self.current_info_field,
            current_hop_field: self.current_hop_field_index() as u8,
            segments: self
                .segments
                .iter()
                .map(|segment| {
                    Segment {
                        info_field: segment.info_field,
                        hop_fields: segment
                            .hop_fields
                            .iter()
                            .map(HbirdHopField::to_standard_hop_field)
                            .collect(),
                    }
                })
                .collect(),
        }
    }

    /// Returns the index of the current hop field.
    ///
    /// `current_hop_field` addresses a hop field by its offset in 4-byte lines, because hop fields
    /// vary in width; converting to an index means walking them. Returns the hop field count if
    /// the offset does not name a hop field.
    pub fn current_hop_field_index(&self) -> usize {
        let target = self.current_hop_field as usize * 4;
        let mut byte_offset = 0;

        for (index, hop_field) in self.iter_hop_fields().enumerate() {
            if byte_offset == target {
                return index;
            }
            byte_offset += hop_field.required_size();
        }

        self.hop_field_count()
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

    /// Returns the standard hop field this one extends, discarding any reservation fields.
    pub fn to_standard_hop_field(&self) -> HopField {
        match self {
            HbirdHopField::Standard(hop_field) => *hop_field,
            HbirdHopField::Flyover(hop_field) => {
                HopField {
                    flags: hop_field.flags,
                    expiration_units: hop_field.expiration_units,
                    cons_ingress: hop_field.cons_ingress,
                    cons_egress: hop_field.cons_egress,
                    mac: hop_field.mac,
                }
            }
        }
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
        match self {
            // In a Hummingbird path the first flags bit *is* the flyover
            // discriminator, and it also sets the hop field's width. A standard
            // hop field carrying it would be encoded as 12 bytes and read back
            // as a 20-byte flyover, swallowing whatever follows it, so the model
            // must not be allowed to express it. (The bit is merely reserved in a
            // standard SCION path, which is why `HopFieldFlags` itself permits
            // it.)
            HbirdHopField::Standard(hf) => {
                if hf.flags.bits() & HbirdHopFieldFlags::FLYOVER.bits() != 0 {
                    return Err(
                        "standard hop field in a Hummingbird path must not set the flyover bit"
                            .into(),
                    );
                }
                hf.wire_valid()
            }
            HbirdHopField::Flyover(fhf) => fhf.wire_valid(),
        }
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
    /// Hop field flags.
    ///
    /// These are the *standard* hop field flags. The flyover bit is not among them: it is implied
    /// by this type and written by the encoder, so setting it here is rejected by
    /// [`wire_valid`](WireEncode::wire_valid).
    pub flags: HopFieldFlags,
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
        // `flags` holds the standard hop field flags only; being a flyover is carried by the type
        // itself and written by the encoder. Storing the bit here as well is redundant state that
        // decoding cannot give back, since the view masks it out of `flags`.
        if self.flags.bits() & HbirdHopFieldFlags::FLYOVER.bits() != 0 {
            return Err(
                "flyover hop field must not repeat the flyover bit in its standard flags".into(),
            );
        }
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

/// Turning a standard hop field into a flyover.
impl HopField {
    /// The aggregated MAC this hop field carries when `reservation` is applied to it for a packet
    /// of `pkt_len` bytes, together with the reservation's start offset from `meta`'s base
    /// timestamp.
    ///
    /// The aggregated MAC is this hop's standard SCION MAC XORed with the reservation's flyover
    /// MAC. A border router de-aggregates before forwarding, which is how a received Hummingbird
    /// path comes to carry plain standard MACs.
    pub fn aggregated_flyover_mac(
        &self,
        meta: HbirdMetaFields,
        reservation: &Reservation,
        dst_ia: IsdAsn,
        pkt_len: u16,
    ) -> Result<(HopFieldMac, u16), HbirdEncodeError> {
        let res_start_offset = reservation
            .res_start_offset(meta.base_timestamp)
            .ok_or(HbirdEncodeError::ReservationNotValid)?;

        let flyover = flyover_mac(
            dst_ia,
            pkt_len,
            res_start_offset,
            meta.millis_timestamp,
            meta.counter,
            reservation.cipher(),
        );

        let mut mac = self.mac.0;
        xor_in_place(&mut mac, &flyover);

        Ok((HopFieldMac(mac), res_start_offset))
    }
}

impl FlyoverHopField {
    /// Builds the flyover hop field `hop` becomes under `reservation`, given the aggregated MAC
    /// and start offset from [`HopField::aggregated_flyover_mac`].
    pub fn from_hop_field(
        hop: &HopField,
        reservation: &Reservation,
        mac: HopFieldMac,
        res_start_offset: u16,
    ) -> Self {
        let info = reservation.info();
        Self {
            flags: hop.flags,
            expiration_units: hop.expiration_units,
            cons_ingress: hop.cons_ingress,
            cons_egress: hop.cons_egress,
            mac,
            res_id: info.res_id,
            bw: info.bandwidth.encode(),
            res_start_offset,
            res_duration: info.duration,
        }
    }

    /// Writes the parts of `hop`'s flyover encoding that do not vary from packet to packet,
    /// leaving the rest zero for [`patch_per_packet_fields`](Self::patch_per_packet_fields).
    ///
    /// The flags, expiration and interface numbers come from the standard hop field and hold for
    /// the life of the path; the MAC and the four reservation fields change with the packet or
    /// with which reservation was selected for it. Splitting them is what lets resolution copy a
    /// precomputed header and overwrite only the second group.
    pub fn encode_template(hop: &HopField, buf: &mut [u8; FlyoverHopFieldLayout::SIZE_BYTES]) {
        use FlyoverHopFieldLayout as FHFL;

        buf.fill(0);
        // SAFETY: `buf` is exactly one flyover hop field, so every range is in bounds.
        unsafe {
            unchecked_bit_range_be_write(
                buf,
                FHFL::FLAGS_RNG,
                hop.flags.bits() | HbirdHopFieldFlags::FLYOVER.bits(),
            );
            unchecked_bit_range_be_write(buf, FHFL::EXP_TIME_RNG, hop.expiration_units);
            unchecked_bit_range_be_write(buf, FHFL::CONS_INGRESS_RNG, hop.cons_ingress);
            unchecked_bit_range_be_write(buf, FHFL::CONS_EGRESS_RNG, hop.cons_egress);
        }
    }

    /// Overwrites the parts of a flyover hop field that vary from packet to packet.
    ///
    /// `bw` is the encoded bandwidth, as [`Bandwidth::encode`] produces and as the wire carries.
    ///
    /// Every field written here is written in full, so a buffer may be patched repeatedly without
    /// being reset in between.
    pub fn patch_per_packet_fields(
        buf: &mut [u8; FlyoverHopFieldLayout::SIZE_BYTES],
        mac: &HopFieldMac,
        res_id: u32,
        bw: u16,
        res_start_offset: u16,
        res_duration: u16,
    ) {
        use FlyoverHopFieldLayout as FHFL;

        // The five per-packet fields are contiguous and between them cover bytes 6..20 exactly,
        // so nothing here is a read-modify-write: the MAC is six bytes, and the remaining four
        // fields pack into one big-endian u64 (22 + 10 + 16 + 16 bits). Writing them as two
        // stores rather than through four bit-range writes is worth roughly a tenth of the encode
        // — each bit-range write otherwise reads its lane, masks, and writes it back.
        //
        // Hand-packing is only safe while it agrees with the layout, so the layout checks it.
        const {
            assert!(FHFL::MAC_RNG.start == 48 && FHFL::MAC_RNG.end == 96);
            assert!(FHFL::RES_ID_RNG.start == 96 && FHFL::RES_ID_RNG.end == 118);
            assert!(FHFL::BW_RANGE.start == 118 && FHFL::BW_RANGE.end == 128);
            assert!(FHFL::RES_START_OFFSET_RNG.start == 128);
            assert!(FHFL::RES_START_OFFSET_RNG.end == 144);
            assert!(FHFL::RES_DURATION_RNG.start == 144 && FHFL::RES_DURATION_RNG.end == 160);
        }

        // Masked for the same reason the flyover MAC's inputs are: `res_id` and `bw` are narrower
        // than their Rust types, and an over-wide value would silently overwrite its neighbour
        // rather than being truncated to its own field.
        let tail = (u64::from(res_id & 0x003F_FFFF) << 42)
            | (u64::from(bw & 0x03FF) << 32)
            | (u64::from(res_start_offset) << 16)
            | u64::from(res_duration);

        // SAFETY: `buf` is exactly one flyover hop field, so bytes 6..20 are in bounds.
        unsafe {
            buf.get_unchecked_mut(6..12).copy_from_slice(&mac.0);
            buf.get_unchecked_mut(12..20)
                .copy_from_slice(&tail.to_be_bytes());
        }
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
                        // A Hummingbird path can carry at most 80 hop fields. HdrLen counts
                        // 4-byte lines in 8 bits, capping the header at 1020 bytes: 12 for the
                        // common header, 24 for an IPv4 address header, 12 for the Hummingbird
                        // meta header and 8 for one info field leave 964 bytes, or 80 standard
                        // hop fields.
                        //
                        // The 900-byte trim below stays clear of that ceiling, leaving room for
                        // the second and third info fields a multi-segment path adds.
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

                        // current_info_field is defined by which segment the current_hop_field is
                        // in
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
                any::<HopField>().prop_map(|mut hf| {
                    // The flyover bit is the width discriminator; a standard hop field carrying it
                    // is not a representable Hummingbird hop field. See `wire_valid`.
                    hf.flags = HopFieldFlags::from_bits_retain(
                        hf.flags.bits() & !HbirdHopFieldFlags::FLYOVER.bits(),
                    );
                    HbirdHopField::Standard(hf)
                }),
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
                any::<HopFieldFlags>().prop_map(|flags| {
                    // The flyover bit belongs to the variant, not to `flags`. See `wire_valid`.
                    HopFieldFlags::from_bits_retain(
                        flags.bits() & !HbirdHopFieldFlags::FLYOVER.bits(),
                    )
                }),
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
                    )| {
                        FlyoverHopField {
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
                        }
                    },
                )
                .boxed()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::{convert::ToModel, view::View},
        dataplane_path::{
            model::DpPath,
            standard::{
                layout::HopFieldLayout,
                types::{EXP_TIME_UNIT, exp_time_to_duration},
            },
            types::PathType,
            view::ScionDpPathViewExt,
        },
    };

    fn standard_hop(cons_ingress: u16, cons_egress: u16) -> HbirdHopField {
        HbirdHopField::Standard(HopField {
            flags: HopFieldFlags::empty(),
            expiration_units: 63,
            cons_ingress,
            cons_egress,
            mac: HopFieldMac::new([1, 2, 3, 4, 5, 6]),
        })
    }

    fn flyover_hop(cons_ingress: u16, cons_egress: u16, res_id: u32) -> HbirdHopField {
        HbirdHopField::Flyover(FlyoverHopField {
            flags: HopFieldFlags::empty(),
            expiration_units: 63,
            cons_ingress,
            cons_egress,
            mac: HopFieldMac::new([7, 8, 9, 10, 11, 12]),
            res_id,
            bw: 0x03FF,
            res_start_offset: 4242,
            res_duration: 3600,
        })
    }

    fn segment(hop_fields: Vec<HbirdHopField>) -> HbirdSegment {
        HbirdSegment {
            info_field: InfoField {
                flags: InfoFieldFlags::CONS_DIR,
                segment_id: 0xBEEF,
                timestamp: 1_700_000_000,
            },
            hop_fields: hop_fields.into_iter().collect(),
        }
    }

    /// A path whose single segment mixes flyover and standard hop fields.
    fn mixed_path() -> HummingbirdPath {
        HummingbirdPath {
            current_info_field: 0,
            current_hop_field: 0,
            segments: vec![segment(vec![
                flyover_hop(0, 1, 0x3F_FFFF),
                standard_hop(2, 3),
                flyover_hop(4, 0, 7),
            ])],
            base_timestamp: 1_700_000_000,
            millis_timestamp: 1023,
            counter: 0x3F_FFFF,
        }
    }

    #[test]
    fn mixed_path_round_trips_through_the_wire_format() {
        let path = mixed_path();
        let view = path.try_encode_to_owned_view().expect("path should encode");

        assert_eq!(HummingbirdPath::from_view(&view), path);
    }

    #[test]
    fn required_size_matches_the_encoded_length() {
        // `required_size` is consulted before encoding to size the buffer; an answer below the
        // real length is a buffer overrun, above it is a malformed packet length.
        let path = mixed_path();
        let view = path.try_encode_to_owned_view().expect("path should encode");

        assert_eq!(path.required_size(), View::as_slice(&*view).len());
    }

    #[test]
    fn encoded_length_accounts_for_each_hop_field_width() {
        let path = mixed_path();

        let expected = HbirdPathMetaLayout::SIZE_BYTES
            + InfoFieldLayout::SIZE_BYTES
            + 2 * FlyoverHopFieldLayout::SIZE_BYTES
            + HopFieldLayout::SIZE_BYTES;

        assert_eq!(path.required_size(), expected);
    }

    #[test]
    fn segment_length_is_recorded_in_lines() {
        // The meta header counts 4-byte lines, so a segment of two flyovers and one standard hop
        // field is (20 + 20 + 12) / 4 = 13 lines, a number no hop field count could produce.
        let path = mixed_path();
        let view = path.try_encode_to_owned_view().expect("path should encode");

        assert_eq!(view.seg0_len(), 13);
        assert_eq!(view.seg0_len_bytes(), 52);
        assert_eq!(view.info_field_count(), 1);
    }

    #[test]
    fn flyover_bit_is_set_only_on_flyover_hop_fields() {
        let path = mixed_path();
        let view = path.try_encode_to_owned_view().expect("path should encode");

        let flyovers: Vec<bool> = view.hop_fields().map(|hop| hop.is_flyover()).collect();
        assert_eq!(flyovers, vec![true, false, true]);
    }

    #[test]
    fn reservation_fields_survive_the_round_trip() {
        // The reservation fields are the whole point of a flyover hop field, and they sit beyond
        // the bytes a standard hop field occupies.
        let path = mixed_path();
        let view = path.try_encode_to_owned_view().expect("path should encode");
        let back = view.to_model();

        let HbirdHopField::Flyover(first) = &back.segments[0].hop_fields[0] else {
            panic!("first hop field should be a flyover");
        };
        assert_eq!(first.res_id, 0x3F_FFFF);
        assert_eq!(first.bw, 0x03FF);
        assert_eq!(first.res_start_offset, 4242);
        assert_eq!(first.res_duration, 3600);
    }

    #[test]
    fn a_multi_segment_path_round_trips() {
        let path = HummingbirdPath {
            current_info_field: 1,
            current_hop_field: 5,
            segments: vec![
                segment(vec![flyover_hop(0, 1, 11), standard_hop(2, 3)]),
                segment(vec![standard_hop(3, 4), flyover_hop(4, 0, 22)]),
            ],
            base_timestamp: 42,
            millis_timestamp: 7,
            counter: 9,
        };
        let view = path.try_encode_to_owned_view().expect("path should encode");

        assert_eq!(view.info_field_count(), 2);
        assert_eq!(view.to_model(), path);
    }

    #[test]
    fn a_path_without_segments_is_rejected() {
        // A bare meta header would encode and decode cleanly, so nothing downstream would notice
        // the path routes nowhere; `wire_valid` is what catches it.
        let path = HummingbirdPath {
            current_info_field: 0,
            current_hop_field: 0,
            segments: vec![],
            base_timestamp: 0,
            millis_timestamp: 0,
            counter: 0,
        };

        assert!(path.wire_valid().is_err());
        assert!(path.try_encode_to_owned_view().is_err());
    }

    #[test]
    fn a_standard_hop_field_may_not_set_the_flyover_bit() {
        // Encoded as 12 bytes but read back as a 20-byte flyover, this would swallow whatever
        // follows it in the segment. Found by the packet round-trip property test.
        let mut path = mixed_path();
        let HbirdHopField::Standard(hop) = &mut path.segments[0].hop_fields[1] else {
            panic!("second hop field should be standard");
        };
        hop.flags = HopFieldFlags::from_bits_retain(HbirdHopFieldFlags::FLYOVER.bits());

        assert!(path.wire_valid().is_err());
        assert!(path.try_encode_to_owned_view().is_err());
    }

    #[test]
    fn a_flyover_hop_field_may_not_repeat_the_flyover_bit_in_its_flags() {
        // Being a flyover is carried by the variant; the view masks the bit out of `flags`, so a
        // model that also stores it there cannot round-trip.
        let mut path = mixed_path();
        let HbirdHopField::Flyover(hop) = &mut path.segments[0].hop_fields[0] else {
            panic!("first hop field should be a flyover");
        };
        hop.flags = HopFieldFlags::from_bits_retain(HbirdHopFieldFlags::FLYOVER.bits());

        assert!(path.wire_valid().is_err());
    }

    #[test]
    fn router_alert_flags_survive_on_both_hop_field_kinds() {
        // The bits that *are* allowed must still make it through, on either width of hop field.
        let mut path = mixed_path();
        let alerts =
            HopFieldFlags::CONS_INGRESS_ROUTER_ALERT | HopFieldFlags::CONS_EGRESS_ROUTER_ALERT;
        match &mut path.segments[0].hop_fields[0] {
            HbirdHopField::Flyover(hop) => hop.flags = alerts,
            _ => panic!("first hop field should be a flyover"),
        }
        match &mut path.segments[0].hop_fields[1] {
            HbirdHopField::Standard(hop) => hop.flags = alerts,
            _ => panic!("second hop field should be standard"),
        }

        let view = path.try_encode_to_owned_view().expect("path should encode");
        assert_eq!(view.to_model(), path);
    }

    #[test]
    fn reversal_yields_a_standard_path_over_the_same_hops_in_reverse() {
        // Flyover reservations are directional, so the reverse is a plain standard path. What must
        // survive is the route: the same interface pairs, walked backwards and with each hop's
        // ingress and egress swapped by the flipped construction direction.
        let path = mixed_path();
        let forward: Vec<(u16, u16)> = path
            .iter_hop_fields()
            .map(|hop| {
                let hop = hop.to_standard_hop_field();
                (hop.cons_ingress, hop.cons_egress)
            })
            .collect();

        let mut dp_path = DpPath::Hummingbird(path);
        dp_path.try_reverse().expect("path should reverse");

        let DpPath::Standard(reversed) = dp_path else {
            panic!("reversing a Hummingbird path must yield a standard path");
        };
        let backward: Vec<(u16, u16)> = reversed
            .iter_hop_fields()
            .map(|hop| (hop.cons_ingress, hop.cons_egress))
            .collect();

        assert_eq!(
            backward,
            forward.into_iter().rev().collect::<Vec<_>>(),
            "reversal must preserve the route"
        );
    }

    #[test]
    fn reversal_drops_every_reservation() {
        let mut dp_path = DpPath::Hummingbird(mixed_path());
        dp_path.try_reverse().expect("path should reverse");

        assert_eq!(dp_path.path_type(), PathType::Scion);
        assert!(
            dp_path.required_size() < DpPath::Hummingbird(mixed_path()).required_size(),
            "dropping two flyovers must make the path shorter"
        );
    }

    #[test]
    fn reversal_flips_the_construction_direction() {
        let mut dp_path = DpPath::Hummingbird(mixed_path());
        let was_cons_dir = matches!(&dp_path, DpPath::Hummingbird(p)
            if p.segments[0].info_field.flags.contains(InfoFieldFlags::CONS_DIR));
        dp_path.try_reverse().expect("path should reverse");

        let DpPath::Standard(reversed) = dp_path else {
            panic!("expected a standard path");
        };
        assert_ne!(
            reversed.segments[0]
                .info_field
                .flags
                .contains(InfoFieldFlags::CONS_DIR),
            was_cons_dir
        );
    }

    #[test]
    fn to_standard_path_keeps_the_current_hop_field() {
        // The Hummingbird index is a line offset while the standard one is a hop field index, so
        // the conversion has to walk the hop fields rather than copy the number across.
        let mut path = mixed_path();
        // The second hop field starts one flyover (5 lines) in.
        path.current_hop_field = 5;

        let standard = path.to_standard_path();
        assert_eq!(standard.current_hop_field, 1);

        // The third starts after a flyover and a standard hop field: 5 + 3 lines.
        path.current_hop_field = 8;
        assert_eq!(path.to_standard_path().current_hop_field, 2);
    }

    #[test]
    fn a_reversed_path_re_encodes() {
        // Reversal changes the encoded length, so the result has to survive a fresh encode.
        let mut dp_path = DpPath::Hummingbird(mixed_path());
        dp_path.try_reverse().expect("path should reverse");

        let view = dp_path
            .try_encode_to_owned_view()
            .expect("reversed path should encode");
        assert_eq!(DpPath::from_view(&view.as_ref()), dp_path);
    }

    #[test]
    fn an_out_of_range_millis_timestamp_is_rejected() {
        // The field is 10 bits wide; a larger value would silently truncate into the counter.
        let mut path = mixed_path();
        path.millis_timestamp = 1024;

        assert!(path.wire_valid().is_err());
    }

    #[test]
    fn expiration_units_keep_their_standard_meaning() {
        // A flyover hop field is a standard hop field with fields appended, so its expiration is
        // read in the standard unit rather than anything Hummingbird-specific.
        let path = mixed_path();
        let view = path.try_encode_to_owned_view().expect("path should encode");

        let first = view.hop_fields().next().expect("a hop field");
        assert_eq!(first.exp_time(), 63);
        assert_eq!(exp_time_to_duration(first.exp_time()), EXP_TIME_UNIT * 64);
    }
}

#[cfg(test)]
mod flyover_encode_tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use crate::hummingbird::{Bandwidth, test_support::reservation};

    /// The start `test_support::reservation` uses, so a base timestamp can be placed after it.
    const RES_START: u64 = 1_700_000_000;

    fn dst_ia() -> IsdAsn {
        IsdAsn(0x1_ff00_0000_0112)
    }

    fn hop() -> HopField {
        HopField {
            flags: HopFieldFlags::CONS_INGRESS_ROUTER_ALERT,
            expiration_units: 63,
            cons_ingress: 1,
            cons_egress: 2,
            mac: HopFieldMac([1, 2, 3, 4, 5, 6]),
        }
    }

    fn meta() -> HbirdMetaFields {
        HbirdMetaFields {
            current_info_field: 0,
            current_hop_field: 0,
            // Three standard hop fields: 36 bytes, so nine 4-byte lines.
            segment_lengths: [9, 0, 0],
            base_timestamp: RES_START as u32 + 5,
            millis_timestamp: 250,
            counter: 7,
        }
    }

    fn test_reservation() -> Reservation {
        reservation(0x1234, 1024, UNIX_EPOCH + Duration::from_secs(RES_START))
    }

    #[test]
    fn the_aggregated_mac_is_the_standard_mac_xored_with_the_flyover_mac() {
        // The relationship the border router inverts: `deAggregateAndCacheMac` XORs the flyover
        // MAC back out before delivering to the end host. Any other relationship forwards nothing.
        let hop = hop();
        let reservation = test_reservation();

        let (aggregated, offset) = hop
            .aggregated_flyover_mac(meta(), &reservation, dst_ia(), 100)
            .expect("the reservation starts before the base timestamp");

        let mut expected = hop.mac.0;
        xor_in_place(
            &mut expected,
            &flyover_mac(dst_ia(), 100, offset, 250, 7, reservation.cipher()),
        );

        assert_eq!(aggregated.0, expected);
    }

    #[test]
    fn the_start_offset_is_measured_from_the_base_timestamp() {
        let (_, offset) = hop()
            .aggregated_flyover_mac(meta(), &test_reservation(), dst_ia(), 100)
            .expect("the reservation starts before the base timestamp");

        assert_eq!(offset, 5);
    }

    #[test]
    fn a_reservation_starting_after_the_base_timestamp_cannot_be_applied() {
        // The offset is unsigned and measured backwards from the base timestamp, so a reservation
        // whose window has not opened has no representable offset.
        let early = HbirdMetaFields {
            base_timestamp: RES_START as u32 - 1,
            ..meta()
        };

        assert_eq!(
            hop().aggregated_flyover_mac(early, &test_reservation(), dst_ia(), 100),
            Err(HbirdEncodeError::ReservationNotValid),
        );
    }

    #[test]
    fn template_plus_patch_equals_a_full_encode() {
        // The fast path copies a template and patches only the per-packet region. A byte belonging
        // to neither group, or to both, makes the two encoders disagree — and the disagreement
        // first shows up at a router, as a MAC failure.
        let hop = hop();
        let reservation = test_reservation();
        let mac = HopFieldMac([9, 8, 7, 6, 5, 4]);
        let info = reservation.info();

        let mut patched = [0u8; FlyoverHopFieldLayout::SIZE_BYTES];
        FlyoverHopField::encode_template(&hop, &mut patched);
        FlyoverHopField::patch_per_packet_fields(
            &mut patched,
            &mac,
            info.res_id,
            info.bandwidth.encode(),
            5,
            info.duration,
        );

        let mut expected = [0u8; FlyoverHopFieldLayout::SIZE_BYTES];
        FlyoverHopField::from_hop_field(&hop, &reservation, mac, 5)
            .try_encode(&mut expected)
            .expect("the buffer is exactly one hop field");

        assert_eq!(patched, expected);
    }

    #[test]
    fn the_template_leaves_every_per_packet_byte_zero() {
        // A template that baked in a MAC would produce correct bytes for one packet and stale ones
        // for every packet after it.
        let mut template = [0u8; FlyoverHopFieldLayout::SIZE_BYTES];
        FlyoverHopField::encode_template(&hop(), &mut template);

        let mut zeroed = template;
        FlyoverHopField::patch_per_packet_fields(
            &mut zeroed,
            &HopFieldMac([0; 6]),
            0,
            Bandwidth::from_bytes_per_sec(0)
                .expect("representable")
                .encode(),
            0,
            0,
        );

        assert_eq!(template, zeroed);
    }

    #[test]
    fn patching_twice_leaves_no_trace_of_the_first_patch() {
        // Resolution reuses one buffer across packets, so every per-packet field is written in
        // full rather than merged into what was there.
        let mut once = [0u8; FlyoverHopFieldLayout::SIZE_BYTES];
        FlyoverHopField::encode_template(&hop(), &mut once);
        let mut twice = once;

        FlyoverHopField::patch_per_packet_fields(
            &mut twice,
            &HopFieldMac([0xFF; 6]),
            0x3F_FFFF,
            1023,
            0xFFFF,
            0xFFFF,
        );
        FlyoverHopField::patch_per_packet_fields(&mut twice, &HopFieldMac([1; 6]), 7, 3, 9, 11);
        FlyoverHopField::patch_per_packet_fields(&mut once, &HopFieldMac([1; 6]), 7, 3, 9, 11);

        assert_eq!(once, twice);
    }

    #[test]
    fn the_template_carries_the_flyover_bit() {
        // Hop field width is discriminated by this bit alone: without it the twenty bytes decode
        // as a twelve-byte standard hop field followed by eight bytes of whatever comes next.
        let mut template = [0u8; FlyoverHopFieldLayout::SIZE_BYTES];
        FlyoverHopField::encode_template(&hop(), &mut template);

        assert_ne!(template[0] & HbirdHopFieldFlags::FLYOVER.bits(), 0);
    }

    #[test]
    fn the_template_preserves_the_standard_hop_fields_flags() {
        // Router alerts are set by whoever built the path and must survive the widening.
        let mut template = [0u8; FlyoverHopFieldLayout::SIZE_BYTES];
        FlyoverHopField::encode_template(&hop(), &mut template);

        assert_ne!(
            template[0] & HopFieldFlags::CONS_INGRESS_ROUTER_ALERT.bits(),
            0
        );
    }

    #[test]
    fn meta_fields_reject_values_their_wire_fields_cannot_carry() {
        assert!(
            HbirdMetaFields {
                millis_timestamp: 1024,
                ..meta()
            }
            .wire_valid()
            .is_err()
        );
        assert!(
            HbirdMetaFields {
                counter: 4_194_304,
                ..meta()
            }
            .wire_valid()
            .is_err()
        );
        assert!(
            HbirdMetaFields {
                segment_lengths: [128, 0, 0],
                ..meta()
            }
            .wire_valid()
            .is_err()
        );
        assert!(meta().wire_valid().is_ok());
    }

    #[test]
    fn meta_fields_encode_like_the_path_model() {
        // Resolution writes the meta header from HbirdMetaFields while everything else writes it
        // from HummingbirdPath. The two must agree byte for byte.
        let path = HummingbirdPath {
            current_info_field: 0,
            current_hop_field: 0,
            segments: vec![HbirdSegment {
                info_field: InfoField {
                    flags: InfoFieldFlags::CONS_DIR,
                    segment_id: 7,
                    timestamp: 1_700_000_000,
                },
                hop_fields: std::iter::repeat_with(|| HbirdHopField::Standard(hop()))
                    .take(3)
                    .collect(),
            }],
            base_timestamp: RES_START as u32 + 5,
            millis_timestamp: 250,
            counter: 7,
        };

        let mut from_path = vec![0u8; path.required_size()];
        path.try_encode(&mut from_path).expect("encodes");

        let mut from_meta = [0u8; HbirdPathMetaLayout::SIZE_BYTES];
        meta().try_encode(&mut from_meta).expect("encodes");

        assert_eq!(&from_path[..HbirdPathMetaLayout::SIZE_BYTES], &from_meta);
    }

    /// One standard hop field followed by one flyover: 32 bytes, and both widths in one segment.
    fn mixed_segment() -> HbirdSegment {
        HbirdSegment {
            info_field: InfoField {
                flags: InfoFieldFlags::CONS_DIR,
                segment_id: 7,
                timestamp: RES_START as u32,
            },
            hop_fields: [
                HbirdHopField::Standard(hop()),
                HbirdHopField::Flyover(FlyoverHopField::from_hop_field(
                    &hop(),
                    &test_reservation(),
                    HopFieldMac([1, 2, 3, 4, 5, 6]),
                    0,
                )),
            ]
            .into_iter()
            .collect(),
        }
    }

    #[test]
    fn the_meta_header_addresses_hop_fields_in_lines() {
        let mut meta = HbirdMetaFields::default();

        meta.set_current_hop_field_bytes(20 + 12)
            .expect("two lines");
        assert_eq!(meta.current_hop_field, 8);
        assert_eq!(meta.current_hop_field_bytes(), 32);
    }

    #[test]
    fn an_unaddressable_current_hop_field_is_refused() {
        // Eight bits of line count reach 1020 bytes, and an offset that is not a whole number of
        // lines has no encoding at all. Either would otherwise be truncated into an offset that
        // names a different hop field.
        let mut meta = HbirdMetaFields::default();

        assert_eq!(
            meta.set_current_hop_field_bytes(1024),
            Err(HbirdEncodeError::CurrentHopFieldUnaddressable { bytes: 1024 })
        );
        assert_eq!(
            meta.set_current_hop_field_bytes(14),
            Err(HbirdEncodeError::CurrentHopFieldUnaddressable { bytes: 14 })
        );
        assert_eq!(meta.set_current_hop_field_bytes(1020), Ok(()));
    }

    #[test]
    fn a_segment_past_the_line_count_field_is_refused() {
        // Seven bits per segment length, so 127 lines and 508 bytes. This is the limit that makes
        // mixing 12- and 20-byte hop fields in one segment possible at all, and the one a long
        // path with many flyovers runs into.
        let mut meta = HbirdMetaFields::default();

        assert_eq!(meta.set_segment_lengths_bytes([508, 0, 0]), Ok(()));
        assert_eq!(meta.segment_lengths, [127, 0, 0]);

        assert_eq!(
            meta.set_segment_lengths_bytes([12, 512, 0]),
            Err(HbirdEncodeError::SegmentTooLong {
                segment: 1,
                bytes: 512
            })
        );
    }

    #[test]
    fn the_meta_header_reports_the_length_of_the_path_it_describes() {
        // Resolution sizes the packet from these fields alone, without building a path model.
        let path = HummingbirdPath {
            current_info_field: 0,
            current_hop_field: 0,
            segments: vec![mixed_segment(), mixed_segment()],
            base_timestamp: RES_START as u32,
            millis_timestamp: 0,
            counter: 0,
        };

        let mut meta = HbirdMetaFields::default();
        meta.set_segment_lengths_bytes([12 + 20, 20 + 12, 0])
            .expect("both segments fit");

        assert_eq!(meta.info_field_count(), 2);
        assert_eq!(meta.encoded_len(), path.required_size());
    }
}
