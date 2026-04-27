//! SCION Hummingbird path views
//!
//! See [`View`](crate::core::view) for more information about views in general.

use std::{
    fmt::Debug,
    mem::transmute,
    ops::{Deref, DerefMut, Range},
};

use crate::{
    core::{
        read::unchecked_bit_range_be_read,
        view::{
            View, ViewConversionError,
            macros::{gen_field_read, gen_field_write, gen_unsafe_field_write, gen_view_impl},
        },
        write::unchecked_bit_range_be_write,
    },
    path::{
        hbird::{
            layout::{
                FlyoverHopFieldLayout, HbirdPathDataLayout, HbirdPathLayout, HbirdPathMetaLayout,
            },
            types::HbirdHopFieldFlags,
        },
        standard::{
            layout::{HopFieldLayout, InfoFieldLayout},
            types::{HopFieldMac, InfoFieldFlags, StdHopFieldFlags},
            view::{HopFieldView, InfoFieldView},
        },
    },
};

/// A view over a Hummingbird SCION path, including meta header and data
#[repr(transparent)]
pub struct HbirdPathView([u8]);
gen_view_impl!(HbirdPathView, HbirdPathLayout);

// Meta header
impl HbirdPathView {
    gen_field_read!(
        curr_info_field,
        HbirdPathMetaLayout::CURR_INFO_FIELD_RNG,
        u8
    );
    gen_field_read!(curr_hop_field, HbirdPathMetaLayout::CURR_HOP_FIELD_RNG, u8);
    gen_field_read!(seg0_len, HbirdPathMetaLayout::SEG0_LEN_RNG, u8);
    gen_field_read!(seg1_len, HbirdPathMetaLayout::SEG1_LEN_RNG, u8);
    gen_field_read!(seg2_len, HbirdPathMetaLayout::SEG2_LEN_RNG, u8);
    gen_field_read!(base_timestamp, HbirdPathMetaLayout::BASE_TIMESTAMP_RNG, u32);
    gen_field_read!(
        millis_timestamp,
        HbirdPathMetaLayout::MILLIS_TIMESTAMP_RNG,
        u16
    );
    gen_field_read!(counter, HbirdPathMetaLayout::COUNTER_RNG, u32);

    /// Returns the number of info fields present in the path
    #[inline]
    pub fn info_field_count(&self) -> u8 {
        (self.seg0_len() > 0) as u8 + (self.seg1_len() > 0) as u8 + (self.seg2_len() > 0) as u8
    }

    /// Returns the length of the first segment in bytes.
    #[inline]
    pub fn seg0_len_bytes(&self) -> u16 {
        self.seg0_len() as u16 * 4
    }

    /// Returns the length of the second segment in bytes.
    #[inline]
    pub fn seg1_len_bytes(&self) -> u16 {
        self.seg1_len() as u16 * 4
    }

    /// Returns the length of the third segment in bytes.
    #[inline]
    pub fn seg2_len_bytes(&self) -> u16 {
        self.seg2_len() as u16 * 4
    }

    /// Returns the total length of all segments in bytes.
    #[inline]
    pub fn total_seg_len_bytes(&self) -> u16 {
        self.seg0_len_bytes() + self.seg1_len_bytes() + self.seg2_len_bytes()
    }
}

// Meta header mut
impl HbirdPathView {
    gen_field_write!(
        set_curr_info_field,
        HbirdPathMetaLayout::CURR_INFO_FIELD_RNG,
        u8
    );
    gen_field_write!(
        set_curr_hop_field,
        HbirdPathMetaLayout::CURR_HOP_FIELD_RNG,
        u8
    );
    gen_unsafe_field_write!(set_seg0_len, HbirdPathMetaLayout::SEG0_LEN_RNG, u8);
    gen_unsafe_field_write!(set_seg1_len, HbirdPathMetaLayout::SEG1_LEN_RNG, u8);
    gen_unsafe_field_write!(set_seg2_len, HbirdPathMetaLayout::SEG2_LEN_RNG, u8);
    gen_field_write!(
        set_base_timestamp,
        HbirdPathMetaLayout::BASE_TIMESTAMP_RNG,
        u32
    );
    gen_unsafe_field_write!(
        set_millis_timestamp,
        HbirdPathMetaLayout::MILLIS_TIMESTAMP_RNG,
        u16
    );
    gen_unsafe_field_write!(set_counter, HbirdPathMetaLayout::COUNTER_RNG, u32);
}

// Data Helpers
impl HbirdPathView {
    /// Returns the byte range for the info field at the given index, or None if
    /// the index is out of bounds
    #[inline]
    fn checked_info_field_range(&self, index: usize) -> Option<Range<usize>> {
        let info_field_count = self.info_field_count() as usize;
        if index >= info_field_count {
            return None;
        }

        Some(
            HbirdPathDataLayout::new(
                self.seg0_len() as usize * 4,
                self.seg1_len() as usize * 4,
                self.seg2_len() as usize * 4,
            )
            .info_field_range(index)
            .shift(HbirdPathMetaLayout::SIZE_BYTES)
            .aligned_byte_range(),
        )
    }

    /// Returns the byte range for the hop field at the given byte_offset, or None
    /// if the index is out of bounds.
    ///
    /// The byte offset is taken to be relative to the start of the hop fields,
    /// i.e., the first hop field has byte offset 0.
    ///
    /// The range depends on whether the hop field is a flyover hop field or
    /// not.
    #[inline]
    pub fn checked_hop_field_range(&self, byte_offset: usize) -> Option<Range<usize>> {
        let start = self.info_field_count() as usize * InfoFieldLayout::SIZE_BYTES
            + HbirdPathMetaLayout::SIZE_BYTES
            + byte_offset;

        let is_flyover = self.is_flyover_checked(byte_offset)?;

        // Check if the entire hop field is within bounds (use range to avoid off-by-one
        // when the field ends exactly at the buffer boundary)
        let _ = if is_flyover {
            self.0.get(start..start + FlyoverHopFieldLayout::SIZE_BYTES)
        } else {
            self.0.get(start..start + HopFieldLayout::SIZE_BYTES)
        }?;

        Some(
            HbirdPathDataLayout::new(
                self.seg0_len_bytes() as usize,
                self.seg1_len_bytes() as usize,
                self.seg2_len_bytes() as usize,
            )
            .hop_field_range(byte_offset, is_flyover)
            .shift(HbirdPathMetaLayout::SIZE_BYTES)
            .aligned_byte_range(),
        )
    }

    /// Returns whether the hop field at the given byte offset is a flyover hop
    /// field or not.
    /// The byte offset is taken to be relative to the start of the first hop
    /// field.
    pub fn is_flyover_checked(&self, byte_offset: usize) -> Option<bool> {
        debug_assert!(byte_offset.is_multiple_of(4));

        let base = HbirdPathMetaLayout::SIZE_BYTES
            + self.info_field_count() as usize * InfoFieldLayout::SIZE_BYTES;

        Some(*self.0.get(base + byte_offset)? & HbirdHopFieldFlags::FLYOVER.bits() != 0)
    }
}

// Data
impl HbirdPathView {
    /// Returns a view over the info field at the given index, or None if the index is out of bounds
    #[inline]
    pub fn info_field(&self, index: usize) -> Option<&InfoFieldView> {
        let field_range = self.checked_info_field_range(index)?;

        // SAFETY:
        // - index is checked to be less than field count
        // - AddressHeaderView can only be created if buf is at least as large as indicated by field
        //   count
        let field =
            unsafe { InfoFieldView::from_slice_unchecked(self.0.get_unchecked(field_range)) };

        Some(field)
    }

    /// Returns the index of the hop field at the given byte offset.
    pub fn hop_field_index(&self, byte_offset: usize) -> Option<usize> {
        let mut curr_offset = 0;
        let mut curr_idx = 0;

        while curr_offset < byte_offset {
            let field_size = if self.is_flyover_checked(curr_offset)? {
                FlyoverHopFieldLayout::SIZE_BYTES
            } else {
                HopFieldLayout::SIZE_BYTES
            };

            curr_offset += field_size;
            curr_idx += 1;
        }

        if curr_offset == byte_offset {
            Some(curr_idx)
        } else {
            None
        }
    }

    /// Returns a view over the hop field at the given byte offset, or None if the
    /// byte offset is out of bounds
    #[inline]
    pub fn hop_field(
        &self,
        byte_offset: usize,
    ) -> Option<HbirdHopFieldView<&HopFieldView, &FlyoverHopFieldView>> {
        let field_range = self.checked_hop_field_range(byte_offset)?;

        // SAFETY:
        // - field_range is checked to be within bounds of self.0
        // - AddressHeaderView can only be created if buf is at least as large as
        //   indicated by field count
        if field_range.len() == FlyoverHopFieldLayout::SIZE_BYTES {
            Some(HbirdHopFieldView::from_flyover(unsafe {
                FlyoverHopFieldView::from_slice_unchecked(self.0.get_unchecked(field_range))
            }))
        } else {
            Some(HbirdHopFieldView::from_standard(unsafe {
                HopFieldView::from_slice_unchecked(self.0.get_unchecked(field_range))
            }))
        }
    }

    /// Returns a view over all info fields
    #[inline]
    pub fn info_fields(&self) -> &[InfoFieldView] {
        let layout = HbirdPathDataLayout::new(
            self.seg0_len() as usize * 4,
            self.seg1_len() as usize * 4,
            self.seg2_len() as usize * 4,
        );

        let info_fields_range = layout
            .info_fields_range()
            .shift(HbirdPathMetaLayout::SIZE_BYTES)
            .aligned_byte_range();

        // SAFETY: buffer size is checked on construction
        let slice = unsafe { self.0.get_unchecked(info_fields_range) };

        debug_assert!(slice.len() == layout.info_field_count() * InfoFieldLayout::SIZE_BYTES);

        // SAFETY: InfoFieldView is #[repr(transparent)] over [u8; SIZE_BYTES], as such the cast is
        // safe
        unsafe {
            std::slice::from_raw_parts(
                slice.as_ptr() as *const InfoFieldView,
                layout.info_field_count(),
            )
        }
    }

    /// Returns a view over all hop fields
    #[inline]
    pub fn hop_fields(
        &self,
    ) -> impl Iterator<Item = HbirdHopFieldView<&HopFieldView, &FlyoverHopFieldView>> {
        let total_seg_bytes = self.seg0_len_bytes() as usize
            + self.seg1_len_bytes() as usize
            + self.seg2_len_bytes() as usize;

        // Iterate relative byte offsets (0..total_seg_bytes); scan yields a hop field only when
        // the offset matches the expected start of the next hop field.
        (0..total_seg_bytes)
            .scan(0usize, move |next_hf_start, byte_offset| {
                if byte_offset != *next_hf_start {
                    return Some(None);
                }

                let field = self.hop_field(byte_offset)?;
                *next_hf_start += field.size_bytes();

                Some(Some(field))
            })
            .flatten()
    }
}
// Data mut
impl HbirdPathView {
    /// Returns a view over the info field at the given index, or None if the index is out of bounds
    #[inline]
    pub fn info_field_mut(&mut self, index: usize) -> Option<&mut InfoFieldView> {
        let field_range = self.checked_info_field_range(index)?;

        // SAFETY:
        // - index is checked to be less than field count
        // - AddressHeaderView can only be created if buf is at least as large as indicated by field
        //   count
        let field = unsafe {
            InfoFieldView::from_mut_slice_unchecked(self.0.get_unchecked_mut(field_range))
        };

        Some(field)
    }

    /// Returns a view over the hop field at the given byte offset, or None if the
    /// byte offset is out of bounds
    #[inline]
    pub fn hop_field_mut(
        &mut self,
        byte_offset: usize,
    ) -> Option<HbirdHopFieldView<&mut HopFieldView, &mut FlyoverHopFieldView>> {
        let field_range = self.checked_hop_field_range(byte_offset)?;

        // SAFETY:
        // - field_range is checked to be within bounds of self.0
        // - AddressHeaderView can only be created if buf is at least as large as
        //   indicated by field count
        if field_range.len() == FlyoverHopFieldLayout::SIZE_BYTES {
            Some(HbirdHopFieldView::from_flyover(unsafe {
                FlyoverHopFieldView::from_mut_slice_unchecked(self.0.get_unchecked_mut(field_range))
            }))
        } else {
            Some(HbirdHopFieldView::from_standard(unsafe {
                HopFieldView::from_mut_slice_unchecked(self.0.get_unchecked_mut(field_range))
            }))
        }
    }

    /// Returns a view over all info fields
    #[inline]
    pub fn info_fields_mut(&mut self) -> &mut [InfoFieldView] {
        let layout = HbirdPathDataLayout::new(
            self.seg0_len() as usize * 4,
            self.seg1_len() as usize * 4,
            self.seg2_len() as usize * 4,
        );

        let info_fields_range = layout
            .info_fields_range()
            .shift(HbirdPathMetaLayout::SIZE_BYTES)
            .aligned_byte_range();

        // SAFETY: buffer size is checked on construction
        let slice = unsafe { self.0.get_unchecked_mut(info_fields_range) };

        debug_assert!(slice.len() == layout.info_field_count() * InfoFieldLayout::SIZE_BYTES);

        // SAFETY: InfoFieldView is #[repr(transparent)] over [u8; SIZE_BYTES], as such the cast is
        // safe
        unsafe {
            std::slice::from_raw_parts_mut(
                slice.as_mut_ptr() as *mut InfoFieldView,
                layout.info_field_count(),
            )
        }
    }
}

impl Debug for HbirdPathView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hop_fields = self.hop_fields();
        let info_fields = self.info_fields();
        f.debug_struct("StandardPathMetaHeaderView")
            .field("current_info_field", &self.curr_info_field())
            .field("curr_hop_field", &self.curr_hop_field())
            .field("seg0_len", &self.seg0_len())
            .field("seg1_len", &self.seg1_len())
            .field("seg2_len", &self.seg2_len())
            .field("info_fields", &info_fields)
            .field("hop_fields", &hop_fields.collect::<Vec<_>>())
            .finish()
    }
}

/// A view over a Hummingbird SCION path hop field
#[derive(Debug, Clone)]
pub enum HbirdHopFieldView<HopFieldViewRef, FlyoverHopFieldViewRef>
where
    HopFieldViewRef: Deref<Target = HopFieldView>,
    FlyoverHopFieldViewRef: Deref<Target = FlyoverHopFieldView>,
{
    /// A standard hop field.
    Standard(HopFieldViewRef),
    /// A flyover hop field.
    Flyover(FlyoverHopFieldViewRef),
}

impl<HFR, FHFR> HbirdHopFieldView<HFR, FHFR>
where
    HFR: Deref<Target = HopFieldView>,
    FHFR: Deref<Target = FlyoverHopFieldView>,
{
    /// Returns whether this is a flyover hop field.
    pub fn is_flyover(&self) -> bool {
        match self {
            HbirdHopFieldView::Standard(_) => false,
            HbirdHopFieldView::Flyover(_) => true,
        }
    }

    /// Converts a standard hop field view to a Hummingbird hop field view.
    #[inline]
    pub fn from_standard(view: HFR) -> Self {
        HbirdHopFieldView::Standard(view)
    }

    /// Converts a flyover hop field view to a Hummingbird hop field view.
    #[inline]
    pub fn from_flyover(view: FHFR) -> Self {
        HbirdHopFieldView::Flyover(view)
    }

    /// Returns the length of the hop field in bytes.
    #[inline]
    pub fn size_bytes(&self) -> usize {
        match self {
            HbirdHopFieldView::Standard(_) => HopFieldLayout::SIZE_BYTES,
            HbirdHopFieldView::Flyover(_) => FlyoverHopFieldLayout::SIZE_BYTES,
        }
    }
}

// Immutable
impl<HFR, FHFR> HbirdHopFieldView<HFR, FHFR>
where
    HFR: Deref<Target = HopFieldView>,
    FHFR: Deref<Target = FlyoverHopFieldView>,
{
    /// Returns the flags of the hop field
    #[inline]
    pub fn std_flags(&self) -> StdHopFieldFlags {
        match self {
            HbirdHopFieldView::Standard(v) => v.flags(),
            HbirdHopFieldView::Flyover(v) => v.flags().into(),
        }
    }

    /// Returns the expiration time of the hop field
    #[inline]
    pub fn exp_time(&self) -> u8 {
        match self {
            HbirdHopFieldView::Standard(v) => v.exp_time(),
            HbirdHopFieldView::Flyover(v) => v.exp_time(),
        }
    }

    /// Returns the cons_ingress field of the hop field
    #[inline]
    pub fn cons_ingress(&self) -> u16 {
        match self {
            HbirdHopFieldView::Standard(v) => v.cons_ingress(),
            HbirdHopFieldView::Flyover(v) => v.cons_ingress(),
        }
    }

    /// Returns the cons_egress field of the hop field
    #[inline]
    pub fn cons_egress(&self) -> u16 {
        match self {
            HbirdHopFieldView::Standard(v) => v.cons_egress(),
            HbirdHopFieldView::Flyover(v) => v.cons_egress(),
        }
    }

    /// Returns the ingress interface in the direction the packet is travelling.
    ///
    /// Reads `cons_ingress` when the `CONS_DIR` flag is set on `info_field`, and
    /// `cons_egress` otherwise (reversed segment).
    #[inline]
    pub fn ingress_interface(&self, info_field: &InfoFieldView) -> u16 {
        match self {
            HbirdHopFieldView::Standard(v) => v.ingress_interface(info_field),
            HbirdHopFieldView::Flyover(v) => v.ingress_interface(info_field),
        }
    }

    /// Returns the egress interface in the direction the packet is travelling.
    ///
    /// Reads `cons_egress` when the `CONS_DIR` flag is set on `info_field`, and
    /// `cons_ingress` otherwise (reversed segment).
    #[inline]
    pub fn egress_interface(&self, info_field: &InfoFieldView) -> u16 {
        match self {
            HbirdHopFieldView::Standard(v) => v.egress_interface(info_field),
            HbirdHopFieldView::Flyover(v) => v.egress_interface(info_field),
        }
    }

    /// Returns the MAC of the hop field
    #[inline]
    pub fn mac(&self) -> HopFieldMac {
        match self {
            HbirdHopFieldView::Standard(v) => v.mac(),
            HbirdHopFieldView::Flyover(v) => v.mac(),
        }
    }

    /// Returns the reservation ID of the hop field, or None if this is not a
    /// flyover hop field.  
    #[inline]
    pub fn res_id(&self) -> Option<u32> {
        match self {
            HbirdHopFieldView::Standard(_) => None,
            HbirdHopFieldView::Flyover(v) => Some(v.res_id()),
        }
    }

    /// Returns the reserved bandwidth of the hop field, or None if this is not a
    /// flyover hop field.
    #[inline]
    pub fn res_bw(&self) -> Option<u16> {
        match self {
            HbirdHopFieldView::Standard(_) => None,
            HbirdHopFieldView::Flyover(v) => Some(v.res_bw()),
        }
    }

    /// Returns the reservation start offset of the hop field, or None if this is not a
    /// flyover hop field.
    #[inline]
    pub fn res_start_offset(&self) -> Option<u16> {
        match self {
            HbirdHopFieldView::Standard(_) => None,
            HbirdHopFieldView::Flyover(v) => Some(v.res_start_offset()),
        }
    }
}

// Mutable
impl<HFR, FHFR> HbirdHopFieldView<HFR, FHFR>
where
    HFR: DerefMut<Target = HopFieldView>,
    FHFR: DerefMut<Target = FlyoverHopFieldView>,
{
    /// Sets the flags of the hop field
    #[inline]
    pub fn set_flags(&mut self, flags: StdHopFieldFlags) {
        match self {
            HbirdHopFieldView::Standard(v) => v.set_flags(flags),
            HbirdHopFieldView::Flyover(v) => v.set_flags(flags),
        }
    }

    /// Sets the expiration time of the hop field
    #[inline]
    pub fn set_exp_time(&mut self, exp_time: u8) {
        match self {
            HbirdHopFieldView::Standard(v) => v.set_exp_time(exp_time),
            HbirdHopFieldView::Flyover(v) => v.set_exp_time(exp_time),
        }
    }

    /// Sets the cons_ingress field of the hop field
    #[inline]
    pub fn set_cons_ingress(&mut self, cons_ingress: u16) {
        match self {
            HbirdHopFieldView::Standard(v) => v.set_cons_ingress(cons_ingress),
            HbirdHopFieldView::Flyover(v) => v.set_cons_ingress(cons_ingress),
        }
    }

    /// Sets the cons_egress field of the hop field
    #[inline]
    pub fn set_cons_egress(&mut self, cons_egress: u16) {
        match self {
            HbirdHopFieldView::Standard(v) => v.set_cons_egress(cons_egress),
            HbirdHopFieldView::Flyover(v) => v.set_cons_egress(cons_egress),
        }
    }

    /// Sets the MAC of the hop field
    #[inline]
    pub fn set_mac(&mut self, mac: HopFieldMac) {
        match self {
            HbirdHopFieldView::Standard(v) => v.set_mac(mac),
            HbirdHopFieldView::Flyover(v) => v.set_mac(mac),
        }
    }
}

/// A view over a Hummingbird path flyover hop field
#[repr(transparent)]
pub struct FlyoverHopFieldView([u8; FlyoverHopFieldLayout::SIZE_BYTES]);
impl View for FlyoverHopFieldView {
    #[inline]
    fn has_required_size(buf: &[u8]) -> Result<usize, ViewConversionError> {
        if buf.len() < FlyoverHopFieldLayout::SIZE_BYTES {
            return Err(ViewConversionError::BufferTooSmall {
                at: "FlyoverHopFieldView",
                required: FlyoverHopFieldLayout::SIZE_BYTES,
                actual: buf.len(),
            });
        }

        Ok(FlyoverHopFieldLayout::SIZE_BYTES)
    }

    #[inline]
    unsafe fn from_slice_unchecked(buf: &[u8]) -> &Self {
        // SAFETY: see View trait documentation
        let sized: &[u8; FlyoverHopFieldLayout::SIZE_BYTES] =
            unsafe { buf.try_into().unwrap_unchecked() };
        unsafe { transmute(sized) }
    }

    #[inline]
    unsafe fn from_mut_slice_unchecked(buf: &mut [u8]) -> &mut Self {
        // SAFETY: see View trait documentation
        let sized: &mut [u8; FlyoverHopFieldLayout::SIZE_BYTES] =
            unsafe { buf.try_into().unwrap_unchecked() };
        unsafe { transmute(sized) }
    }

    #[inline]
    unsafe fn from_boxed_unchecked(buf: Box<[u8]>) -> Box<Self> {
        // SAFETY: see View trait documentation
        let sized: Box<[u8; FlyoverHopFieldLayout::SIZE_BYTES]> =
            unsafe { buf.try_into().unwrap_unchecked() };
        unsafe { transmute(sized) }
    }

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[inline]
    unsafe fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    #[inline]
    fn as_bytes_boxed(self: Box<Self>) -> Box<[u8]> {
        // SAFETY: repr(transparent) over [u8; N]
        let sized: Box<[u8; FlyoverHopFieldLayout::SIZE_BYTES]> = unsafe { transmute(self) };
        sized
    }
}

// Immutable
impl FlyoverHopFieldView {
    /// Returns the flags of the hop field
    #[inline]
    pub fn flags(&self) -> StdHopFieldFlags {
        // SAFETY: buffer size is checked on construction
        let value =
            unsafe { unchecked_bit_range_be_read::<u8>(&self.0, FlyoverHopFieldLayout::FLAGS_RNG) };

        // Mask out flyover bit to get standard flags
        let value = value & !HbirdHopFieldFlags::FLYOVER.bits();

        StdHopFieldFlags::from_bits_retain(value)
    }

    gen_field_read!(exp_time, HopFieldLayout::EXP_TIME_RNG, u8);
    gen_field_read!(cons_ingress, HopFieldLayout::CONS_INGRESS_RNG, u16);
    gen_field_read!(cons_egress, HopFieldLayout::CONS_EGRESS_RNG, u16);
    gen_field_read!(res_id, FlyoverHopFieldLayout::RES_ID_RNG, u32);
    gen_field_read!(res_bw, FlyoverHopFieldLayout::BW_RANGE, u16);
    gen_field_read!(
        res_start_offset,
        FlyoverHopFieldLayout::RES_START_OFFSET_RNG,
        u16
    );
    gen_field_read!(res_duration, FlyoverHopFieldLayout::RES_DURATION_RNG, u16);

    /// Returns the MAC of the hop field
    #[inline]
    pub fn mac(&self) -> HopFieldMac {
        // SAFETY: buffer size is checked on construction
        let mac: [u8; 6] = unsafe {
            self.0
                .get_unchecked(FlyoverHopFieldLayout::MAC_RNG.aligned_byte_range())
                .try_into()
                .unwrap_unchecked()
        };

        HopFieldMac(mac)
    }

    /// Returns the ingress interface in the direction the packet is travelling.
    ///
    /// Reads `cons_ingress` when the `CONS_DIR` flag is set on `info_field`, and
    /// `cons_egress` otherwise (reversed segment).
    #[inline]
    pub fn ingress_interface(&self, info_field: &InfoFieldView) -> u16 {
        if info_field.flags().contains(InfoFieldFlags::CONS_DIR) {
            self.cons_ingress()
        } else {
            self.cons_egress()
        }
    }

    /// Returns the egress interface in the direction the packet is travelling.
    ///
    /// Reads `cons_egress` when the `CONS_DIR` flag is set on `info_field`, and
    /// `cons_ingress` otherwise (reversed segment).
    #[inline]
    pub fn egress_interface(&self, info_field: &InfoFieldView) -> u16 {
        if info_field.flags().contains(InfoFieldFlags::CONS_DIR) {
            self.cons_egress()
        } else {
            self.cons_ingress()
        }
    }
}
// Mutable
impl FlyoverHopFieldView {
    /// Sets the flags of the hop field
    #[inline]
    pub fn set_flags(&mut self, flags: StdHopFieldFlags) {
        // SAFETY: buffer size is checked on construction
        // Preserve the FLYOVER bit — it is structural, not a user-settable flag.
        let value = flags.bits() | HbirdHopFieldFlags::FLYOVER.bits();
        unsafe {
            unchecked_bit_range_be_write::<u8>(&mut self.0, FlyoverHopFieldLayout::FLAGS_RNG, value)
        }
    }

    gen_field_write!(set_exp_time, HopFieldLayout::EXP_TIME_RNG, u8);
    gen_field_write!(set_cons_ingress, HopFieldLayout::CONS_INGRESS_RNG, u16);
    gen_field_write!(set_cons_egress, HopFieldLayout::CONS_EGRESS_RNG, u16);
    gen_field_write!(set_res_id, FlyoverHopFieldLayout::RES_ID_RNG, u32);
    gen_field_write!(set_res_bw, FlyoverHopFieldLayout::BW_RANGE, u16);
    gen_field_write!(
        set_res_start_offset,
        FlyoverHopFieldLayout::RES_START_OFFSET_RNG,
        u16
    );
    gen_field_write!(
        set_res_duration,
        FlyoverHopFieldLayout::RES_DURATION_RNG,
        u16
    );

    /// Sets the MAC of the hop field
    #[inline]
    pub fn set_mac(&mut self, mac: HopFieldMac) {
        // SAFETY: buffer size is checked on construction
        unsafe {
            self.0
                .get_unchecked_mut(HopFieldLayout::MAC_RNG.aligned_byte_range())
                .copy_from_slice(&mac.0);
        }
    }
}
impl Debug for FlyoverHopFieldView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StandardPathHopFieldView")
            .field("flags", &self.flags())
            .field("exp_time", &self.exp_time())
            .field("cons_ingress", &self.cons_ingress())
            .field("cons_egress", &self.cons_egress())
            .field("mac", &self.mac())
            .field("res_id", &self.res_id())
            .field("res_bw", &self.res_bw())
            .field("res_start_offset", &self.res_start_offset())
            .field("res_duration", &self.res_duration())
            .finish()
    }
}
