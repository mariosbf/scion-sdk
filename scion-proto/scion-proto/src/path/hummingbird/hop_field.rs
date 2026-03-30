//! HopField and FlyoverHopField definitions and encoding/decoding logic.

use bytes::{Buf, BufMut, Bytes};
use chrono::{DateTime, Utc};
use std::{num::NonZeroU16, time::Duration};

use crate::{
    packet::{DecodeError, InadequateBufferSize},
    path::{
        EncodedHopField, EncodedInfoField, EncodedStandardHopField, HopField, InfoField,
        StandardHopField,
    },
    wire_encoding::{WireDecode, WireEncode},
};

/// A HopField when Hummingbird is used.
pub enum HummingbirdHopField {
    /// Regular hop field when a flyover is not reserved.
    Standard(StandardHopField),

    /// FlyoverHopField used in Hummingbird paths when there is a reservation
    /// for a flyover.
    Flyover(FlyoverHopField),
}

impl HopField for HummingbirdHopField {
    fn interfaces(&self, is_construction_dir: bool) -> (u16, u16) {
        match self {
            Self::Standard(hop_field) => hop_field.interfaces(is_construction_dir),
            Self::Flyover(flyover_hop_field) => flyover_hop_field.interfaces(is_construction_dir),
        }
    }

    fn alerts(&self, is_construction_dir: bool) -> (bool, bool) {
        match self {
            Self::Standard(hop_field) => hop_field.alerts(is_construction_dir),
            Self::Flyover(flyover_hop_field) => flyover_hop_field.alerts(is_construction_dir),
        }
    }

    fn expiry_offset(&self) -> Duration {
        match self {
            Self::Standard(hop_field) => hop_field.expiry_offset(),
            Self::Flyover(flyover_hop_field) => flyover_hop_field.expiry_offset(),
        }
    }

    fn expiry_time(&self, info_field: &InfoField) -> DateTime<Utc> {
        match self {
            Self::Standard(hop_field) => hop_field.expiry_time(info_field),
            Self::Flyover(flyover_hop_field) => flyover_hop_field.expiry_time(info_field),
        }
    }
}

impl WireDecode<Bytes> for HummingbirdHopField {
    type Error = DecodeError;

    fn decode(data: &mut Bytes) -> Result<Self, Self::Error> {
        // Peek at first byte
        let flags = *data
            .iter()
            .next()
            .ok_or(Self::Error::PacketEmptyOrTruncated)?;

        if flags & FlyoverHopField::FLYOVER_BIT == 0 {
            // Regular hop field.
            Ok(Self::Standard(StandardHopField::decode(data)?))
        } else {
            // Flyover hop field.
            Ok(Self::Flyover(FlyoverHopField::decode(data)?))
        }
    }
}

impl WireEncode for HummingbirdHopField {
    type Error = InadequateBufferSize;

    fn encoded_length(&self) -> usize {
        match self {
            Self::Standard(hop_field) => hop_field.encoded_length(),
            Self::Flyover(flyover_hop_field) => flyover_hop_field.encoded_length(),
        }
    }

    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        match self {
            Self::Standard(hop_field) => hop_field.encode_to_unchecked(buffer),
            Self::Flyover(flyover_hop_field) => flyover_hop_field.encode_to_unchecked(buffer),
        }
    }
}

/// A view into a Hummingbird path hop field.
#[repr(transparent)]
#[derive(Debug, PartialEq, Eq)]
pub struct EncodedHummingbirdHopField {
    inner: [u8],
}

impl EncodedHummingbirdHopField {
    /// Checks whether the flyover bit is set.
    pub fn is_flyover(&self) -> bool {
        self.inner[0] & FlyoverHopField::FLYOVER_BIT != 0
    }

    /// Checks whether the flyover bit is set in the first byte. If it is set, the
    /// lenth of the data must be equal to the encoded size of a FlyoverHop
    /// field, otherwise it must be equal to the encoded size of a StandardHopField.
    /// Panics if these conditions are not met.
    fn assert_length(&self) {
        assert!(!self.inner.is_empty());

        assert!(if self.is_flyover() {
            self.inner.len() == FlyoverHopField::ENCODED_SIZE
        } else {
            self.inner.len() == StandardHopField::ENCODED_SIZE
        });
    }
}

macro_rules! dispatch_to_correct_encoding {
    (fn $method_name:ident(&self $(, $arg_name:ident : $arg_type:ty)*) $(-> $return_type:ty)?) => {
        fn $method_name(&self $(, $arg_name : $arg_type)*) $(-> $return_type)? {
            if self.is_flyover() {
                EncodedFlyoverHopField::new(&self.inner).$method_name($($arg_name),*)
            } else {
                EncodedStandardHopField::new(&self.inner).$method_name($($arg_name),*)
            }
        }
    };
    (fn $method_name:ident(&mut self $(, $arg_name:ident : $arg_type:ty)*) $(-> $return_type:ty)?) => {
        fn $method_name(&mut self $(, $arg_name : $arg_type)*) $(-> $return_type)? {
            if self.is_flyover() {
                EncodedFlyoverHopField::new_mut(&mut self.inner).$method_name($($arg_name),*)
            } else {
                EncodedStandardHopField::new_mut(&mut self.inner).$method_name($($arg_name),*)
            }
        }
    }
}

impl EncodedHopField for EncodedHummingbirdHopField {
    /// Creates a new view into a Hummingbird path hop field.
    ///
    /// # Panics
    /// Checks whether the flyover bit is set in the first byte. If it is set, the
    /// lenth of the data must be equal to the encoded size of a FlyoverHopField,
    /// otherwise it must be equal to the encoded size of a StandardHopField.
    /// Panics if these conditions are not met.
    fn new(data: &[u8]) -> &Self {
        let result = unsafe { &*(data as *const [u8] as *const Self) };
        result.assert_length();

        result
    }

    /// Creates a mutable view into a Hummingbird path hop field.
    ///
    /// # Panics
    /// Checks whether the flyover bit is set in the first byte. If it is set, the
    /// lenth of the data must be equal to the encoded size of a FlyoverHopField,
    /// otherwise it must be equal to the encoded size of a StandardHopField.
    /// Panics if these conditions are not met.
    fn new_mut(data: &mut [u8]) -> &mut Self {
        let result = unsafe { &mut *(data as *mut [u8] as *mut Self) };
        result.assert_length();

        result
    }

    dispatch_to_correct_encoding!(
        fn is_cons_ingress_router_alert(&self) -> bool
    );

    dispatch_to_correct_encoding!(
        fn is_cons_egress_router_alert(&self) -> bool
    );

    dispatch_to_correct_encoding!(
        fn set_cons_egress_router_alert(&mut self, enable: bool)
    );

    dispatch_to_correct_encoding!(
        fn set_cons_ingress_router_alert(&mut self, enable: bool)
    );

    dispatch_to_correct_encoding!(
        fn cons_ingress_interface(&self) -> Option<NonZeroU16>
    );

    dispatch_to_correct_encoding!(
        fn cons_egress_interface(&self) -> Option<NonZeroU16>
    );

    dispatch_to_correct_encoding!(
        fn ingress_interface(&self, info_field: &EncodedInfoField) -> Option<NonZeroU16>
    );

    dispatch_to_correct_encoding!(
        fn egress_interface(&self, info_field: &EncodedInfoField) -> Option<NonZeroU16>
    );

    dispatch_to_correct_encoding!(
        fn expiry_offset(&self) -> Duration
    );

    dispatch_to_correct_encoding!(
        fn expiry_time(&self, info_field: &EncodedInfoField) -> DateTime<Utc>
    );
}

impl<'a> TryFrom<&'a EncodedHummingbirdHopField> for &'a EncodedStandardHopField {
    // Note(mariosbf): We could create a specific Error type for this, but
    // the default use is probably to check if the flyover bit is set, before
    // converting and calling expect.
    type Error = &'static str;

    fn try_from(value: &'a EncodedHummingbirdHopField) -> Result<Self, Self::Error> {
        if value.is_flyover() {
            Err("Cannot convert a flyover hop field to a standard hop field")
        } else {
            Ok(EncodedStandardHopField::new(&value.inner))
        }
    }
}

impl<'a> TryFrom<&'a EncodedHummingbirdHopField> for &'a EncodedFlyoverHopField {
    // Note(mariosbf): We could create a specific Error type for this, but
    // the default use is probably to check if the flyover bit is set, before
    // converting and calling expect.
    type Error = &'static str;

    fn try_from(value: &'a EncodedHummingbirdHopField) -> Result<Self, Self::Error> {
        if value.is_flyover() {
            Err("Cannot convert a standard hop field to a flyover hop field")
        } else {
            Ok(EncodedFlyoverHopField::new(&value.inner))
        }
    }
}

/// FlyoverHopField is the hop field used for Hummingbird paths when
/// there is a reservation.
///
/// FlyoverHopFields have the following format:
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |r r r r r r I E|    ExpTime    |           ConsIngress         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        ConsEgress             |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
/// |                              MAC                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   ResID                   |        BW         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        ResStartOffset         |         ResDuration           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Default, Clone)]
pub struct FlyoverHopField {
    /// IngressRouterAlert flag. If the IngressRouterAlert is set, the ingress
    /// router (in construction direction) will process the L4 payload in the
    /// packet.
    pub ingress_router_alert: bool,

    /// EgressRouterAlert flag. If the EgressRouterAlert is set, the egress router
    /// (in construction direction) will process the L4 payload in the packet.
    pub egress_router_alert: bool,

    /// Exptime is the expiry time of a FlyoverHopField. The field is 1-byte long,
    /// thus there are 256 different values available to express an expiration
    /// time. The expiration time expressed by the value of this field is
    /// relative, and an absolute expiration time in seconds is computed
    /// in combination with the timestamp field (from the corresponding info
    /// field) as follows: Timestamp + (1 + ExpTime) * (24*60*60)/256
    pub exp_time: u8,

    /// ConsIngress is the ingress interface ID in construction direction.
    pub cons_ingress: u16,

    /// ConsEgress is the egress interface ID in construction direction.
    pub cons_egress: u16,

    /// Mac is the 6-byte Message Authentication Code to authenticate the HopField.
    /// Note: MAC calculation for FlyoverHopFields is different from that of  
    /// regular HopFields, as it also includes reservation information.
    pub aggregated_mac: [u8; 6],

    /// ResID ist the 22-bit reservation ID of the reservation being used by
    /// this FlyoverHopField.
    pub res_id: u32,

    /// ResBW is a 10-bit representation of the bandwidth of the reservation
    /// being used by this FlyoverHopField.
    /// TODO: Is the encoding fixed yet?
    pub res_bw: u16,

    /// ResStartOffset is the 16-bit offset in seconds between the BaseTimestamp
    /// of the path meta header and the the start of the reservation being used
    /// by this FlyoverHopField.
    pub res_start_offset: u16,

    /// ResDuration is the 16-bit duration in seconds of the reservation being used
    /// by this FlyoverHopField.
    pub res_duration: u16,
}

impl FlyoverHopField {
    /// The encoded size of a FlyoverHopField.
    pub const ENCODED_SIZE: usize = 20;

    pub(super) const FLAGS_EGRESS_ROUTER_ALERT: u8 = StandardHopField::FLAGS_EGRESS_ROUTER_ALERT;
    pub(super) const FLAGS_INGRESS_ROUTER_ALERT: u8 = StandardHopField::FLAGS_INGRESS_ROUTER_ALERT;
    pub(super) const FLYOVER_BIT: u8 = 0b1000_0000;

    pub(super) const DURATION_PER_EXP_UNIT: Duration = StandardHopField::DURATION_PER_EXP_UNIT;
}

impl HopField for FlyoverHopField {
    fn interfaces(&self, is_construction_dir: bool) -> (u16, u16) {
        if is_construction_dir {
            (self.cons_ingress, self.cons_egress)
        } else {
            (self.cons_egress, self.cons_ingress)
        }
    }

    fn alerts(&self, is_construction_dir: bool) -> (bool, bool) {
        if is_construction_dir {
            (self.ingress_router_alert, self.egress_router_alert)
        } else {
            (self.egress_router_alert, self.ingress_router_alert)
        }
    }

    fn expiry_offset(&self) -> Duration {
        Self::DURATION_PER_EXP_UNIT * (1 + self.exp_time as u32)
    }

    fn expiry_time(&self, info_field: &InfoField) -> DateTime<Utc> {
        info_field.timestamp() + self.expiry_offset()
    }
}

impl WireEncode for FlyoverHopField {
    type Error = InadequateBufferSize;

    fn encoded_length(&self) -> usize {
        Self::ENCODED_SIZE
    }

    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        let mut flags: u8 = 0;
        flags |= Self::FLYOVER_BIT;
        if self.ingress_router_alert {
            flags |= Self::FLAGS_INGRESS_ROUTER_ALERT;
        }
        if self.egress_router_alert {
            flags |= Self::FLAGS_EGRESS_ROUTER_ALERT;
        }
        buffer.put_u8(flags);
        buffer.put_u8(self.exp_time);
        buffer.put_u16(self.cons_ingress);
        buffer.put_u16(self.cons_egress);
        buffer.put_slice(&self.aggregated_mac);
        let res_id_and_bw = ((self.res_id & 0x3FFFFF) << 10) | (self.res_bw & 0x3FF) as u32;
        buffer.put_u32(res_id_and_bw);
        buffer.put_u16(self.res_start_offset);
        buffer.put_u16(self.res_duration);
    }
}

impl WireDecode<Bytes> for FlyoverHopField {
    type Error = DecodeError;

    fn decode(data: &mut Bytes) -> Result<Self, Self::Error> {
        if data.remaining() < Self::ENCODED_SIZE {
            return Err(Self::Error::PacketEmptyOrTruncated);
        }

        let flags = data.get_u8();
        let ingress_router_alert = flags & Self::FLAGS_INGRESS_ROUTER_ALERT != 0;
        let egress_router_alert = flags & Self::FLAGS_EGRESS_ROUTER_ALERT != 0;

        // TODO: Handle non-flyover hop fields.

        let exp_time = data.get_u8();
        let cons_ingress = data.get_u16();
        let cons_egress = data.get_u16();
        let aggregated_mac = data.split_to(6).slice(..6).to_vec().try_into().unwrap();
        let res_id_and_bw = data.get_u32();
        let res_id = res_id_and_bw >> 10;
        let res_bw = (res_id_and_bw & 0x3FF) as u16;
        let res_start_offset = data.get_u16();
        let res_duration = data.get_u16();

        Ok(Self {
            ingress_router_alert,
            egress_router_alert,
            exp_time,
            cons_ingress,
            cons_egress,
            aggregated_mac,
            res_id,
            res_bw,
            res_start_offset,
            res_duration,
        })
    }
}

/// A Hummingbird path flyover hop field.
///
/// Contains information to be processed by SCION routers, such as path interfaces and
/// hop expiration time.
#[repr(transparent)]
#[derive(Debug, PartialEq, Eq)]
pub struct EncodedFlyoverHopField {
    inner: [u8],
}

impl EncodedFlyoverHopField {
    /// The length of a flyover hop field in bytes.
    const LENGTH: usize = FlyoverHopField::ENCODED_SIZE;
}

impl EncodedFlyoverHopField {
    /// Returns the reservation ID from the flyover hop field.
    pub fn reservation_id(&self) -> u32 {
        let res_id_and_bw = ((self.inner[12] as u32) << 24)
            | ((self.inner[13] as u32) << 16)
            | ((self.inner[14] as u32) << 8)
            | self.inner[15] as u32;
        res_id_and_bw >> 10
    }

    /// Returns the bandwidth from the flyover hop field.
    pub fn bandwidth(&self) -> u16 {
        let res_id_and_bw = ((self.inner[12] as u32) << 24)
            | ((self.inner[13] as u32) << 16)
            | ((self.inner[14] as u32) << 8)
            | self.inner[15] as u32;
        (res_id_and_bw & 0x3FF) as u16
    }

    /// Returns the reservation start offset from the flyover hop field.
    pub fn reservation_start_offset(&self) -> Duration {
        Duration::from_secs(((self.inner[16] as u64) << 8) | self.inner[17] as u64)
    }

    /// Returns the reservation duration from the flyover hop field.
    pub fn reservation_duration(&self) -> u16 {
        ((self.inner[18] as u16) << 8) | self.inner[19] as u16
    }
}

impl EncodedHopField for EncodedFlyoverHopField {
    fn new(data: &[u8]) -> &Self {
        assert_eq!(data.len(), Self::LENGTH);

        unsafe { &*(data as *const [u8] as *const Self) }
    }

    fn new_mut(data: &mut [u8]) -> &mut Self {
        assert_eq!(data.len(), StandardHopField::ENCODED_SIZE);
        unsafe { &mut *(data as *mut [u8] as *mut Self) }
    }

    fn is_cons_ingress_router_alert(&self) -> bool {
        (self.inner[0] & StandardHopField::FLAGS_INGRESS_ROUTER_ALERT) != 0
    }

    fn set_cons_ingress_router_alert(&mut self, enable: bool) {
        if enable {
            self.inner[0] |= StandardHopField::FLAGS_INGRESS_ROUTER_ALERT;
        } else {
            self.inner[0] &= !StandardHopField::FLAGS_INGRESS_ROUTER_ALERT;
        }
    }

    fn is_cons_egress_router_alert(&self) -> bool {
        (self.inner[0] & StandardHopField::FLAGS_EGRESS_ROUTER_ALERT) != 0
    }

    fn set_cons_egress_router_alert(&mut self, enable: bool) {
        if enable {
            self.inner[0] |= StandardHopField::FLAGS_EGRESS_ROUTER_ALERT;
        } else {
            self.inner[0] &= !StandardHopField::FLAGS_EGRESS_ROUTER_ALERT;
        }
    }

    fn cons_ingress_interface(&self) -> Option<NonZeroU16> {
        NonZeroU16::new(((self.inner[2] as u16) << 8) | self.inner[3] as u16)
    }

    fn cons_egress_interface(&self) -> Option<NonZeroU16> {
        NonZeroU16::new(((self.inner[4] as u16) << 8) | self.inner[5] as u16)
    }

    fn ingress_interface(&self, info_field: &EncodedInfoField) -> Option<NonZeroU16> {
        if info_field.is_constructed_dir() {
            self.cons_ingress_interface()
        } else {
            self.cons_egress_interface()
        }
    }

    fn egress_interface(&self, info_field: &EncodedInfoField) -> Option<NonZeroU16> {
        if info_field.is_constructed_dir() {
            self.cons_egress_interface()
        } else {
            self.cons_ingress_interface()
        }
    }

    fn expiry_offset(&self) -> Duration {
        StandardHopField::DURATION_PER_EXP_UNIT * (1 + self.inner[1] as u32)
    }

    fn expiry_time(&self, info_field: &EncodedInfoField) -> DateTime<Utc> {
        info_field.timestamp() + self.expiry_offset()
    }
}

impl AsRef<[u8]> for EncodedFlyoverHopField {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

/// Iterator over hop fields in a Hummingbird path.
pub struct HummingbirdHopFields<'a> {
    inner: &'a [u8],
}

impl<'a> HummingbirdHopFields<'a> {
    /// Creates a new iterator over hop fields in a Hummingbird path.
    pub fn new(data: &'a [u8]) -> Self {
        Self { inner: data }
    }
}

impl<'a> Iterator for HummingbirdHopFields<'a> {
    type Item = &'a EncodedFlyoverHopField;

    fn next(&mut self) -> Option<Self::Item> {
        if self.inner.is_empty() {
            return None;
        }

        let is_flyover = self.inner[0] & FlyoverHopField::FLYOVER_BIT != 0;

        #[allow(clippy::collapsible_else_if)]
        if is_flyover {
            // Flyover hop field.
            if self.inner.len() < FlyoverHopField::ENCODED_SIZE {
                None
            } else {
                let (current, rest) = self.inner.split_at(FlyoverHopField::ENCODED_SIZE);
                self.inner = rest;
                Some(EncodedFlyoverHopField::new(current))
            }
        } else {
            // Standard hop field.
            if self.inner.len() < StandardHopField::ENCODED_SIZE {
                None
            } else {
                let (current, rest) = self.inner.split_at(StandardHopField::ENCODED_SIZE);
                self.inner = rest;
                Some(EncodedFlyoverHopField::new(current))
            }
        }
    }
}
