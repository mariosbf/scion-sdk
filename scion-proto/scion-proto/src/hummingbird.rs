//! Hummingbird-specific types and functions.
//!
//! See also [path::hummingbird].

use bytes::{Buf, BufMut, Bytes};
use chrono::{DateTime, Duration, Utc};

use crate::{
    address::IsdAsn,
    packet::{DecodeError, InadequateBufferSize},
    path::hummingbird::{HbirdAuthKey, calculate_flyover_mac},
    wire_encoding::{WireDecode, WireEncode},
};

pub const MAX_FRESHNESS_TOLERANCE: i64 = 5;

/// Bandwidth for Hummingbird reservations.  
#[derive(Clone, PartialEq, Eq, Hash, Copy, Debug, Default)]
pub struct Bandwidth {
    /// Exponent
    exponent: u8,

    /// Significand
    significand: u8,
}

impl Bandwidth {
    /// The length of the bandwidth encoding in bits.
    pub const ENCODED_LENGTH: usize = 10;

    /// The number of bits used for the exponent in the bandwidth encoding.
    pub const EXPONENT_BITS: usize = 5;

    /// The number of bits used for the significand in the bandwidth encoding.
    pub const SIGNIFICAND_BITS: usize = Self::ENCODED_LENGTH - Self::EXPONENT_BITS;

    /// The maximum value of the bandwidth encoding, which is 2^10 - 1 = 1023.
    pub const MASK: u16 = (1 << Self::ENCODED_LENGTH) - 1;

    /// Creates a new Bandwidth from a given bandwidth in kbps. Returns an error
    /// if the bandwidth is too large to be represented in the 10-bit encoding.
    /// If the bandwidth cannot be represented in the 10-bit encoding, the
    /// function will create the closest possible representation that is less than
    /// the provided bandwidth.
    pub fn from_kbps(kbps: u64) -> Result<Self, String> {
        let max_significand = (1 << Self::SIGNIFICAND_BITS) - 1;
        let max_exponent = (1 << Self::EXPONENT_BITS) - 1;

        // Special case: exponent = 0
        if kbps <= max_significand {
            return Ok(Self {
                exponent: 0,
                significand: kbps as u8,
            });
        }

        let exponent = 64 - (kbps.leading_zeros() as usize) - Self::SIGNIFICAND_BITS;
        if exponent > max_exponent {
            return Err(format!(
                "bandwidth too large, cannot convert to wire format: {} kbps",
                kbps
            ));
        }

        // Compute significand: shift right by (exponent - 1), then subtract the
        // implicit prepended '1'.
        let significand = (kbps >> (exponent - 1)) - (1 << Self::SIGNIFICAND_BITS);

        Ok(Self {
            exponent: exponent as u8,
            significand: significand as u8,
        })
    }

    /// Converts the bandwidth to kbps.
    pub fn to_kbps(&self) -> u64 {
        if self.exponent == 0 {
            self.significand as u64
        } else {
            ((self.significand as u64) + (1 << Self::SIGNIFICAND_BITS))
                << (self.exponent - 1) as u64
        }
    }

    /// Encodes the bandwidth as a 16-bit integer.
    /// Note that the bandwidth is encoded as a 10-bit value. Thus, the leading 6
    /// bits of the encoded value are always 0.
    pub fn encode(&self) -> u16 {
        ((self.exponent as u16) << Self::SIGNIFICAND_BITS) | (self.significand as u16)
    }

    /// Decodes a 16-bit integer to a Bandwidth. Note that the bandwidth is
    /// encoded as a 10-bit value. Thus, if the leading 6 bits of the input are
    /// not 0, the function will return an error.
    pub fn decode(encoded: u16) -> Self {
        let exponent = (encoded >> Self::SIGNIFICAND_BITS) as u8;
        let significand = (encoded & ((1 << Self::SIGNIFICAND_BITS) - 1)) as u8;
        Self {
            exponent,
            significand,
        }
    }
}

/// Information about a Hummingbird reservation.
///
/// Wire format:
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |              ISD              |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+              AS               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           ConsIngress         |           ConsEgress          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   ResID                   |        BW         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           ResStart                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          ResDuration          |            Padding            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationInfo {
    /// The ISD-AS for which bandwidth was reserved.
    pub isd_as: IsdAsn,

    /// The ingress interface for which bandwidth was reserved.
    pub ingress_interface: u16,

    /// The egress interface for which bandwidth was reserved.
    pub egress_interface: u16,

    /// The reservation ID.
    pub res_id: u32,

    /// The reserved bandwidth.
    pub bandwidth: Bandwidth,

    /// The start time of the reservation.
    pub start: DateTime<Utc>,

    /// The duration for which the bandwidth is reserved in seconds.
    pub duration: u16,
}

impl ReservationInfo {
    /// The start time of the reservation.
    pub fn start(&self) -> DateTime<Utc> {
        self.start
    }

    /// The end time of the reservation, i.e., when the reservation expires.
    pub fn end(&self) -> DateTime<Utc> {
        self.start + Duration::seconds(self.duration as i64)
    }

    /// Returns whether the reservation's validity window has passed.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.end()
    }

    /// Returns whether the reservation is valid right now, i.e. its validity
    /// window has started but not yet passed.
    pub fn is_valid_now(&self) -> bool {
        let now = Utc::now();
        self.start <= now && now < self.end()
    }

    /// Returns the encoding of the reservation start time according to the
    /// Hummingbird specification.
    pub fn encode_start(&self) -> u32 {
        self.start.timestamp() as u32
    }

    /// Returns the result of decoding `value` as start time according to the
    /// Hummingbird specification
    pub fn decode_start(value: u32) -> DateTime<Utc> {
        DateTime::from_timestamp(value as i64, 0).unwrap()
    }

    /// Computes `ResStartOffset`: the number of whole seconds between this
    /// reservation's start and `base_timestamp` (a path meta header's base
    /// timestamp — a Unix timestamp with 1-second granularity).
    ///
    /// Returns `None` if `base_timestamp` is before the reservation's start, or
    /// if the offset does not fit in the 16-bit wire encoding.
    pub fn res_start_offset(&self, base_timestamp: u32) -> Option<u16> {
        u16::try_from(i64::from(base_timestamp) - self.start.timestamp()).ok()
    }
}

impl ReservationInfo {
    /// Wire-encoded length of a [`ReservationInfo`] in bytes.
    pub const ENCODED_LENGTH: usize = 24;
}

impl WireEncode for ReservationInfo {
    type Error = InadequateBufferSize;

    fn encoded_length(&self) -> usize {
        Self::ENCODED_LENGTH
    }

    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        buffer.put_u64(self.isd_as.0);
        buffer.put_u16(self.ingress_interface);
        buffer.put_u16(self.egress_interface);
        let res_id_and_bw = ((self.res_id & 0x3F_FFFF) << 10) | self.bandwidth.encode() as u32;
        buffer.put_u32(res_id_and_bw);
        buffer.put_u32(self.encode_start());
        buffer.put_u16(self.duration);
        buffer.put_u16(0); // padding
    }
}

impl WireDecode<Bytes> for ReservationInfo {
    type Error = DecodeError;

    fn decode(data: &mut Bytes) -> Result<Self, Self::Error> {
        if data.remaining() < Self::ENCODED_LENGTH {
            return Err(DecodeError::PacketEmptyOrTruncated);
        }
        let isd_as = IsdAsn(data.get_u64());
        let ingress_interface = data.get_u16();
        let egress_interface = data.get_u16();
        let res_id_and_bw = data.get_u32();
        let res_id = res_id_and_bw >> 10;
        let bandwidth = Bandwidth::decode((res_id_and_bw & 0x3FF) as u16);
        let res_start = data.get_u32();
        let start = ReservationInfo::decode_start(res_start);
        let duration = data.get_u16();
        let _ = data.get_u16(); // padding
        Ok(Self {
            isd_as,
            ingress_interface,
            egress_interface,
            res_id,
            bandwidth,
            start,
            duration,
        })
    }
}

/// A full Hummingbird reservation.
///
/// Wire format:
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |              ISD              |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+              AS               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           ConsIngress         |           ConsEgress          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   ResID                   |        BW         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           ResStart                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          ResDuration          |            Padding            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                       ReservationKey                          +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    /// Information about the reservation.
    pub info: ReservationInfo,

    /// The path for which bandwidth was reserved.
    pub reservation_key: HbirdAuthKey,
}

impl Reservation {
    /// Wire-encoded length of a [`Reservation`] in bytes.
    pub const ENCODED_LENGTH: usize = ReservationInfo::ENCODED_LENGTH + 16;

    /// Returns whether the reservation's validity window has passed.
    pub fn is_expired(&self) -> bool {
        self.info.is_expired()
    }

    /// Returns whether the reservation is valid right now, i.e. its validity
    /// window has started but not yet passed.
    pub fn is_valid_now(&self) -> bool {
        self.info.is_valid_now()
    }

    /// Generates the flyover MAC for this reservation, for a packet of length
    /// `pkt_len` bound for `destination`, sent at `timestamp`.
    ///
    /// `counter` defaults to `0` when `None`.
    ///
    /// Note: this computes only the flyover MAC, not the aggregated MAC — the
    /// caller must XOR it with the underlying standard hop field's MAC.
    ///
    /// Returns `None` if `timestamp` is before this reservation's start, or if
    /// the resulting start offset does not fit in the wire encoding.
    pub fn generate_flyover_mac(
        &self,
        destination: IsdAsn,
        pkt_len: u16,
        timestamp: DateTime<Utc>,
        counter: Option<u32>,
    ) -> Option<FlyoverMAC> {
        let base_timestamp = u32::try_from(timestamp.timestamp()).ok()?;
        let res_start_offset = self.info.res_start_offset(base_timestamp)?;
        let millis_timestamp = timestamp.timestamp_subsec_millis() as u16;
        let counter = counter.unwrap_or(0);

        let mac = calculate_flyover_mac(
            destination.isd(),
            destination.asn(),
            pkt_len,
            res_start_offset,
            millis_timestamp,
            counter,
            &self.reservation_key,
        );

        Some(FlyoverMAC {
            mac,
            reservation_info: self.info.clone(),
            dst_isd_asn: destination,
            base_timestamp,
            millis_timestamp,
            counter,
            packet_length: pkt_len,
        })
    }
}

impl WireEncode for Reservation {
    type Error = InadequateBufferSize;

    fn encoded_length(&self) -> usize {
        Self::ENCODED_LENGTH
    }

    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        self.info.encode_to_unchecked(buffer);
        buffer.put_slice(self.reservation_key.as_slice());
    }
}

impl WireDecode<Bytes> for Reservation {
    type Error = DecodeError;

    fn decode(data: &mut Bytes) -> Result<Self, Self::Error> {
        if data.remaining() < Self::ENCODED_LENGTH {
            return Err(DecodeError::PacketEmptyOrTruncated);
        }
        let info = ReservationInfo::decode(data)?;
        let reservation_key = HbirdAuthKey::clone_from_slice(&data.split_to(16));
        Ok(Self {
            info,
            reservation_key,
        })
    }
}

/// A pre-computed flyover MAC.
///
/// Can be used to turn a matching standard hop into a flyover hop.
pub struct FlyoverMAC {
    /// The actual flyover MAC.
    pub mac: [u8; 6],
    /// The details of the reservation corresponding to this MAC.
    pub reservation_info: ReservationInfo,
    /// The ISD-ASN to send packets to when using this MAC.
    pub dst_isd_asn: IsdAsn,
    /// The path meta header base timestamp used when calculating the MAC: a
    /// Unix timestamp with 1-second granularity.
    pub base_timestamp: u32,
    /// The millis timestamp used when calculating the MAC.
    pub millis_timestamp: u16,
    /// The counter value used when calculating the MAC.
    pub counter: u32,
    /// The packet length used when calculating the MAC.
    pub packet_length: u16,
}

impl FlyoverMAC {
    pub fn packet_timestamp(&self) -> DateTime<Utc> {
        ReservationInfo::decode_start(self.base_timestamp)
            + Duration::milliseconds(i64::from(self.millis_timestamp))
    }

    /// Returns when the flyover MAC becomes valid, i.e., if a packet using this  
    /// MAC arrives at this point in time it should be valid (but not before
    /// then).
    /// If the flyover MAC is never vaild, returns the end time of the
    /// reservation.
    pub fn valid_from(&self) -> DateTime<Utc> {
        self.packet_timestamp().min(self.reservation_info.end())
    }

    /// Returns until when the flyover MAC is valid, i.e., the last point in time
    /// at which the packet can arrive at the border router such that the border
    /// router forwards the packet with priority.
    pub fn valid_until(&self) -> DateTime<Utc> {
        self.reservation_info
            .end()
            .min(self.packet_timestamp() + Duration::seconds(MAX_FRESHNESS_TOLERANCE))
    }

    /// Returns whether this flyover MAC's validity window has passed.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.valid_until()
    }

    /// Returns whether the flyover MAC is valid right now, i.e. its validity
    /// window has started but not yet passed.
    pub fn is_valid_now(&self) -> bool {
        let now = Utc::now();
        self.valid_from() <= now && self.valid_until() >= now
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire_encoding::{WireDecode, WireEncode};

    #[test]
    fn zero_bandwidth() {
        let bw = Bandwidth::from_kbps(0).unwrap();
        assert_eq!(bw.to_kbps(), 0);
    }

    #[test]
    fn small_bandwidth_uses_exponent_zero() {
        // Values 0..=31 are stored directly as the significand (exponent = 0).
        for kbps in [1u64, 15, 31] {
            let bw = Bandwidth::from_kbps(kbps).unwrap();
            assert_eq!(bw.exponent, 0, "kbps={kbps}");
            assert_eq!(bw.to_kbps(), kbps, "kbps={kbps}");
        }
    }

    #[test]
    fn boundary_between_exponent_zero_and_one() {
        // 31 fits in exponent=0; 32 requires exponent=1.
        let bw31 = Bandwidth::from_kbps(31).unwrap();
        assert_eq!(bw31.exponent, 0);

        let bw32 = Bandwidth::from_kbps(32).unwrap();
        assert_eq!(bw32.exponent, 1);
        assert_eq!(bw32.to_kbps(), 32);
    }

    #[test]
    fn roundtrip_various_values() {
        // Values that are exactly representable should survive a roundtrip.
        // For exponent E, only multiples of 2^(E-1) are exactly representable.
        for kbps in [32u64, 63, 64, 128, 1024] {
            let bw = Bandwidth::from_kbps(kbps).unwrap();
            assert_eq!(bw.to_kbps(), kbps, "roundtrip failed for {kbps} kbps");
        }
    }

    #[test]
    fn non_representable_value_rounds_down() {
        // For exponent=2 the stride is 2, so odd values in [64,126] are not
        // representable. 65 should encode as 64.
        let bw = Bandwidth::from_kbps(65).unwrap();
        assert!(bw.to_kbps() <= 65);
        assert_eq!(bw.to_kbps(), 64);
    }

    #[test]
    fn too_large_returns_error() {
        // Max exponent is 31. An error is triggered when the required exponent
        // would be 32, which first happens at 2^36 kbps.
        let just_fits: u64 = (1 << 36) - 1;
        assert!(Bandwidth::from_kbps(just_fits).is_ok());
        assert!(Bandwidth::from_kbps(1u64 << 36).is_err());
    }

    #[test]
    fn encode_decode_roundtrip() {
        for kbps in [0u64, 1, 31, 32, 64, 1024, 1_000_000] {
            let bw = Bandwidth::from_kbps(kbps).unwrap();
            let decoded = Bandwidth::decode(bw.encode());
            assert_eq!(
                bw, decoded,
                "encode/decode roundtrip failed for {kbps} kbps"
            );
        }
    }

    #[test]
    fn encode_fits_in_10_bits() {
        for kbps in [0u64, 1, 31, 32, 64, 1_000_000] {
            let encoded = Bandwidth::from_kbps(kbps).unwrap().encode();
            assert_eq!(
                encoded & !Bandwidth::MASK,
                0,
                "encoded value exceeds 10 bits for {kbps} kbps"
            );
        }
    }

    #[test]
    fn reservation_info_encode_decode_roundtrip() {
        use crate::address::IsdAsn;

        let info = ReservationInfo {
            isd_as: IsdAsn(0x1_ff00_0000_0110),
            ingress_interface: 1,
            egress_interface: 2,
            res_id: 0x3FFFFF,
            bandwidth: Bandwidth::from_kbps(1024).unwrap(),
            start: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            duration: 3600,
        };
        assert_eq!(info.encoded_length(), ReservationInfo::ENCODED_LENGTH);

        let encoded = info.encode_to_bytes();
        assert_eq!(encoded.len(), ReservationInfo::ENCODED_LENGTH);

        let decoded = ReservationInfo::decode(&mut encoded.clone()).unwrap();
        assert_eq!(decoded, info);
    }

    #[test]
    fn reservation_encode_decode_roundtrip() {
        use crate::address::IsdAsn;

        let res = Reservation {
            info: ReservationInfo {
                isd_as: IsdAsn(0x1_ff00_0000_0110),
                ingress_interface: 3,
                egress_interface: 4,
                res_id: 42,
                bandwidth: Bandwidth::from_kbps(64).unwrap(),
                start: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                duration: 600,
            },
            reservation_key: HbirdAuthKey::from([0xABu8; 16]),
        };
        assert_eq!(res.encoded_length(), Reservation::ENCODED_LENGTH);

        let encoded = res.encode_to_bytes();
        assert_eq!(encoded.len(), Reservation::ENCODED_LENGTH);

        let decoded = Reservation::decode(&mut encoded.clone()).unwrap();
        assert_eq!(decoded, res);
    }
}
