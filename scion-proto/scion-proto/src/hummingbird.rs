//! Hummingbird-specific types and functions.
//!
//! See also [path::hummingbird].

use crate::{address::IsdAsn, path::hummingbird::HbirdAuthKey};

/// Bandwidth for Hummingbird reservations, in bytes per second.
///
/// Stored as a 10-bit floating-point encoding (5-bit exponent, 5-bit
/// significand), matching the data-plane wire format from the Hummingbird
/// paper. The encoded value travels end-to-end unmodified: it is what the
/// redemption service derives the authentication key from and what the border
/// router decodes (as bytes per second) to enforce the bandwidth restriction.
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

    /// Creates a new Bandwidth from a given bandwidth in bytes per second.
    /// Returns an error if the bandwidth is too large to be represented in the
    /// 10-bit encoding. If the value is not exactly representable, the closest
    /// representation that is less than the provided bandwidth is used.
    pub fn from_bytes_per_sec(bytes_per_sec: u64) -> Result<Self, String> {
        let max_significand = (1 << Self::SIGNIFICAND_BITS) - 1;
        let max_exponent = (1 << Self::EXPONENT_BITS) - 1;

        // Special case: exponent = 0
        if bytes_per_sec <= max_significand {
            return Ok(Self {
                exponent: 0,
                significand: bytes_per_sec as u8,
            });
        }

        let exponent = 64 - (bytes_per_sec.leading_zeros() as usize) - Self::SIGNIFICAND_BITS;
        if exponent > max_exponent {
            return Err(format!(
                "bandwidth too large, cannot convert to wire format: {} bytes/s",
                bytes_per_sec
            ));
        }

        // Compute significand: shift right by (exponent - 1), then subtract the
        // implicit prepended '1'.
        let significand = (bytes_per_sec >> (exponent - 1)) - (1 << Self::SIGNIFICAND_BITS);

        Ok(Self {
            exponent: exponent as u8,
            significand: significand as u8,
        })
    }

    /// Converts the bandwidth to bytes per second.
    pub fn to_bytes_per_sec(&self) -> u64 {
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
    pub start: u32,

    /// The duration for which the bandwidth is reserved in seconds.
    pub duration: u16,
}

/// A full Hummingbird reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reservation {
    /// Information about the reservation.
    pub info: ReservationInfo,

    /// The path for which bandwidth was reserved.
    pub reservation_key: HbirdAuthKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_bandwidth() {
        let bw = Bandwidth::from_bytes_per_sec(0).unwrap();
        assert_eq!(bw.to_bytes_per_sec(), 0);
    }

    #[test]
    fn small_bandwidth_uses_exponent_zero() {
        // Values 0..=31 are stored directly as the significand (exponent = 0).
        for bytes_per_sec in [1u64, 15, 31] {
            let bw = Bandwidth::from_bytes_per_sec(bytes_per_sec).unwrap();
            assert_eq!(bw.exponent, 0, "bytes_per_sec={bytes_per_sec}");
            assert_eq!(bw.to_bytes_per_sec(), bytes_per_sec, "bytes_per_sec={bytes_per_sec}");
        }
    }

    #[test]
    fn boundary_between_exponent_zero_and_one() {
        // 31 fits in exponent=0; 32 requires exponent=1.
        let bw31 = Bandwidth::from_bytes_per_sec(31).unwrap();
        assert_eq!(bw31.exponent, 0);

        let bw32 = Bandwidth::from_bytes_per_sec(32).unwrap();
        assert_eq!(bw32.exponent, 1);
        assert_eq!(bw32.to_bytes_per_sec(), 32);
    }

    #[test]
    fn roundtrip_various_values() {
        // Values that are exactly representable should survive a roundtrip.
        // For exponent E, only multiples of 2^(E-1) are exactly representable.
        for bytes_per_sec in [32u64, 63, 64, 128, 1024] {
            let bw = Bandwidth::from_bytes_per_sec(bytes_per_sec).unwrap();
            assert_eq!(
                bw.to_bytes_per_sec(),
                bytes_per_sec,
                "roundtrip failed for {bytes_per_sec} bytes/s"
            );
        }
    }

    #[test]
    fn non_representable_value_rounds_down() {
        // For exponent=2 the stride is 2, so odd values in [64,126] are not
        // representable. 65 should encode as 64.
        let bw = Bandwidth::from_bytes_per_sec(65).unwrap();
        assert!(bw.to_bytes_per_sec() <= 65);
        assert_eq!(bw.to_bytes_per_sec(), 64);
    }

    #[test]
    fn too_large_returns_error() {
        // Max exponent is 31. An error is triggered when the required exponent
        // would be 32, which first happens at 2^36 bytes/s.
        let just_fits: u64 = (1 << 36) - 1;
        assert!(Bandwidth::from_bytes_per_sec(just_fits).is_ok());
        assert!(Bandwidth::from_bytes_per_sec(1u64 << 36).is_err());
    }

    #[test]
    fn encode_decode_roundtrip() {
        for bytes_per_sec in [0u64, 1, 31, 32, 64, 1024, 1_000_000] {
            let bw = Bandwidth::from_bytes_per_sec(bytes_per_sec).unwrap();
            let decoded = Bandwidth::decode(bw.encode());
            assert_eq!(
                bw, decoded,
                "encode/decode roundtrip failed for {bytes_per_sec} bytes/s"
            );
        }
    }

    #[test]
    fn encode_fits_in_10_bits() {
        for bytes_per_sec in [0u64, 1, 31, 32, 64, 1_000_000] {
            let encoded = Bandwidth::from_bytes_per_sec(bytes_per_sec).unwrap().encode();
            assert_eq!(
                encoded & !Bandwidth::MASK,
                0,
                "encoded value exceeds 10 bits for {bytes_per_sec} bytes/s"
            );
        }
    }
}
