//! Hummingbird-specific types and functions.
//!
//! See also [path::hummingbird].

use std::time::SystemTime;

use crate::{address::IsdAsn, path::hummingbird::HbirdAuthKey};

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
    pub fn to_kpbs(&self) -> u64 {
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
#[derive(Debug, Clone)]
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

    /// The duration for which the bandwidth is reserved.
    pub duration: u16,
}

/// A full Hummingbird reservation.
#[derive(Debug, Clone)]
pub struct Reservation {
    /// Information about the reservation.
    pub info: ReservationInfo,

    /// The path for which bandwidth was reserved.
    pub reservation_key: HbirdAuthKey,
}

impl Reservation {
    /// Returns whether the reservation has expired.
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(SystemTime::now())
    }

    /// Returns whether the reservation is expired at the given point in time.
    pub fn is_expired_at(&self, time: SystemTime) -> bool {
        let time = time
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.info.start as u64 + (self.info.duration as u64) > time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_bandwidth() {
        let bw = Bandwidth::from_kbps(0).unwrap();
        assert_eq!(bw.to_kpbs(), 0);
    }

    #[test]
    fn small_bandwidth_uses_exponent_zero() {
        // Values 0..=31 are stored directly as the significand (exponent = 0).
        for kbps in [1u64, 15, 31] {
            let bw = Bandwidth::from_kbps(kbps).unwrap();
            assert_eq!(bw.exponent, 0, "kbps={kbps}");
            assert_eq!(bw.to_kpbs(), kbps, "kbps={kbps}");
        }
    }

    #[test]
    fn boundary_between_exponent_zero_and_one() {
        // 31 fits in exponent=0; 32 requires exponent=1.
        let bw31 = Bandwidth::from_kbps(31).unwrap();
        assert_eq!(bw31.exponent, 0);

        let bw32 = Bandwidth::from_kbps(32).unwrap();
        assert_eq!(bw32.exponent, 1);
        assert_eq!(bw32.to_kpbs(), 32);
    }

    #[test]
    fn roundtrip_various_values() {
        // Values that are exactly representable should survive a roundtrip.
        // For exponent E, only multiples of 2^(E-1) are exactly representable.
        for kbps in [32u64, 63, 64, 128, 1024] {
            let bw = Bandwidth::from_kbps(kbps).unwrap();
            assert_eq!(bw.to_kpbs(), kbps, "roundtrip failed for {kbps} kbps");
        }
    }

    #[test]
    fn non_representable_value_rounds_down() {
        // For exponent=2 the stride is 2, so odd values in [64,126] are not
        // representable. 65 should encode as 64.
        let bw = Bandwidth::from_kbps(65).unwrap();
        assert!(bw.to_kpbs() <= 65);
        assert_eq!(bw.to_kpbs(), 64);
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
}
