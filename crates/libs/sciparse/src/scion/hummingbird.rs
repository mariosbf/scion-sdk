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

//! Hummingbird reservation material.
//!
//! A *flyover reservation* grants a sender a bandwidth allowance across one hop of one AS for a
//! bounded window of time, together with the key that authenticates its use. Reservations are
//! obtained from an AS's redemption service; this module models what comes back, and nothing
//! about how it is obtained or how it is spent.
//!
//! The types here carry no wire encoding of their own. Reservations are exchanged with the
//! redemption service field by field over protobuf, and what ends up on the wire is the *flyover
//! hop field* built from a reservation, which lives with the path types.

use std::{
    sync::{Arc, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes::{Aes128Enc, cipher::KeyInit};

use crate::identifier::isd_asn::IsdAsn;

pub mod crypto;
pub mod tracker;

/// The key that authenticates use of a flyover reservation.
///
/// Issued by the redemption service of the AS the reservation is for, and used to key the flyover
/// MAC. Sixteen bytes, matching [`ForwardingKey`](crate::path::standard::mac::ForwardingKey).
pub type HbirdAuthKey = [u8; 16];

/// Maximum clock skew tolerated when checking reservation freshness against the current time.
pub const MAX_FRESHNESS_TOLERANCE: Duration = Duration::from_secs(5);

/// Bandwidth for Hummingbird reservations, in bytes per second.
///
/// Stored as a 10-bit floating-point encoding (5-bit exponent, 5-bit significand), matching the
/// data-plane wire format from the Hummingbird paper. The encoded value travels end-to-end
/// unmodified: it is what the redemption service derives the authentication key from and what the
/// border router decodes (as bytes per second) to enforce the bandwidth restriction.
///
/// Not every value is representable. [`from_bytes_per_sec`](Self::from_bytes_per_sec) rounds
/// *down* to the nearest representable value, so a reservation never claims more bandwidth than
/// was asked for.
#[derive(Clone, PartialEq, Eq, Hash, Copy, Debug, Default)]
pub struct Bandwidth {
    /// Exponent.
    exponent: u8,
    /// Significand.
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

    /// Creates a new bandwidth from a value in bytes per second.
    ///
    /// If the value is not exactly representable, the closest representable value *below* it is
    /// used. Returns an error if the value is too large for the 10-bit encoding.
    pub fn from_bytes_per_sec(bytes_per_sec: u64) -> Result<Self, BandwidthTooLarge> {
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
            return Err(BandwidthTooLarge { bytes_per_sec });
        }

        // Compute significand: shift right by (exponent - 1), then subtract the implicit
        // prepended '1'.
        let significand = (bytes_per_sec >> (exponent - 1)) - (1 << Self::SIGNIFICAND_BITS);

        Ok(Self {
            exponent: exponent as u8,
            significand: significand as u8,
        })
    }

    /// Converts the bandwidth to bytes per second.
    pub const fn to_bytes_per_sec(&self) -> u64 {
        if self.exponent == 0 {
            self.significand as u64
        } else {
            ((self.significand as u64) + (1 << Self::SIGNIFICAND_BITS)) << (self.exponent - 1)
        }
    }

    /// Encodes the bandwidth as a 16-bit integer.
    ///
    /// Only the low 10 bits are used; the leading 6 bits are always zero.
    pub const fn encode(&self) -> u16 {
        ((self.exponent as u16) << Self::SIGNIFICAND_BITS) | (self.significand as u16)
    }

    /// Decodes a 16-bit integer into a bandwidth. Any bits above the low 10 are ignored.
    pub const fn decode(encoded: u16) -> Self {
        let exponent = (encoded >> Self::SIGNIFICAND_BITS) as u8 & 0x1F;
        let significand = (encoded & ((1 << Self::SIGNIFICAND_BITS) - 1)) as u8;
        Self {
            exponent,
            significand,
        }
    }
}

impl PartialOrd for Bandwidth {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Bandwidth {
    /// Orders by the bandwidth each value denotes.
    ///
    /// Reservation selection compares and sorts candidates by how much bandwidth they grant, so
    /// that is what the ordering means. The encoding happens to be monotonic in the same
    /// direction, but comparing encodings would tie that guarantee to the wire format.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_bytes_per_sec().cmp(&other.to_bytes_per_sec())
    }
}

/// A bandwidth value too large for the 10-bit wire encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("bandwidth too large for the wire encoding: {bytes_per_sec} bytes/s")]
pub struct BandwidthTooLarge {
    /// The value that could not be represented.
    pub bytes_per_sec: u64,
}

/// What a flyover reservation covers: one hop of one AS, for a bounded window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationInfo {
    /// The AS that issued the reservation, and whose hop it applies to.
    pub isd_as: IsdAsn,

    /// The ingress interface for which bandwidth was reserved.
    pub ingress_interface: u16,

    /// The egress interface for which bandwidth was reserved.
    pub egress_interface: u16,

    /// The reservation ID. Only the low 22 bits are carried on the wire.
    pub res_id: u32,

    /// The reserved bandwidth.
    pub bandwidth: Bandwidth,

    /// The start of the reservation's validity window, at one-second granularity.
    pub start: SystemTime,

    /// The length of the validity window, in seconds.
    pub duration: u16,
}

impl ReservationInfo {
    /// The end of the validity window, i.e. when the reservation expires.
    pub fn end(&self) -> SystemTime {
        self.start + Duration::from_secs(self.duration as u64)
    }

    /// Whether the reservation's validity window has passed.
    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.end()
    }

    /// Whether the reservation is valid right now: its window has started but not yet passed.
    pub fn is_valid_now(&self) -> bool {
        let now = SystemTime::now();
        self.start <= now && now < self.end()
    }

    /// The start time as the Unix timestamp the Hummingbird encoding uses.
    ///
    /// Returns `None` for times outside the range a `u32` timestamp can express.
    pub fn encode_start(&self) -> Option<u32> {
        u32::try_from(self.start.duration_since(UNIX_EPOCH).ok()?.as_secs()).ok()
    }

    /// The time a Hummingbird-encoded start timestamp denotes.
    pub fn decode_start(value: u32) -> SystemTime {
        // A u32 second count is ~136 years past the epoch; it cannot overflow SystemTime.
        UNIX_EPOCH + Duration::from_secs(value as u64)
    }

    /// Computes `ResStartOffset`: the whole seconds between this reservation's start and
    /// `base_timestamp`, a path meta header's base timestamp.
    ///
    /// Returns `None` if `base_timestamp` precedes the reservation's start, or if the offset does
    /// not fit the 16-bit wire encoding.
    pub fn res_start_offset(&self, base_timestamp: u32) -> Option<u16> {
        let start = self.encode_start()?;
        u16::try_from(base_timestamp.checked_sub(start)?).ok()
    }
}

/// A flyover reservation: what it covers, and the key that authenticates its use.
#[derive(Debug, Clone)]
pub struct Reservation {
    /// What the reservation covers.
    ///
    /// Kept private so it cannot change after construction: [`Self::is_valid_at`] answers from a
    /// validity window cached at construction.
    info: ReservationInfo,

    /// The key used to authenticate use of this reservation.
    ///
    /// Kept private so it cannot change after construction: [`Self::cipher`] caches the AES key
    /// schedule derived from it.
    auth_key: HbirdAuthKey,

    /// Start of the validity window, precomputed from `info`.
    valid_from: SystemTime,

    /// End of the validity window, precomputed from `info`. Inclusive.
    valid_until: SystemTime,

    /// AES key schedule for `auth_key`, expanded lazily on first MAC computation and reused for
    /// the lifetime of the reservation.
    ///
    /// Behind an [`Arc`] so that the reservation stays small — it is cloned per packet on the
    /// encoding hot path — and so that clones share the cache: expanding the schedule through a
    /// clone must warm the original, or the work repeats on every packet.
    cipher: Arc<OnceLock<Aes128Enc>>,
}

impl PartialEq for Reservation {
    fn eq(&self, other: &Self) -> bool {
        // The cipher is a pure function of `auth_key`; its cache state must not affect equality.
        self.info == other.info && self.auth_key == other.auth_key
    }
}

impl Eq for Reservation {}

impl Reservation {
    /// Creates a reservation from what it covers and the key authenticating it.
    pub fn new(info: ReservationInfo, auth_key: HbirdAuthKey) -> Self {
        Self {
            valid_from: info.start,
            valid_until: info.end(),
            info,
            auth_key,
            cipher: Arc::new(OnceLock::new()),
        }
    }

    /// What the reservation covers.
    pub fn info(&self) -> &ReservationInfo {
        &self.info
    }

    /// The key used to authenticate use of this reservation.
    pub fn auth_key(&self) -> &HbirdAuthKey {
        &self.auth_key
    }

    /// Whether this reservation's validity window contains `now`.
    ///
    /// Both bounds are inclusive, unlike [`ReservationInfo::is_valid_now`], whose upper bound is
    /// exclusive. This is the check reservation trackers perform when selecting a reservation for
    /// a packet, so it answers from the window cached at construction rather than recomputing it.
    pub fn is_valid_at(&self, now: SystemTime) -> bool {
        self.valid_from <= now && now <= self.valid_until
    }

    /// Whether the reservation's validity window has passed.
    pub fn is_expired(&self) -> bool {
        self.info.is_expired()
    }

    /// Whether the reservation is valid right now.
    pub fn is_valid_now(&self) -> bool {
        self.info.is_valid_now()
    }

    /// The AES key schedule for [`Self::auth_key`], expanded on first use and cached.
    ///
    /// Expanding the schedule costs more than the MAC it keys, so a reservation used for many
    /// packets must expand it once, not once per packet.
    pub fn cipher(&self) -> &Aes128Enc {
        self.cipher
            .get_or_init(|| Aes128Enc::new(&self.auth_key.into()))
    }
}

/// Reservation builders shared by the tracker tests in this module's children.
///
/// Central so that all three trackers are tested against identically shaped reservations.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A reservation over interfaces 1 to 2 of `1-ff00:0:110`, valid from `start` for one hour.
    pub(crate) fn reservation(res_id: u32, bytes_per_sec: u64, start: SystemTime) -> Reservation {
        reservation_for(res_id, bytes_per_sec, start, 3600)
    }

    /// [`reservation`], with an explicit validity window length in seconds.
    pub(crate) fn reservation_for(
        res_id: u32,
        bytes_per_sec: u64,
        start: SystemTime,
        duration: u16,
    ) -> Reservation {
        Reservation::new(
            ReservationInfo {
                isd_as: IsdAsn(0x1_ff00_0000_0110),
                ingress_interface: 1,
                egress_interface: 2,
                res_id,
                bandwidth: Bandwidth::from_bytes_per_sec(bytes_per_sec).expect("representable"),
                start,
                duration,
            },
            [0x11; 16],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(timestamp: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(timestamp)
    }

    fn info() -> ReservationInfo {
        ReservationInfo {
            isd_as: IsdAsn(0x1_ff00_0000_0110),
            ingress_interface: 1,
            egress_interface: 2,
            res_id: 0x3F_FFFF,
            bandwidth: Bandwidth::from_bytes_per_sec(1024).unwrap(),
            start: at(1_700_000_000),
            duration: 3600,
        }
    }

    #[test]
    fn zero_bandwidth() {
        let bw = Bandwidth::from_bytes_per_sec(0).unwrap();
        assert_eq!(bw.to_bytes_per_sec(), 0);
    }

    #[test]
    fn bandwidth_ord_matches_bytes_per_sec_ordering() {
        let low = Bandwidth::from_bytes_per_sec(10).unwrap();
        let high = Bandwidth::from_bytes_per_sec(1024).unwrap();
        assert!(low < high);

        // Exponent boundary: 31 uses exponent=0, 32 uses exponent=1.
        let boundary_low = Bandwidth::from_bytes_per_sec(31).unwrap();
        let boundary_high = Bandwidth::from_bytes_per_sec(32).unwrap();
        assert!(boundary_low < boundary_high);

        // Sorting a mixed set must come back in bytes-per-second order.
        let mut values =
            [1024u64, 31, 1_000_000, 0, 32].map(|v| Bandwidth::from_bytes_per_sec(v).unwrap());
        values.sort();
        assert!(
            values
                .windows(2)
                .all(|w| w[0].to_bytes_per_sec() <= w[1].to_bytes_per_sec())
        );
    }

    #[test]
    fn small_bandwidth_uses_exponent_zero() {
        // Values 0..=31 are stored directly as the significand (exponent = 0).
        for bytes_per_sec in [1u64, 15, 31] {
            let bw = Bandwidth::from_bytes_per_sec(bytes_per_sec).unwrap();
            assert_eq!(bw.exponent, 0, "bytes_per_sec={bytes_per_sec}");
            assert_eq!(
                bw.to_bytes_per_sec(),
                bytes_per_sec,
                "bytes_per_sec={bytes_per_sec}"
            );
        }
    }

    #[test]
    fn boundary_between_exponent_zero_and_one() {
        let bw31 = Bandwidth::from_bytes_per_sec(31).unwrap();
        assert_eq!(bw31.exponent, 0);

        let bw32 = Bandwidth::from_bytes_per_sec(32).unwrap();
        assert_eq!(bw32.exponent, 1);
        assert_eq!(bw32.to_bytes_per_sec(), 32);
    }

    #[test]
    fn roundtrip_various_values() {
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
        // A reservation must never claim more than was asked for. For exponent=2 the stride is 2,
        // so 65 is not representable and must land on 64, not 66.
        let bw = Bandwidth::from_bytes_per_sec(65).unwrap();
        assert_eq!(bw.to_bytes_per_sec(), 64);
    }

    #[test]
    fn too_large_returns_error() {
        // Max exponent is 31. An error is triggered when the required exponent would be 32, which
        // first happens at 2^36 bytes/s.
        let just_fits: u64 = (1 << 36) - 1;
        assert!(Bandwidth::from_bytes_per_sec(just_fits).is_ok());
        assert_eq!(
            Bandwidth::from_bytes_per_sec(1u64 << 36),
            Err(BandwidthTooLarge {
                bytes_per_sec: 1 << 36
            })
        );
    }

    #[test]
    fn bandwidth_encode_decode_roundtrip() {
        for bytes_per_sec in [0u64, 1, 31, 32, 64, 1024, 1_000_000] {
            let bw = Bandwidth::from_bytes_per_sec(bytes_per_sec).unwrap();
            assert_eq!(
                bw,
                Bandwidth::decode(bw.encode()),
                "encode/decode roundtrip failed for {bytes_per_sec} bytes/s"
            );
        }
    }

    #[test]
    fn bandwidth_encode_fits_in_10_bits() {
        for bytes_per_sec in [0u64, 1, 31, 32, 64, 1_000_000] {
            let encoded = Bandwidth::from_bytes_per_sec(bytes_per_sec)
                .unwrap()
                .encode();
            assert_eq!(
                encoded & !Bandwidth::MASK,
                0,
                "encoded value exceeds 10 bits for {bytes_per_sec} bytes/s"
            );
        }
    }

    #[test]
    fn validity_window_ends_after_the_duration() {
        let info = info();
        assert_eq!(info.end(), at(1_700_000_000 + 3600));
    }

    #[test]
    fn start_timestamp_roundtrips_through_the_wire_encoding() {
        let info = info();
        assert_eq!(info.encode_start(), Some(1_700_000_000));
        assert_eq!(
            ReservationInfo::decode_start(info.encode_start().unwrap()),
            info.start
        );
    }

    #[test]
    fn res_start_offset_measures_forward_from_the_start() {
        let info = info();
        assert_eq!(info.res_start_offset(1_700_000_000), Some(0));
        assert_eq!(info.res_start_offset(1_700_000_042), Some(42));
    }

    #[test]
    fn res_start_offset_rejects_timestamps_the_encoding_cannot_carry() {
        let info = info();
        // Before the reservation started.
        assert_eq!(info.res_start_offset(1_699_999_999), None);
        // Further past the start than the 16-bit offset can express.
        assert_eq!(info.res_start_offset(1_700_000_000 + 65_536), None);
    }

    #[test]
    fn reservation_validity_bounds_are_inclusive() {
        let reservation = Reservation::new(info(), [0u8; 16]);

        assert!(!reservation.is_valid_at(at(1_699_999_999)));
        assert!(reservation.is_valid_at(at(1_700_000_000)));
        assert!(reservation.is_valid_at(at(1_700_000_000 + 3600)));
        assert!(!reservation.is_valid_at(at(1_700_000_000 + 3601)));
    }

    #[test]
    fn reservation_equality_ignores_the_cipher_cache() {
        let warm = Reservation::new(info(), [7u8; 16]);
        let cold = Reservation::new(info(), [7u8; 16]);
        let _ = warm.cipher();

        assert_eq!(warm, cold);
        assert_ne!(warm, Reservation::new(info(), [8u8; 16]));
    }

    #[test]
    fn cloned_reservations_share_the_cipher_cache() {
        // The encoder clones a reservation before computing MACs; expanding the key schedule
        // through the clone must warm the original, or the work repeats on every packet.
        let original = Reservation::new(info(), [1u8; 16]);
        let clone = original.clone();
        let _ = clone.cipher();

        assert!(
            original.cipher.get().is_some(),
            "expanding through a clone should warm the original"
        );
    }
}
