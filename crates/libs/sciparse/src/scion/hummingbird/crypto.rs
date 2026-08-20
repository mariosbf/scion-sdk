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

//! The two AES computations Hummingbird reservations are built on.
//!
//! A reservation is authenticated by a *flyover MAC*: a single AES-128 block, keyed by the
//! reservation's authentication key, over the destination AS, the packet length, and the send
//! time. The key itself is derived by the issuing AS from its secret value and the reservation's
//! parameters — the other computation here.
//!
//! Neither function decides anything. Which reservation a packet uses is a
//! [tracker's][super::tracker] business, and where the resulting bytes go is the path's; this
//! module only computes.

use aes::{
    Aes128Enc,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};

use super::{Bandwidth, HbirdAuthKey};
use crate::identifier::isd_asn::IsdAsn;

/// A 16-byte AS secret value, from which that AS derives per-reservation authentication keys.
///
/// `SV_K` in the Hummingbird paper. Distinct from [`HbirdAuthKey`], which is what a *sender*
/// holds: an AS keeps one secret value and derives an authentication key per reservation from it.
pub type HbirdKey = [u8; 16];

/// Computes the flyover MAC for one hop of one packet.
///
/// This is *not* the MAC the wire carries. The wire carries the **aggregated** MAC: this value
/// XORed with the hop's standard SCION MAC. Border routers de-aggregate before forwarding, which
/// is why a Hummingbird path taken from a received packet carries plain standard MACs.
///
/// Takes an expanded cipher rather than a key because it runs once per flyover hop per packet,
/// and expanding an AES-128 key schedule costs several times more than the single block
/// encryption it keys. Use [`Reservation::cipher`](super::Reservation::cipher), which expands the
/// schedule once and caches it for the reservation's lifetime.
///
/// Two inputs are narrower than their types suggest and are truncated here: `millis_timestamp` is
/// 10 bits wide and `counter` is 22 bits.
///
/// The MAC input block, all fields big-endian:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            DstISD             |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
/// |                             DstAS                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            PktLen             |        ResStartOffset         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  MillisTimestamp  |                  Counter                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// `PktLen` is the length of the *whole* packet — common header, address header, path, and
/// payload — matching the reference implementation's `SCION.PacketLen()`.
#[inline]
pub fn flyover_mac(
    dst_ia: IsdAsn,
    pkt_len: u16,
    res_start_offset: u16,
    millis_timestamp: u16,
    counter: u32,
    cipher: &Aes128Enc,
) -> [u8; 6] {
    // The two share one 32-bit word, so both masks are load-bearing: without them a wide millis
    // value would overwrite the counter's high bits, and a wide counter would corrupt millis.
    let millis_and_counter = (u32::from(millis_timestamp & 0x3FF) << 22) | (counter & 0x3F_FFFF);

    let mut input = [0u8; 16];
    input[0..8].copy_from_slice(&dst_ia.to_be_bytes());
    input[8..10].copy_from_slice(&pkt_len.to_be_bytes());
    input[10..12].copy_from_slice(&res_start_offset.to_be_bytes());
    input[12..16].copy_from_slice(&millis_and_counter.to_be_bytes());

    let mut block = GenericArray::from(input);
    cipher.encrypt_block(&mut block);

    let mut mac = [0u8; 6];
    mac.copy_from_slice(&block[..6]);
    mac
}

/// Derives a reservation's authentication key from the issuing AS's secret value.
///
/// This is the AS side of the scheme. A sender receives the derived key from the redemption
/// service and never runs this; it is here to pin the derivation against the reference
/// implementation, and to let tests mint reservations without a redemption service.
///
/// Unlike [`flyover_mac`] this takes a raw key and expands it internally: it runs once per
/// reservation rather than once per packet, so the expansion is not worth caching.
///
/// Two inputs are narrower than their types suggest and are truncated here: `res_id` is 22 bits
/// wide and the encoded bandwidth is 10 bits.
///
/// The derivation input block, all fields big-endian:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          ConsIngress          |          ConsEgress           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   ResID                   |        BW         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           ResStart                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          ResDuration          |               0               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub fn derive_auth_key(
    cons_ingress: u16,
    cons_egress: u16,
    res_id: u32,
    bw: Bandwidth,
    res_start: u32,
    res_duration: u16,
    key: &HbirdKey,
) -> HbirdAuthKey {
    let res_id_and_bw = ((res_id & 0x3F_FFFF) << 10) | u32::from(bw.encode() & 0x3FF);

    let mut input = [0u8; 16];
    input[0..2].copy_from_slice(&cons_ingress.to_be_bytes());
    input[2..4].copy_from_slice(&cons_egress.to_be_bytes());
    input[4..8].copy_from_slice(&res_id_and_bw.to_be_bytes());
    input[8..12].copy_from_slice(&res_start.to_be_bytes());
    input[12..14].copy_from_slice(&res_duration.to_be_bytes());
    // input[14..16] stays zero: explicit padding in the reference layout, not spare space.

    let cipher = Aes128Enc::new(key.into());
    let mut block = GenericArray::from(input);
    cipher.encrypt_block(&mut block);

    let mut auth_key = [0u8; 16];
    auth_key.copy_from_slice(&block);
    auth_key
}

/// XORs `b` into `a` in place.
///
/// If the slices differ in length the excess bytes of the longer one are ignored, which is what
/// makes this usable to fold a 6-byte flyover MAC into a 6-byte hop field MAC without either side
/// asserting a length.
#[inline]
pub fn xor_in_place(a: &mut [u8], b: &[u8]) {
    a.iter_mut().zip(b.iter()).for_each(|(x, y)| *x ^= y);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An arbitrary destination, fixed so tests compare like with like.
    fn dst_ia() -> IsdAsn {
        IsdAsn::from_u64(0x0001_FF00_0000_0110)
    }

    fn cipher() -> Aes128Enc {
        Aes128Enc::new(&[0x22u8; 16].into())
    }

    fn bw(bytes_per_sec: u64) -> Bandwidth {
        Bandwidth::from_bytes_per_sec(bytes_per_sec).expect("representable")
    }

    #[test]
    fn flyover_mac_matches_the_go_reference_vector() {
        // Generated with the Go reference implementation. The aggregated MAC is what the wire
        // carries; the flyover MAC is that XORed with the standard SCION MAC, which is what this
        // function computes. Nothing else in this module ties the computation to the reference —
        // every other test here would pass just as well against a subtly wrong block layout.
        let aggregated = [0x39, 0xe6, 0x85, 0x2b, 0x6e, 0x88];
        let scion_mac = [0xc8, 0xca, 0x9c, 0xeb, 0x30, 0x60];
        let mut expected = aggregated;
        xor_in_place(&mut expected, &scion_mac);

        let auth_key: HbirdAuthKey = [
            0x66, 0x58, 0x4c, 0xd6, 0x05, 0x01, 0x16, 0xc2, 0x28, 0xcc, 0x3b, 0x4d, 0xc2, 0xc9,
            0xcc, 0x56,
        ];
        let cipher = Aes128Enc::new(&auth_key.into());

        let mac = flyover_mac(
            IsdAsn::from_u64(0x0001_FF00_0000_0112),
            22,  // pkt_len
            3,   // res_start_offset
            352, // millis_timestamp, i.e. (0x5800_0000 >> 22) & 0x3FF
            0,   // counter
            &cipher,
        );

        assert_eq!(mac, expected);
    }

    #[test]
    fn every_mac_input_reaches_the_block() {
        // Guards the block layout in the cheapest way that catches a field written to the wrong
        // offset or not written at all: change one input, expect a different MAC.
        let base = flyover_mac(dst_ia(), 100, 7, 5, 9, &cipher());

        assert_ne!(
            base,
            flyover_mac(
                IsdAsn::from_u64(0x0001_FF00_0000_0111),
                100,
                7,
                5,
                9,
                &cipher()
            )
        );
        assert_ne!(base, flyover_mac(dst_ia(), 101, 7, 5, 9, &cipher()));
        assert_ne!(base, flyover_mac(dst_ia(), 100, 8, 5, 9, &cipher()));
        assert_ne!(base, flyover_mac(dst_ia(), 100, 7, 6, 9, &cipher()));
        assert_ne!(base, flyover_mac(dst_ia(), 100, 7, 5, 10, &cipher()));
    }

    #[test]
    fn the_key_selects_the_mac() {
        // The reservation's key is what makes the MAC unforgeable; a computation that ignored it
        // would still satisfy every layout test above.
        let other = Aes128Enc::new(&[0x33u8; 16].into());
        assert_ne!(
            flyover_mac(dst_ia(), 100, 7, 5, 9, &cipher()),
            flyover_mac(dst_ia(), 100, 7, 5, 9, &other),
        );
    }

    #[test]
    fn the_millis_timestamp_is_truncated_to_ten_bits() {
        // 1024 == 0b100_0000_0000: its low ten bits are zero, so it must be indistinguishable
        // from zero.
        assert_eq!(
            flyover_mac(dst_ia(), 100, 0, 1024, 0, &cipher()),
            flyover_mac(dst_ia(), 100, 0, 0, 0, &cipher()),
        );
    }

    #[test]
    fn the_counter_is_truncated_to_twenty_two_bits() {
        assert_eq!(
            flyover_mac(dst_ia(), 100, 0, 0, 1 << 22, &cipher()),
            flyover_mac(dst_ia(), 100, 0, 0, 0, &cipher()),
        );
    }

    #[test]
    fn the_millis_timestamp_does_not_bleed_into_the_counter() {
        // The two share one 32-bit word. Without the masks a millis value of 1 would be
        // indistinguishable from a counter of 4_194_304 — a collision neither field's own
        // truncation test would catch, because each is correct in isolation.
        assert_ne!(
            flyover_mac(dst_ia(), 100, 0, 1, 0, &cipher()),
            flyover_mac(dst_ia(), 100, 0, 0, 0, &cipher()),
        );
        assert_ne!(
            flyover_mac(dst_ia(), 100, 0, 1, 0, &cipher()),
            flyover_mac(dst_ia(), 100, 0, 0, 1 << 22, &cipher()),
        );
    }

    #[test]
    fn a_derived_key_is_a_function_of_its_reservation() {
        // Deriving twice from the same parameters must give the same key: the AS derives it once
        // to hand out, the router derives it again to verify, and a packet only forwards if the
        // two agree.
        let sv: HbirdKey = [0x11; 16];
        let derive = || derive_auth_key(2, 3, 0x1234, bw(1024), 1_700_000_000, 60, &sv);

        assert_eq!(derive(), derive());

        let cipher = Aes128Enc::new(&derive().into());
        assert_ne!(
            flyover_mac(dst_ia(), 100, 5, 1, 0, &cipher),
            [0u8; 6],
            "an all-zero MAC would mean the cipher never ran"
        );
    }

    #[test]
    fn changing_any_reservation_parameter_changes_the_derived_key() {
        // Guards the derivation block layout the same way the MAC's layout is guarded. Two
        // different reservations sharing a key would let one be used in place of the other.
        let sv: HbirdKey = [0x11; 16];
        let base = derive_auth_key(2, 3, 0x1234, bw(1024), 1_700_000_000, 60, &sv);

        assert_ne!(
            base,
            derive_auth_key(9, 3, 0x1234, bw(1024), 1_700_000_000, 60, &sv)
        );
        assert_ne!(
            base,
            derive_auth_key(2, 9, 0x1234, bw(1024), 1_700_000_000, 60, &sv)
        );
        assert_ne!(
            base,
            derive_auth_key(2, 3, 0x9999, bw(1024), 1_700_000_000, 60, &sv)
        );
        assert_ne!(
            base,
            derive_auth_key(2, 3, 0x1234, bw(2048), 1_700_000_000, 60, &sv)
        );
        assert_ne!(
            base,
            derive_auth_key(2, 3, 0x1234, bw(1024), 1_700_000_001, 60, &sv)
        );
        assert_ne!(
            base,
            derive_auth_key(2, 3, 0x1234, bw(1024), 1_700_000_000, 61, &sv)
        );
        assert_ne!(
            base,
            derive_auth_key(2, 3, 0x1234, bw(1024), 1_700_000_000, 60, &[0x12; 16])
        );
    }

    #[test]
    fn the_res_id_does_not_bleed_into_the_bandwidth() {
        // The mirror of the millis/counter case: ResID and BW share a 32-bit word, and the
        // res_id mask is what keeps a 23-bit id from corrupting the bandwidth it is packed with.
        let sv: HbirdKey = [0x11; 16];
        let with_high_bit = derive_auth_key(2, 3, 1 << 22, bw(1024), 1_700_000_000, 60, &sv);
        let without = derive_auth_key(2, 3, 0, bw(1024), 1_700_000_000, 60, &sv);

        assert_eq!(with_high_bit, without, "bit 22 of res_id is not carried");
    }

    #[test]
    fn xor_in_place_stops_at_the_shorter_slice() {
        let mut a = [0xFFu8; 6];
        xor_in_place(&mut a, &[0x0F, 0x0F]);
        assert_eq!(a, [0xF0, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF]);
    }
}
