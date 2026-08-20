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

//! Hummingbird SCION path types and related structures.

use std::fmt::Debug;

use crate::dataplane_path::standard::types::HopFieldFlags;

// HbirdHopFieldFlags
bitflags::bitflags! {
    /// Flags byte of a Hummingbird hop field.
    ///
    /// This is the standard SCION hop field flags byte plus one bit: [`FLYOVER`](Self::FLYOVER),
    /// which says whether the hop field carries a flyover reservation and is therefore five lines
    /// long rather than three. The router-alert bits keep the positions they have in a standard
    /// hop field, because a Hummingbird hop field *is* a standard hop field with extra fields
    /// appended — see the compile-time check below.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
    pub struct HbirdHopFieldFlags: u8 {
        /// If ConsEgress Router Alert is set, the egress router in construction direction will
        /// process the L4 payload in the packet.
        const CONS_EGRESS_ROUTER_ALERT = 0b0000_0001;
        /// If ConsIngress Router Alert is set, the ingress router in construction direction will
        /// process the L4 payload in the packet.
        const CONS_INGRESS_ROUTER_ALERT = 0b0000_0010;
        /// Indicates that this hop field uses a flyover reservation.
        const FLYOVER = 0b1000_0000;

        // Other bits are reserved.
        const _ = !0;
    }
}

// A Hummingbird hop field's flags byte is the standard one with FLYOVER added, so the shared bits
// must sit in the same positions. Getting this wrong alerts the wrong router, which no test of
// either type alone would catch.
const _: () = {
    assert!(
        HbirdHopFieldFlags::CONS_INGRESS_ROUTER_ALERT.bits()
            == HopFieldFlags::CONS_INGRESS_ROUTER_ALERT.bits()
    );
    assert!(
        HbirdHopFieldFlags::CONS_EGRESS_ROUTER_ALERT.bits()
            == HopFieldFlags::CONS_EGRESS_ROUTER_ALERT.bits()
    );
};

impl HbirdHopFieldFlags {
    /// Bits shared with a standard hop field's flags byte.
    const STANDARD_BITS: u8 = !Self::FLYOVER.bits();

    /// Returns true if the ConsIngress Router Alert flag is set.
    #[inline]
    pub fn cons_ingress_router_alert(&self) -> bool {
        self.contains(HbirdHopFieldFlags::CONS_INGRESS_ROUTER_ALERT)
    }

    /// Returns true if the ConsEgress Router Alert flag is set.
    #[inline]
    pub fn cons_egress_router_alert(&self) -> bool {
        self.contains(HbirdHopFieldFlags::CONS_EGRESS_ROUTER_ALERT)
    }

    /// Returns true if the Flyover flag is set, i.e. this hop field carries a reservation.
    #[inline]
    pub fn is_flyover(&self) -> bool {
        self.contains(HbirdHopFieldFlags::FLYOVER)
    }

    /// Returns the normalized router alert flag based on the construction direction.
    ///
    /// If `cons_dir` is true, the construction direction is used as is. If false, the direction
    /// is reversed.
    #[inline]
    pub fn normalized_ingress_router_alert(&self, cons_dir: bool) -> bool {
        if cons_dir {
            self.cons_ingress_router_alert()
        } else {
            self.cons_egress_router_alert()
        }
    }

    /// Returns the normalized router alert flag based on the construction direction.
    ///
    /// If `cons_dir` is true, the construction direction is used as is. If false, the direction
    /// is reversed.
    #[inline]
    pub fn normalized_egress_router_alert(&self, cons_dir: bool) -> bool {
        if cons_dir {
            self.cons_egress_router_alert()
        } else {
            self.cons_ingress_router_alert()
        }
    }
}

impl From<HbirdHopFieldFlags> for HopFieldFlags {
    /// Drops the flyover bit; every other bit keeps its position.
    #[inline]
    fn from(val: HbirdHopFieldFlags) -> Self {
        HopFieldFlags::from_bits_retain(val.bits() & HbirdHopFieldFlags::STANDARD_BITS)
    }
}

impl From<HopFieldFlags> for HbirdHopFieldFlags {
    /// Clears the flyover bit: in a standard hop field that position is reserved, and reading it
    /// as a flyover would claim a reservation the hop field does not carry.
    #[inline]
    fn from(std_flags: HopFieldFlags) -> Self {
        HbirdHopFieldFlags::from_bits_retain(std_flags.bits() & HbirdHopFieldFlags::STANDARD_BITS)
    }
}

/// Support for [`proptest::arbitrary`].
#[cfg(feature = "proptest")]
pub mod ptest {
    use ::proptest::prelude::*;

    use super::*;

    impl Arbitrary for HbirdHopFieldFlags {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            any::<u8>()
                .prop_map(HbirdHopFieldFlags::from_bits_retain)
                .boxed()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flyover_bit_is_the_high_bit() {
        assert_eq!(HbirdHopFieldFlags::FLYOVER.bits(), 0b1000_0000);
    }

    #[test]
    fn is_flyover_reads_the_flyover_bit() {
        assert!(HbirdHopFieldFlags::from_bits_retain(0b1000_0000).is_flyover());
        assert!(!HbirdHopFieldFlags::from_bits_retain(0b0000_0011).is_flyover());
    }

    #[test]
    fn router_alert_bits_are_independent_of_flyover() {
        // 0b1000_0001 is a flyover with the *egress* alert set: bit 0 is egress, matching the
        // standard hop field and the Go reference implementation.
        let flags = HbirdHopFieldFlags::from_bits_retain(0b1000_0001);
        assert!(flags.is_flyover());
        assert!(flags.cons_egress_router_alert());
        assert!(!flags.cons_ingress_router_alert());
    }

    #[test]
    fn router_alert_bits_match_the_standard_hop_field() {
        // A Hummingbird hop field is a standard hop field with fields appended, so a flags byte
        // must mean the same thing read either way.
        for bits in 0u8..=255 {
            let hbird = HbirdHopFieldFlags::from_bits_retain(bits);
            let standard = HopFieldFlags::from_bits_retain(bits);
            assert_eq!(
                hbird.cons_ingress_router_alert(),
                standard.cons_ingress_router_alert(),
                "ingress alert disagrees for {bits:#010b}"
            );
            assert_eq!(
                hbird.cons_egress_router_alert(),
                standard.cons_egress_router_alert(),
                "egress alert disagrees for {bits:#010b}"
            );
        }
    }

    #[test]
    fn conversion_to_standard_flags_drops_only_the_flyover_bit() {
        let hbird = HbirdHopFieldFlags::FLYOVER
            | HbirdHopFieldFlags::CONS_INGRESS_ROUTER_ALERT
            | HbirdHopFieldFlags::CONS_EGRESS_ROUTER_ALERT;
        let standard: HopFieldFlags = hbird.into();

        assert!(standard.cons_ingress_router_alert());
        assert!(standard.cons_egress_router_alert());
        assert_eq!(standard.bits() & HbirdHopFieldFlags::FLYOVER.bits(), 0);
    }

    #[test]
    fn conversion_from_standard_flags_never_claims_a_flyover() {
        // Bit 7 is reserved in a standard hop field; it must not be read as a reservation.
        let standard = HopFieldFlags::from_bits_retain(0b1000_0010);
        let hbird: HbirdHopFieldFlags = standard.into();

        assert!(!hbird.is_flyover());
        assert!(hbird.cons_ingress_router_alert());
    }
}
