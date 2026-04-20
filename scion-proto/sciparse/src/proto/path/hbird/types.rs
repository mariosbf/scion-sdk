//! Hummingbird SCION path types and related structures.

use std::{fmt::Debug};

use crate::path::standard::types::StdHopFieldFlags;

// HopFieldFlags
bitflags::bitflags! {
    /// HopField flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct HbirdHopFieldFlags: u8 {
        /// If ConsIngress Router Alert is set, the ingress router in construction direction will process the L4 payload in the packet.
        const CONS_INGRESS_ROUTER_ALERT = 0b0000_0001;
        /// If ConsEgress Router Alert is set, the egress router in construction direction will process the L4 payload in the packet.
        const CONS_EGRESS_ROUTER_ALERT = 0b0000_0010;
        /// Flag that indicates whether this HopField is using a reservation 
        const FLYOVER = 0b1000_0000;

        // Other bits are reserved.
        const _ = !0;
    }
}
impl HbirdHopFieldFlags {
    /// Returns true if the ConsIngress Router Alert flag is set.
    pub fn cons_ingress_router_alert(&self) -> bool {
        self.contains(HbirdHopFieldFlags::CONS_INGRESS_ROUTER_ALERT)
    }

    /// Returns true if the ConsEgress Router Alert flag is set.
    pub fn cons_egress_router_alert(&self) -> bool {
        self.contains(HbirdHopFieldFlags::CONS_EGRESS_ROUTER_ALERT)
    }

    /// Returns true if the Flyover flag is set.
    pub fn flyover(&self) -> bool {
        self.contains(HbirdHopFieldFlags::FLYOVER)
    }

    /// Returns the normalized router alert flag based on the construction direction.
    ///
    /// If `cons_dir` is true, the construction direction is used as is. If false, the direction
    /// is reversed.
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
    pub fn normalized_egress_router_alert(&self, cons_dir: bool) -> bool {
        if cons_dir {
            self.cons_egress_router_alert()
        } else {
            self.cons_ingress_router_alert()
        }
    }
}

impl Into<StdHopFieldFlags> for HbirdHopFieldFlags {
    fn into(self) -> StdHopFieldFlags {
        let mut std_flags = StdHopFieldFlags::empty();
        if self.contains(HbirdHopFieldFlags::CONS_INGRESS_ROUTER_ALERT) {
            std_flags |= StdHopFieldFlags::CONS_INGRESS_ROUTER_ALERT;
        }
        if self.contains(HbirdHopFieldFlags::CONS_EGRESS_ROUTER_ALERT) {
            std_flags |= StdHopFieldFlags::CONS_EGRESS_ROUTER_ALERT;
        }
        std_flags
    }
}

impl From<StdHopFieldFlags> for HbirdHopFieldFlags {
    fn from(std_flags: StdHopFieldFlags) -> Self {
        let mut hbird_flags = HbirdHopFieldFlags::empty();
        if std_flags.contains(StdHopFieldFlags::CONS_INGRESS_ROUTER_ALERT) {
            hbird_flags |= HbirdHopFieldFlags::CONS_INGRESS_ROUTER_ALERT;
        }
        if std_flags.contains(StdHopFieldFlags::CONS_EGRESS_ROUTER_ALERT) {
            hbird_flags |= HbirdHopFieldFlags::CONS_EGRESS_ROUTER_ALERT;
        }
        hbird_flags
    }
}
