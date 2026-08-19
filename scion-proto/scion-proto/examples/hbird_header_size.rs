// Copyright 2025 Anapaya Systems
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

//! Emits the *wire* cost of Hummingbird paths as CSV on stdout.
//!
//! The companion to the `hummingbird_path` benchmark, which measures the CPU
//! cost. Every packet that carries a Hummingbird path also carries a longer
//! dataplane header than the equivalent regular SCION path, because each
//! reserved hop encodes as a 20-byte flyover hop field instead of a 12-byte
//! standard one, and the meta header grows by 8 bytes for the per-packet
//! timestamp and counter. That is bandwidth the reservation does not deliver.
//!
//! Sizes are taken from real encodes rather than from a formula, so the
//! numbers cannot drift away from the implementation. Run with:
//!
//! ```text
//! cargo run --release -p scion-proto --example hbird_header_size
//! ```

use std::sync::{Arc, Mutex};

use chrono::{Duration, Utc};
use scion_proto::{
    address::IsdAsn,
    hummingbird::{Bandwidth, Reservation, ReservationInfo},
    path::{
        InfoField, StandardHopField,
        hummingbird::{HbirdAuthKey, HummingbirdPath, ReservationTracker, TokenBucketTracker},
    },
};

/// The payload each overhead percentage is quoted against: a full-size data
/// packet, where the header is at its least significant. Shorter packets pay
/// proportionally more.
const PAYLOAD_LEN: u16 = 1200;
const ADDRESS_HEADER_LEN: u16 = 24;

fn destination() -> IsdAsn {
    "1-ff00:0:110".parse().unwrap()
}

fn hop_field(idx: u16) -> StandardHopField {
    StandardHopField {
        ingress_router_alert: false,
        egress_router_alert: false,
        exp_time: 63,
        cons_ingress: idx,
        cons_egress: idx + 1,
        mac: [0x42; 6],
    }
}

fn reservation(hop_idx: u8) -> Reservation {
    Reservation::new(
        ReservationInfo {
            isd_as: destination(),
            ingress_interface: hop_idx as u16,
            egress_interface: hop_idx as u16 + 1,
            res_id: 1000 + hop_idx as u32,
            bandwidth: Bandwidth::from_bytes_per_sec(60_000_000_000).unwrap(),
            start: Utc::now() - Duration::seconds(60),
            duration: u16::MAX,
        },
        HbirdAuthKey::from([0xAB; 16]),
    )
}

/// The encoded header length of a Hummingbird path with `hops` hops, the first
/// `flyovers` of which are reserved.
fn hbird_header_len(hops: u8, flyovers: u8) -> usize {
    let mut path = HummingbirdPath::new();
    let info = InfoField {
        peer: false,
        cons_dir: true,
        seg_id: 0x1337,
        timestamp_epoch: Utc::now().timestamp() as u32,
    };
    let fields = (0..hops).map(|i| (None, hop_field(i as u16))).collect();
    path.add_segment(info, fields).unwrap();
    for hop in 0..flyovers {
        path.add_reservation(hop, reservation(hop)).unwrap();
    }

    // A tracker is attached so that the encode exercises the same selection
    // path a real sender takes; the bandwidth is far above what one packet
    // consumes, so every reserved hop does become a flyover.
    let tracker: Arc<Mutex<dyn ReservationTracker>> =
        Arc::new(Mutex::new(TokenBucketTracker::new()));
    path.set_reservation_tracker(tracker);

    let encoded = path
        .to_encoded(destination(), PAYLOAD_LEN, ADDRESS_HEADER_LEN)
        .expect("path encodes");
    assert_eq!(
        encoded.flyover_hop_fields().count(),
        flyovers as usize,
        "hops={hops} fly={flyovers}: not every reservation was applied"
    );
    encoded.raw().len()
}

/// The encoded header length of the equivalent regular SCION path: 4-byte meta
/// header, one 8-byte info field, 12 bytes per hop field.
fn standard_header_len(hops: u8) -> usize {
    4 + 8 + 12 * hops as usize
}

fn main() {
    println!("hops,flyovers,std_header_bytes,hbird_header_bytes,delta_bytes,overhead_pct");

    for hops in 1u8..=10 {
        for flyovers in 0..=hops {
            let std = standard_header_len(hops);
            let hbird = hbird_header_len(hops, flyovers);
            let delta = hbird as i64 - std as i64;
            // Against the whole packet a regular path would have sent, so the
            // figure is the extra bandwidth Hummingbird costs at equal payload.
            let base = std + ADDRESS_HEADER_LEN as usize + PAYLOAD_LEN as usize;
            let pct = 100.0 * delta as f64 / base as f64;
            println!("{hops},{flyovers},{std},{hbird},{delta},{pct:.3}");
        }
    }
}
