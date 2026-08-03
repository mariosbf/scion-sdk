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

#![allow(missing_docs)]

//! Benchmarks for encoding Hummingbird paths.
//!
//! Measures [`HummingbirdPath::to_encoded`] over paths with a varying number
//! of hops and flyover reservations. The zero-flyover configurations serve as
//! the baseline; the difference to the flyover configurations is the cost of
//! applying reservations (flyover MAC computation and aggregation).
//!
//! No reservation tracker is attached, so no token-bucket state is consumed
//! and repeated encoding of the same path is stable across iterations.

use std::hint::black_box;

use chrono::{Duration, Utc};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use scion_proto::{
    address::IsdAsn,
    hummingbird::{Bandwidth, Reservation, ReservationInfo},
    path::{
        InfoField, StandardHopField,
        hummingbird::{HbirdAuthKey, HummingbirdPath},
    },
};

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
    Reservation {
        info: ReservationInfo {
            isd_as: destination(),
            ingress_interface: hop_idx as u16,
            egress_interface: hop_idx as u16 + 1,
            res_id: 1000 + hop_idx as u32,
            bandwidth: Bandwidth::from_bytes_per_sec(1_000_000).unwrap(),
            start: Utc::now() - Duration::seconds(60),
            duration: u16::MAX,
        },
        reservation_key: HbirdAuthKey::from([0xAB; 16]),
    }
}

/// Builds a single-segment path with `num_hops` hops, the first `num_flyovers`
/// of which carry a reservation.
fn path(num_hops: u8, num_flyovers: u8) -> HummingbirdPath {
    assert!(num_flyovers <= num_hops);

    let mut path = HummingbirdPath::new();
    let info = InfoField {
        peer: false,
        cons_dir: true,
        seg_id: 0x1337,
        timestamp_epoch: Utc::now().timestamp() as u32,
    };
    let hops = (0..num_hops).map(|i| (None, hop_field(i as u16))).collect();
    path.add_segment(info, hops).unwrap();

    for i in 0..num_flyovers {
        path.add_reservation(i, reservation(i)).unwrap();
    }

    path
}

fn bench_to_encoded(c: &mut Criterion) {
    let mut group = c.benchmark_group("HummingbirdPath::to_encoded");
    let destination = destination();

    for (num_hops, num_flyovers) in [(2, 0), (2, 2), (6, 0), (6, 3), (6, 6)] {
        let path = path(num_hops, num_flyovers);
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{num_hops}hops_{num_flyovers}flyovers")),
            &path,
            |b, path| {
                b.iter(|| {
                    path.to_encoded(
                        black_box(destination),
                        black_box(PAYLOAD_LEN),
                        black_box(ADDRESS_HEADER_LEN),
                    )
                    .unwrap()
                })
            },
        );
    }

    group.finish()
}

criterion_group!(benches, bench_to_encoded);
criterion_main!(benches);
