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
//! The untracked group attaches no reservation tracker, so no token-bucket
//! state is consumed and repeated encoding of the same path is stable across
//! iterations. The tracked group attaches a [`ReservationTracker`] in strict
//! mode, measuring the bandwidth-enforcement cost real senders pay; the
//! reservations' bandwidth (near the encoding maximum) refills the buckets
//! much faster than the benchmark drains them, so encoding never falls back.

use std::{
    hint::black_box,
    sync::{Arc, Mutex},
};

use chrono::{Duration, Utc};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use scion_proto::{
    address::IsdAsn,
    hummingbird::{Bandwidth, Reservation, ReservationInfo},
    path::{
        InfoField, StandardHopField,
        hummingbird::{HbirdAuthKey, HummingbirdPath, ReservationTracker},
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
    Reservation::new(
        ReservationInfo {
            isd_as: destination(),
            ingress_interface: hop_idx as u16,
            egress_interface: hop_idx as u16 + 1,
            res_id: 1000 + hop_idx as u32,
            // Near the encoding maximum (~67 GB/s), so that in the tracked
            // benchmarks the token buckets refill much faster than the
            // benchmark loop drains them. Irrelevant to the untracked group.
            bandwidth: Bandwidth::from_bytes_per_sec(60_000_000_000).unwrap(),
            start: Utc::now() - Duration::seconds(60),
            duration: u16::MAX,
        },
        HbirdAuthKey::from([0xAB; 16]),
    )
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

/// Same as [`bench_to_encoded`], but with a strict [`ReservationTracker`]
/// attached — the configuration real senders run with. Measures the added
/// cost of bandwidth enforcement: tracker lock, per-reservation expiry
/// checks, and token-bucket accounting. Strict mode makes the benchmark fail
/// loudly (instead of silently encoding standard hops) if a bucket ever runs
/// dry.
fn bench_to_encoded_tracked(c: &mut Criterion) {
    let mut group = c.benchmark_group("HummingbirdPath::to_encoded (tracked)");
    let destination = destination();

    for (num_hops, num_flyovers) in [(2, 2), (6, 0), (6, 3), (6, 6)] {
        let path = path(num_hops, num_flyovers).with_reservation_tracker(
            Arc::new(Mutex::new(ReservationTracker::new())),
            true,
        );

        // Sanity check outside the timed loop: every reservation must
        // actually be applied, otherwise the benchmark measures fallback.
        let encoded = path
            .to_encoded(destination, PAYLOAD_LEN, ADDRESS_HEADER_LEN)
            .unwrap();
        assert_eq!(encoded.flyover_hop_fields().count(), num_flyovers as usize);

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

/// Builds the wire bytes of a standard SCION path with one segment of
/// `num_hops` hops: 4-byte meta header, one 8-byte info field, and 12 bytes
/// per hop field.
fn standard_path_bytes(num_hops: u8) -> bytes::Bytes {
    let meta: u32 = (num_hops as u32) << 12;
    let mut v = Vec::from(meta.to_be_bytes());
    // Info field: cons_dir flag, seg_id, timestamp.
    v.extend_from_slice(b"\x01\x00\x13\x37\x65\x00\x00\x00");
    for i in 0..num_hops {
        v.extend_from_slice(&[0, 63, 0, i, 0, i + 1, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42]);
    }
    bytes::Bytes::from(v)
}

/// Reference: the per-packet cost of using a regular (standard) SCION path,
/// whose wire bytes are static — either a `Bytes` refcount clone (reusing the
/// cached encoding) or a `deep_copy` (fresh allocation + memcpy).
fn bench_standard_reference(c: &mut Criterion) {
    use scion_proto::{path::EncodedStandardPath, wire_encoding::WireDecode};

    let mut group = c.benchmark_group("StandardPath reference");

    for num_hops in [2u8, 6] {
        let bytes = standard_path_bytes(num_hops);
        let path = EncodedStandardPath::decode(&mut bytes.clone()).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{num_hops}hops_bytes_clone")),
            &bytes,
            |b, bytes| b.iter(|| black_box(bytes.clone())),
        );
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{num_hops}hops_deep_copy")),
            &path,
            |b, path| b.iter(|| black_box(path.deep_copy())),
        );
    }

    group.finish()
}

criterion_group!(
    benches,
    bench_to_encoded,
    bench_to_encoded_tracked,
    bench_standard_reference
);
criterion_main!(benches);
