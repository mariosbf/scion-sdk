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

//! Per-packet cost of Hummingbird path encoding, against regular SCION paths.
//!
//! # What is being compared, and why it is not symmetric
//!
//! A regular (standard) SCION path has a *static* dataplane header: the bytes
//! are fixed for the lifetime of the path, so sending a packet reuses them.
//! The realistic per-packet cost is therefore a [`bytes::Bytes`] refcount
//! clone; `deep_copy` bounds the case where the sender needs its own buffer.
//! Neither touches a MAC.
//!
//! A Hummingbird path cannot do that. Each flyover hop field authenticates a
//! per-packet timestamp, counter and packet length, so every packet re-derives
//! every flyover MAC and rewrites the header. That asymmetry *is* the result:
//! these benchmarks measure how large it is and what it scales with.
//!
//! # Axes
//!
//! - `hops` — hop fields in the path. Drives header length and per-hop work.
//! - `fly` — how many of those hops carry a reservation, and so encode as flyover hop fields. Each
//!   costs one MAC derivation plus aggregation.
//! - `res` — reservations *per flyover hop*. A hop may hold several; the tracker picks one per
//!   packet, scanning all of them. Invisible on the wire, so it moves CPU cost without moving
//!   header bytes.
//! - tracker — `none`, [`TokenBucketTracker`] (selects and enforces bandwidth),
//!   [`ProbabilisticTracker`] (selects by bandwidth, enforces nothing), and either wrapped in
//!   [`Lenient`] (unusable hops degrade to standard hop fields instead of failing the encode).
//!
//! # Groups
//!
//! - `e1-hops` — scaling in path length, at zero and full reservation coverage, against the
//!   standard-path baseline at the same length.
//! - `e2-flyovers` — path length held fixed, coverage swept 0..hops. The slope is the marginal cost
//!   of one reservation.
//! - `e3-trackers` — one configuration, every tracker. The gap between token-bucket and
//!   probabilistic is what bandwidth *enforcement* costs; the gap to `none` is what selection
//!   costs.
//! - `e4-candidates` — reservations per hop swept with the path shape fixed. Isolates tracker
//!   selection, which is linear in candidates.
//! - `e5-fallback` — reservations present but unusable, so hops degrade to standard hop fields.
//!   This misses the precomputed template (which is laid out for full coverage) and takes the
//!   general encoding path instead.
//!
//! Every timed configuration is asserted, outside the timed loop, to encode
//! the number of flyovers it is supposed to — otherwise a silently degraded
//! encode would be reported as a fast one.

use std::{
    hint::black_box,
    sync::{Arc, Mutex},
};

use chrono::{Duration, Utc};
use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, criterion_group, criterion_main, measurement::WallTime,
};
use scion_proto::{
    address::IsdAsn,
    hummingbird::{Bandwidth, Reservation, ReservationInfo},
    path::{
        InfoField, StandardHopField,
        hummingbird::{
            HbirdAuthKey, HummingbirdPath, Lenient, ProbabilisticTracker, ReservationTracker,
            TokenBucketTracker,
        },
    },
};

/// Payload of a full-size data packet; the length is authenticated by every
/// flyover MAC, so it is an input to the encode rather than a bystander.
const PAYLOAD_LEN: u16 = 1200;
const ADDRESS_HEADER_LEN: u16 = 24;

/// Reserved bandwidth near the encoding maximum (~67 GB/s). The token buckets
/// refill far faster than any benchmark loop drains them, so a tracked encode
/// never falls back and the timed loop stays in one regime.
const FAT_BW: u64 = 60_000_000_000;

/// One byte per second: the bucket cannot carry even one packet, so every
/// selection against it fails. Used only by `e5-fallback`.
const STARVED_BW: u64 = 1;

/// Fixed seed: reservation selection must not vary between benchmark runs.
const PROB_SEED: u64 = 0x5EED;

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

/// A reservation for `hop_idx`. `res_idx` distinguishes the candidates on one
/// hop: it goes into `res_id`, which is what a tracker keys its per-reservation
/// state on, so each candidate gets its own bucket.
fn reservation(hop_idx: u8, res_idx: u32, bandwidth: u64) -> Reservation {
    Reservation::new(
        ReservationInfo {
            isd_as: destination(),
            ingress_interface: hop_idx as u16,
            egress_interface: hop_idx as u16 + 1,
            res_id: 1000 + hop_idx as u32 * 100 + res_idx,
            bandwidth: Bandwidth::from_bytes_per_sec(bandwidth).unwrap(),
            start: Utc::now() - Duration::seconds(60),
            duration: u16::MAX,
        },
        HbirdAuthKey::from([0xAB; 16]),
    )
}

/// A single-segment path of `hops` hops, the first `flyovers` of which carry
/// `per_hop` reservations each. `bandwidth_for` sets the reserved bandwidth of
/// hop `i`, which is how `e5-fallback` starves selected hops and no other
/// group does.
fn path_with(
    hops: u8,
    flyovers: u8,
    per_hop: u32,
    bandwidth_for: impl Fn(u8) -> u64,
) -> HummingbirdPath {
    assert!(
        flyovers <= hops,
        "cannot reserve more hops than the path has"
    );

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
        for res in 0..per_hop {
            path.add_reservation(hop, reservation(hop, res, bandwidth_for(hop)))
                .unwrap();
        }
    }

    path
}

/// The common case: every reservation has bandwidth to spare.
fn path(hops: u8, flyovers: u8, per_hop: u32) -> HummingbirdPath {
    path_with(hops, flyovers, per_hop, |_| FAT_BW)
}

fn tracker(t: impl ReservationTracker + 'static) -> Arc<Mutex<dyn ReservationTracker>> {
    Arc::new(Mutex::new(t))
}

/// Times one encode configuration, having first checked outside the timed loop
/// that it encodes `expect_flyovers` flyover hop fields. Without that check a
/// tracker that quietly refused every hop would be timed as a fast standard
/// encode and reported as a fast *Hummingbird* one.
fn bench_encode(
    group: &mut BenchmarkGroup<'_, WallTime>,
    variant: &str,
    hops: u8,
    flyovers: u8,
    per_hop: u32,
    expect_flyovers: usize,
    path: HummingbirdPath,
) {
    let destination = destination();
    let encoded = path
        .to_encoded(destination, PAYLOAD_LEN, ADDRESS_HEADER_LEN)
        .unwrap();
    assert_eq!(
        encoded.flyover_hop_fields().count(),
        expect_flyovers,
        "{variant}: hops={hops} fly={flyovers} res={per_hop} encoded the wrong shape"
    );

    let id = BenchmarkId::new(variant, format!("hops={hops},fly={flyovers},res={per_hop}"));
    group.bench_with_input(id, &path, |b, path| {
        b.iter(|| {
            path.to_encoded(
                black_box(destination),
                black_box(PAYLOAD_LEN),
                black_box(ADDRESS_HEADER_LEN),
            )
            .unwrap()
        })
    });
}

/// Attaches `tracker` to a freshly built path and times it. A tracker is
/// stateful, so each configuration gets its own rather than sharing one.
fn bench_tracked(
    group: &mut BenchmarkGroup<'_, WallTime>,
    variant: &str,
    tracker: &Option<Arc<Mutex<dyn ReservationTracker>>>,
    hops: u8,
    flyovers: u8,
    per_hop: u32,
) {
    let mut p = path(hops, flyovers, per_hop);
    if let Some(t) = tracker {
        p.set_reservation_tracker(t.clone());
    }
    bench_encode(
        group,
        variant,
        hops,
        flyovers,
        per_hop,
        flyovers as usize,
        p,
    );
}

/// The wire bytes of a regular SCION path with one segment of `hops` hops:
/// 4-byte meta header, one 8-byte info field, 12 bytes per hop field.
fn standard_path_bytes(hops: u8) -> bytes::Bytes {
    let meta: u32 = (hops as u32) << 12;
    let mut v = Vec::from(meta.to_be_bytes());
    v.extend_from_slice(b"\x01\x00\x13\x37\x65\x00\x00\x00");
    for i in 0..hops {
        v.extend_from_slice(&[0, 63, 0, i, 0, i + 1, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42]);
    }
    bytes::Bytes::from(v)
}

/// The regular-path baseline at `hops` hops: what a sender pays per packet for
/// a path whose header never changes. `clone` is the realistic cost (share the
/// cached encoding); `deepcopy` bounds the case where the sender needs a
/// private buffer. `fly` and `res` are pinned to zero so that the results table
/// stays rectangular across both path types.
fn bench_standard(group: &mut BenchmarkGroup<'_, WallTime>, hops: u8) {
    use scion_proto::{path::EncodedStandardPath, wire_encoding::WireDecode};

    let param = format!("hops={hops},fly=0,res=0");
    let bytes = standard_path_bytes(hops);
    let decoded = EncodedStandardPath::decode(&mut bytes.clone()).unwrap();

    group.bench_with_input(BenchmarkId::new("std-clone", &param), &bytes, |b, bytes| {
        b.iter(|| black_box(bytes.clone()))
    });
    group.bench_with_input(
        BenchmarkId::new("std-deepcopy", &param),
        &decoded,
        |b, path| b.iter(|| black_box(path.deep_copy())),
    );
}

/// Path lengths swept. 1--6 covers the intra- and inter-ISD paths a SCION
/// endhost actually sees; 8 and 10 extend the line far enough to separate a
/// per-hop slope from a fixed offset.
const HOPS: [u8; 8] = [1, 2, 3, 4, 5, 6, 8, 10];

/// The path length the other groups hold fixed. Six hops is a typical
/// inter-ISD path and leaves room to sweep coverage either side of half.
const FIXED_HOPS: u8 = 6;

fn make_tracker(name: &str) -> Option<Arc<Mutex<dyn ReservationTracker>>> {
    match name {
        "none" => None,
        "tokenbucket" => Some(tracker(TokenBucketTracker::new())),
        "probabilistic" => Some(tracker(ProbabilisticTracker::with_seed(PROB_SEED))),
        "lenient-tokenbucket" => Some(tracker(Lenient(TokenBucketTracker::new()))),
        other => panic!("unknown tracker {other}"),
    }
}

/// E1 — how encoding cost scales with path length, for a regular path, an
/// unreserved Hummingbird path, and a fully reserved one.
///
/// `fly=0` under a tracker is a null control: a path with no reservations
/// never consults its tracker, so those points must match `none` exactly.
fn bench_e1_hops(c: &mut Criterion) {
    let mut group = c.benchmark_group("e1-hops");

    for hops in HOPS {
        bench_standard(&mut group, hops);
        for name in ["none", "tokenbucket"] {
            let t = make_tracker(name);
            bench_tracked(&mut group, &format!("hbird-{name}"), &t, hops, 0, 1);
            let t = make_tracker(name);
            bench_tracked(&mut group, &format!("hbird-{name}"), &t, hops, hops, 1);
        }
    }

    group.finish()
}

/// E2 — path length fixed, reservation coverage swept from none to full. The
/// slope is the marginal cost of one more flyover: one MAC derivation, one
/// aggregation step, and eight more bytes of header.
fn bench_e2_flyovers(c: &mut Criterion) {
    let mut group = c.benchmark_group("e2-flyovers");

    for flyovers in 0..=FIXED_HOPS {
        for name in ["none", "tokenbucket"] {
            let t = make_tracker(name);
            bench_tracked(
                &mut group,
                &format!("hbird-{name}"),
                &t,
                FIXED_HOPS,
                flyovers,
                1,
            );
        }
    }

    group.finish()
}

/// E3 — one fully reserved path, every tracker. `none` isolates the encode
/// itself; `probabilistic` adds selection without enforcement; `tokenbucket`
/// adds enforcement on top; the `Lenient` wrapper adds the fallback check.
fn bench_e3_trackers(c: &mut Criterion) {
    let mut group = c.benchmark_group("e3-trackers");

    for name in [
        "none",
        "probabilistic",
        "tokenbucket",
        "lenient-tokenbucket",
    ] {
        let t = make_tracker(name);
        bench_tracked(
            &mut group,
            &format!("hbird-{name}"),
            &t,
            FIXED_HOPS,
            FIXED_HOPS,
            1,
        );
    }

    group.finish()
}

/// E4 — reservations per hop swept with the path shape held fixed. Candidates
/// are invisible on the wire, so any movement here is tracker selection alone,
/// which scans every candidate on every hop of every packet.
fn bench_e4_candidates(c: &mut Criterion) {
    let mut group = c.benchmark_group("e4-candidates");

    for per_hop in [1u32, 2, 4, 8, 16] {
        for name in ["probabilistic", "tokenbucket"] {
            let t = make_tracker(name);
            bench_tracked(
                &mut group,
                &format!("hbird-{name}"),
                &t,
                FIXED_HOPS,
                FIXED_HOPS,
                per_hop,
            );
        }
    }

    group.finish()
}

/// One `e5-fallback` case: its name, the reserved bandwidth it gives hop `i`,
/// and how many flyover hop fields that leaves the encode with.
type FallbackCase = (&'static str, fn(u8) -> u64, usize);

/// E5 — reservations present but unusable, so hops degrade to standard hop
/// fields.
///
/// The precomputed template is laid out for *full* coverage, so any degraded
/// hop changes the header shape and the encode takes the general path instead
/// of patching the template. The all-usable point is the same configuration
/// with nothing starved, and is what the other two are read against.
fn bench_e5_fallback(c: &mut Criterion) {
    let mut group = c.benchmark_group("e5-fallback");
    let half = FIXED_HOPS / 2;

    let cases: [FallbackCase; 3] = [
        ("usable", |_| FAT_BW, FIXED_HOPS as usize),
        (
            "half-starved",
            |hop| {
                if hop < FIXED_HOPS / 2 {
                    FAT_BW
                } else {
                    STARVED_BW
                }
            },
            half as usize,
        ),
        ("all-starved", |_| STARVED_BW, 0),
    ];

    for (case, bandwidth_for, expect) in cases {
        let mut p = path_with(FIXED_HOPS, FIXED_HOPS, 1, bandwidth_for);
        p.set_reservation_tracker(make_tracker("lenient-tokenbucket").unwrap());
        bench_encode(
            &mut group,
            &format!("hbird-lenient-{case}"),
            FIXED_HOPS,
            FIXED_HOPS,
            1,
            expect,
            p,
        );
    }

    group.finish()
}

/// Enough samples that the confidence interval is tight at nanosecond scale,
/// and enough measurement time that each sample averages many iterations,
/// without the whole suite outgrowing a single reservation.
fn config() -> Criterion {
    Criterion::default()
        .sample_size(200)
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(3))
}

criterion_group! {
    name = benches;
    config = config();
    targets =
        bench_e1_hops,
        bench_e2_flyovers,
        bench_e3_trackers,
        bench_e4_candidates,
        bench_e5_fallback,
}
criterion_main!(benches);
