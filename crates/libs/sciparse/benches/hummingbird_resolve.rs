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

//! What it costs to put a Hummingbird path on the wire, per packet.
//!
//! Two criterion groups, each sweeping a different axis of the same cost model.
//!
//! `hummingbird_resolve` runs four groups over the same paths, so the differences between them
//! isolate one cost each:
//!
//! | group | tracker | adds |
//! |---|---|---|
//! | `standard` | n/a | the baseline a Hummingbird path is paid for against |
//! | `untracked` | none | the encoding: template copy, MAC minting, patching |
//! | `probabilistic` | [`ProbabilisticTracker`] | selection, without enforcement |
//! | `tracked` | [`TokenBucketTracker`] | lock acquisition, replenishment, commit |
//!
//! So *probabilistic − untracked* is what selection costs and *tracked − probabilistic* is what
//! client-side enforcement costs. Hop counts are swept so the per-hop slope is visible, and all
//! four groups run together so the numbers are comparable without cross-run noise.
//!
//! `hummingbird_candidates` holds the path fixed at 6 hops, all reserved, and instead sweeps how
//! many candidate reservations are offered at *each* hop:
//!
//! | group | held fixed | swept | isolates |
//! |---|---|---|---|
//! | `hummingbird_candidates` | 6 hops, all reserved | reservations per hop, 1–16 | tracker
//!   selection alone — candidates are invisible on the wire |
//!
//! Selection scans every candidate on every hop for every packet, so its cost grows with
//! candidate count while the encoded bytes do not: exactly one flyover per hop is chosen and
//! written regardless of how many were offered. That makes this group a probe of the tracker's
//! selection algorithm in isolation from `hummingbird_resolve`'s hop-count slope.

use std::{
    hint::black_box,
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use sciparse::{
    address::{addr::ScionAddr, ip_addr::ScionIpAddr},
    core::{encode::WireEncode, model::Model, view::View},
    dataplane_path::{
        hbird::view::{HbirdHopFieldView, HbirdPathView},
        resolve::PacketFrame,
        standard::{
            model::{HopField, InfoField, Segment, StandardPath},
            types::{HopFieldFlags, HopFieldMac, InfoFieldFlags},
        },
        view::ScionDpPathView,
    },
    header::model::AddressHeader,
    hummingbird::{
        Bandwidth, Reservation, ReservationInfo, probabilistic_tracker::ProbabilisticTracker,
        token_bucket_tracker::TokenBucketTracker, tracker::ReservationTracker,
    },
    identifier::isd_asn::IsdAsn,
    path::ScionPath,
};

/// Hop counts to sweep. Real paths in a test topology run from 2 to 11 hop fields.
const HOP_COUNTS: [usize; 5] = [2, 4, 6, 8, 11];

/// Hop count `hummingbird_candidates` holds fixed while it sweeps candidates per hop.
const CANDIDATES_HOP_COUNT: usize = 6;

/// Candidate reservations offered per hop, swept by `hummingbird_candidates`.
const CANDIDATE_COUNTS: [usize; 5] = [1, 2, 4, 8, 16];

/// Payload size the packet-rate ceiling is quoted at.
const PAYLOAD_BYTES: u16 = 1200;

/// Reservation bandwidth, near the maximum the wire format can express.
///
/// A token bucket starts holding one second's worth of its rate and the benchmark's clock is
/// frozen, so nothing refills during a run. At this rate that is tens of millions of packets of
/// headroom — far more than a run will draw — which keeps the `tracked` group measuring
/// enforcement rather than quietly turning into a demoting group.
const RESERVATION_BYTES_PER_SEC: u64 = 1 << 35;

fn ia(asn: u64) -> IsdAsn {
    IsdAsn(0x1_ff00_0000_0000 | asn)
}

/// The instant every resolution in the benchmark is stamped with.
///
/// Frozen so the loop makes no clock call and every iteration does identical work. The
/// duplicate-detection counter still advances per packet, as it does in production.
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000)
}

/// A single-segment path of `hops` hop fields, so every hop can carry a flyover.
///
/// One segment on purpose: a crossover would make one hop per boundary unreservable, and the
/// figure being measured is cost per *flyover*, not per hop field.
fn standard_path(hops: usize) -> ScionPath {
    let hop_fields = (0..hops as u16)
        .map(|index| {
            HopField {
                flags: HopFieldFlags::empty(),
                expiration_units: 63,
                cons_ingress: index,
                cons_egress: index + 1,
                mac: HopFieldMac::zero(),
            }
        })
        .collect();

    let path = StandardPath {
        current_info_field: 0,
        current_hop_field: 0,
        segments: [Segment {
            info_field: InfoField {
                flags: InfoFieldFlags::CONS_DIR,
                segment_id: 7,
                timestamp: 1_800_000_000,
            },
            hop_fields,
        }]
        .into_iter()
        .collect(),
    };

    ScionPath::new(
        ia(0x110),
        ia(0x112),
        ScionDpPathView::Standard(path.try_encode_to_owned_view().expect("encodes")),
        None,
        None,
    )
}

/// `standard_path`, with `candidates` reservations on every hop and `tracker` attached.
///
/// Each hop's candidates get distinct `res_id`s. The tracker keys its buckets by reservation
/// identity, so reusing one id across candidates would collapse them into a single bucket and
/// silently benchmark 1 candidate no matter what `candidates` says.
fn reserved_path_with_candidates(
    hops: usize,
    candidates: usize,
    tracker: Option<Arc<dyn ReservationTracker>>,
) -> ScionPath {
    let mut path = standard_path(hops);

    for index in 0..hops {
        for candidate in 0..candidates {
            path.add_reservation_at(
                index,
                Reservation::new(
                    ReservationInfo {
                        isd_as: ia(0x110),
                        ingress_interface: index as u16,
                        egress_interface: index as u16 + 1,
                        res_id: (index * candidates + candidate) as u32,
                        bandwidth: Bandwidth::from_bytes_per_sec(RESERVATION_BYTES_PER_SEC)
                            .expect("representable"),
                        start: now() - Duration::from_secs(60),
                        duration: u16::MAX,
                    },
                    [0x11; 16],
                ),
            )
            .expect("a standard path takes an indexed reservation");
        }
    }

    if let Some(tracker) = tracker {
        path.set_tracker(tracker).expect("standard path");
    }

    path
}

/// `standard_path`, with one reservation on every hop and `tracker` attached.
fn reserved_path(hops: usize, tracker: Option<Arc<dyn ReservationTracker>>) -> ScionPath {
    reserved_path_with_candidates(hops, 1, tracker)
}

fn address() -> AddressHeader {
    AddressHeader::new(
        ScionAddr::from(ScionIpAddr::new(ia(0x110), Ipv4Addr::LOCALHOST.into())),
        ScionAddr::from(ScionIpAddr::new(
            ia(0x112),
            Ipv4Addr::new(127, 0, 0, 2).into(),
        )),
    )
}

/// Resolves once and checks the path came out the shape this group claims to measure.
///
/// Run outside the timed loop, and the most important line in this file. A tracker that refused
/// every hop would encode a plain standard path in a fraction of the time and be reported as a
/// Hummingbird figure — a benchmark measuring the wrong thing while looking perfectly healthy.
fn assert_shape(path: &ScionPath, expected_flyovers: usize, label: &str) {
    let frame = PacketFrame::new(&address(), PAYLOAD_BYTES, now());
    let resolved = path.resolve(frame).expect("resolves");

    let mut buf = vec![0u8; resolved.required_size()];
    resolved.try_encode(&mut buf).expect("encodes");

    // A group expecting no flyovers must not even be a Hummingbird path: resolution falls back to
    // the standard path when nothing was selected, and that is the shape the baseline measures.
    let flyovers = match HbirdPathView::try_from_slice(&buf) {
        Ok((view, _rest)) => {
            view.hop_fields()
                .filter(HbirdHopFieldView::is_flyover)
                .count()
        }
        Err(_) => 0,
    };

    assert_eq!(
        flyovers, expected_flyovers,
        "{label}: expected {expected_flyovers} flyovers, encoded {flyovers}"
    );
}

fn resolve_and_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("hummingbird_resolve");
    // One element per packet, so criterion reports the single-core packet-rate ceiling directly.
    group.throughput(Throughput::Elements(1));

    for hops in HOP_COUNTS {
        let cases: [(&str, ScionPath, usize); 4] = [
            ("standard", standard_path(hops), 0),
            ("untracked", reserved_path(hops, None), hops),
            (
                "probabilistic",
                reserved_path(hops, Some(Arc::new(ProbabilisticTracker::new()))),
                hops,
            ),
            (
                "tracked",
                reserved_path(hops, Some(Arc::new(TokenBucketTracker::new()))),
                hops,
            ),
        ];

        for (label, path, expected_flyovers) in cases {
            // Also warms the token bucket tracker's slab, so the first timed iteration is not the
            // one that allocates every bucket.
            assert_shape(&path, expected_flyovers, label);

            let frame = PacketFrame::new(&address(), PAYLOAD_BYTES, now());
            let mut buf = vec![0u8; 1024];

            group.bench_with_input(BenchmarkId::new(label, hops), &hops, |b, _| {
                b.iter(|| {
                    let resolved = path.resolve(black_box(frame)).expect("resolves");
                    let written = resolved
                        .try_encode(&mut buf[..resolved.required_size()])
                        .expect("encodes");
                    black_box(written)
                })
            });
        }
    }

    group.finish();
}

/// Sweeps candidates per hop at a fixed 6-hop, fully-reserved path, for the two trackers that
/// actually select among candidates. `standard`/`untracked` have no candidate-selection cost to
/// probe (untracked always takes the first reservation it sees), so they are not repeated here —
/// `hummingbird_resolve` already covers them.
fn candidates_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("hummingbird_candidates");
    // One element per packet, so criterion reports the single-core packet-rate ceiling directly.
    group.throughput(Throughput::Elements(1));

    for candidates in CANDIDATE_COUNTS {
        let cases: [(&str, ScionPath); 2] = [
            (
                "probabilistic",
                reserved_path_with_candidates(
                    CANDIDATES_HOP_COUNT,
                    candidates,
                    Some(Arc::new(ProbabilisticTracker::new())),
                ),
            ),
            (
                "tracked",
                reserved_path_with_candidates(
                    CANDIDATES_HOP_COUNT,
                    candidates,
                    Some(Arc::new(TokenBucketTracker::new())),
                ),
            ),
        ];

        for (label, path) in cases {
            // Also warms the token bucket tracker's slab, so the first timed iteration is not the
            // one that allocates every bucket.
            assert_shape(&path, CANDIDATES_HOP_COUNT, label);

            let frame = PacketFrame::new(&address(), PAYLOAD_BYTES, now());
            let mut buf = vec![0u8; 1024];

            group.bench_with_input(BenchmarkId::new(label, candidates), &candidates, |b, _| {
                b.iter(|| {
                    let resolved = path.resolve(black_box(frame)).expect("resolves");
                    let written = resolved
                        .try_encode(&mut buf[..resolved.required_size()])
                        .expect("encodes");
                    black_box(written)
                })
            });
        }
    }

    group.finish();
}

criterion_group!(benches, resolve_and_encode, candidates_sweep);
criterion_main!(benches);
