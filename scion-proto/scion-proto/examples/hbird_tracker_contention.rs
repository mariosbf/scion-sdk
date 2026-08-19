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

//! Does Hummingbird path encoding scale across sender threads?
//!
//! Every figure in the `hummingbird_path` benchmark is one thread on an idle
//! core, so every lock in it is uncontended by construction. But a path holds
//! its tracker as `Arc<Mutex<dyn ReservationTracker>>`, and `to_encoded` takes
//! that lock **once per packet** — before it has even established whether any
//! hop carries a reservation. On a path with reservations the lock is held
//! across selection, the whole encode and the commit.
//!
//! So a tracker shared between sender threads is a global serialisation point
//! on the per-packet path. This harness measures what that costs, by running
//! `N` threads that do nothing but encode and counting how many encodes per
//! second come out in aggregate.
//!
//! Three arms make the answer interpretable:
//!
//! - `none` — no tracker at all. No lock exists, so this is the scaling ceiling the other arms are
//!   read against.
//! - `perthread-*` — every thread gets its own tracker. Same work per packet as `shared-*`, same
//!   allocation, but no contention. Isolates the lock from everything else that might not scale
//!   (memory bandwidth, turbo headroom).
//! - `shared-*` — one tracker behind one mutex, as a multi-threaded sender built on this API today
//!   would have it.
//!
//! The `shared` threads deliberately use the *same* reservation ids, so they
//! contend on the same token buckets as well as the same mutex. That is the
//! worst case and also the realistic one: threads sharing a tracker are
//! sharing it because they are sending over the same path.
//!
//! CSV on stdout. Run with:
//!
//! ```text
//! cargo run --release -p scion-proto --example hbird_tracker_contention -- [seconds]
//! ```

use std::{
    hint::black_box,
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use chrono::Utc;
use scion_proto::{
    address::IsdAsn,
    hummingbird::{Bandwidth, Reservation, ReservationInfo},
    path::{
        InfoField, StandardHopField,
        hummingbird::{
            HbirdAuthKey, HummingbirdPath, ProbabilisticTracker, ReservationTracker,
            TokenBucketTracker,
        },
    },
};

const PAYLOAD_LEN: u16 = 1200;
const ADDRESS_HEADER_LEN: u16 = 24;
/// Six hops, all reserved — the reference configuration of the single-threaded
/// suite, so the two sets of numbers are directly comparable.
const HOPS: u8 = 6;
/// Far above what the loop can consume, so no thread ever falls back and every
/// arm stays in one regime.
const FAT_BW: u64 = 60_000_000_000;
/// `Instant::now()` costs the same order as the work being timed, so the
/// deadline is only checked every this many encodes.
const CHECK_EVERY: u64 = 256;

fn destination() -> IsdAsn {
    "1-ff00:0:110".parse().unwrap()
}

fn reservation(hop_idx: u8) -> Reservation {
    Reservation::new(
        ReservationInfo {
            isd_as: destination(),
            ingress_interface: hop_idx as u16,
            egress_interface: hop_idx as u16 + 1,
            res_id: 1000 + hop_idx as u32,
            bandwidth: Bandwidth::from_bytes_per_sec(FAT_BW).unwrap(),
            start: Utc::now() - chrono::Duration::seconds(60),
            duration: u16::MAX,
        },
        HbirdAuthKey::from([0xAB; 16]),
    )
}

fn path() -> HummingbirdPath {
    let mut path = HummingbirdPath::new();
    let info = InfoField {
        peer: false,
        cons_dir: true,
        seg_id: 0x1337,
        timestamp_epoch: Utc::now().timestamp() as u32,
    };
    let hops = (0..HOPS)
        .map(|i| {
            (
                None,
                StandardHopField {
                    ingress_router_alert: false,
                    egress_router_alert: false,
                    exp_time: 63,
                    cons_ingress: i as u16,
                    cons_egress: i as u16 + 1,
                    mac: [0x42; 6],
                },
            )
        })
        .collect();
    path.add_segment(info, hops).unwrap();
    for hop in 0..HOPS {
        path.add_reservation(hop, reservation(hop)).unwrap();
    }
    path
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    None,
    TokenBucket,
    Probabilistic,
}

fn new_tracker(kind: Kind) -> Option<Arc<Mutex<dyn ReservationTracker>>> {
    match kind {
        Kind::None => None,
        Kind::TokenBucket => Some(Arc::new(Mutex::new(TokenBucketTracker::new()))),
        // Seeded per tracker rather than per thread: selection must not vary
        // between runs, and the arms differ in sharing, not in randomness.
        Kind::Probabilistic => {
            Some(Arc::new(Mutex::new(ProbabilisticTracker::with_seed(
                0x5EED,
            ))))
        }
    }
}

/// Runs `threads` encoders for `secs` and returns (total encodes, per-thread).
///
/// `shared` decides whether they contend: one tracker for all of them, or one
/// each. With no tracker the flag is meaningless and the arm runs once.
fn measure(kind: Kind, shared: bool, threads: usize, secs: u64) -> (u64, Vec<u64>) {
    let shared_tracker = if shared { new_tracker(kind) } else { None };
    let barrier = Arc::new(Barrier::new(threads));
    let counts: Vec<Arc<AtomicU64>> = (0..threads).map(|_| Arc::new(AtomicU64::new(0))).collect();

    std::thread::scope(|scope| {
        for counter in counts.iter() {
            let barrier = Arc::clone(&barrier);
            let counter = Arc::clone(counter);
            let tracker = match (&shared_tracker, shared) {
                (Some(t), true) => Some(Arc::clone(t)),
                (_, false) => new_tracker(kind),
                _ => None,
            };
            scope.spawn(move || {
                let mut path = path();
                if let Some(t) = tracker {
                    path.set_reservation_tracker(t);
                }
                let destination = destination();

                // Every thread encodes once before the barrier, so first-touch
                // costs (template allocation, bucket creation, page faults)
                // land outside the measured window rather than inside the
                // first milliseconds of it.
                let warm = path
                    .to_encoded(destination, PAYLOAD_LEN, ADDRESS_HEADER_LEN)
                    .expect("path encodes");
                assert_eq!(
                    warm.flyover_hop_fields().count(),
                    HOPS as usize,
                    "not every reservation was applied; this would time a degraded encode"
                );

                barrier.wait();
                let deadline = Instant::now() + Duration::from_secs(secs);
                let mut n: u64 = 0;
                loop {
                    for _ in 0..CHECK_EVERY {
                        black_box(
                            path.to_encoded(
                                black_box(destination),
                                black_box(PAYLOAD_LEN),
                                black_box(ADDRESS_HEADER_LEN),
                            )
                            .unwrap(),
                        );
                    }
                    n += CHECK_EVERY;
                    if Instant::now() >= deadline {
                        break;
                    }
                }
                counter.store(n, Ordering::Relaxed);
            });
        }
    });

    let per: Vec<u64> = counts.iter().map(|c| c.load(Ordering::Relaxed)).collect();
    (per.iter().sum(), per)
}

fn main() {
    let secs: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    println!(
        "arm,tracker,shared,threads,secs,total_encodes,encodes_per_sec,\
         ns_per_encode_per_thread,thread_min,thread_max,gbps_at_1200B"
    );

    let arms = [
        ("none", Kind::None, false),
        ("perthread-tokenbucket", Kind::TokenBucket, false),
        ("shared-tokenbucket", Kind::TokenBucket, true),
        ("perthread-probabilistic", Kind::Probabilistic, false),
        ("shared-probabilistic", Kind::Probabilistic, true),
    ];

    for (arm, kind, shared) in arms {
        for threads in [1usize, 2, 4, 8, 16] {
            let (total, per) = measure(kind, shared, threads, secs);
            let eps = total as f64 / secs as f64;
            // Per-thread service time: what one encode costs a thread while
            // `threads` of them are running. Flat means it scales; rising
            // means they are queueing on each other.
            let ns = 1e9 / (eps / threads as f64);
            println!(
                "{arm},{tracker},{shared},{threads},{secs},{total},{eps:.0},{ns:.1},{min},{max},{gbps:.2}",
                tracker = match kind {
                    Kind::None => "none",
                    Kind::TokenBucket => "tokenbucket",
                    Kind::Probabilistic => "probabilistic",
                },
                min = per.iter().min().unwrap(),
                max = per.iter().max().unwrap(),
                gbps = eps * PAYLOAD_LEN as f64 * 8.0 / 1e9,
            );
        }
    }
}
