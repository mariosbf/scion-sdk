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

//! Does Hummingbird path resolution scale across sender threads?
//!
//! Every figure in the `hummingbird_resolve` benchmark is one thread on an idle core, so every
//! lock in it is uncontended by construction. But a path holds its tracker as
//! `Arc<dyn ReservationTracker>`, and resolution opens a packet session — taking that lock — once
//! per packet, holding it across selection, MAC minting and commit. Selection and commit have to
//! be one critical section or a concurrent commit can overtake a bandwidth check, so the lock is
//! not an accident of the implementation; it is what makes enforcement exact.
//!
//! A tracker shared between sender threads is therefore a serialisation point on the per-packet
//! path. This harness measures what that costs, by running `N` threads that do nothing but resolve
//! and encode, and counting how many packets per second come out in aggregate.
//!
//! Three arms make the answer interpretable:
//!
//! - `none` — no tracker at all. No lock exists, so this is the scaling ceiling the other arms are
//!   read against.
//! - `perthread-*` — every thread gets its own tracker. Same work per packet, same allocation, but
//!   no contention. Isolates the lock from everything else that might not scale (memory bandwidth,
//!   turbo headroom).
//! - `shared-*` — one tracker behind one mutex, as a multi-threaded sender built on this API today
//!   would have it.
//!
//! The `shared` threads deliberately use the *same* reservation ids, so they contend on the same
//! token buckets as well as the same mutex. That is the worst case and also the realistic one:
//! threads sharing a tracker are sharing it because they are sending over the same path.
//!
//! Note what is *not* measured here, because it no longer happens: a path carrying no reservations
//! never opens a session at all, so attaching a tracker when a path is handed out costs a sender
//! nothing until it actually reserves. Only paths with reservations reach the arms below.
//!
//! CSV on stdout. Run with:
//!
//! ```text
//! cargo run --release -p sciparse --example hbird_tracker_contention -- [seconds]
//! ```

use std::{
    hint::black_box,
    net::Ipv4Addr,
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

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

const PAYLOAD_LEN: u16 = 1200;
/// Six hops, all reserved — the reference configuration of the single-threaded suite, so the two
/// sets of numbers are directly comparable.
const HOPS: usize = 6;
/// Far above what the loop can consume, so no thread ever falls back to best effort and every arm
/// stays in one regime.
const FAT_BW: u64 = 60_000_000_000;
/// `Instant::now()` costs the same order as the work being timed, so the deadline is only checked
/// every this many packets.
const CHECK_EVERY: u64 = 256;

fn ia(asn: u64) -> IsdAsn {
    IsdAsn(0x1_ff00_0000_0000 | asn)
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

fn reservation(hop_idx: usize, start: SystemTime) -> Reservation {
    Reservation::new(
        ReservationInfo {
            isd_as: ia(0x110),
            ingress_interface: hop_idx as u16,
            egress_interface: hop_idx as u16 + 1,
            // The same ids in every thread, so shared arms contend on the same buckets.
            res_id: 1000 + hop_idx as u32,
            bandwidth: Bandwidth::from_bytes_per_sec(FAT_BW).expect("representable"),
            start: start - Duration::from_secs(60),
            duration: u16::MAX,
        },
        [0xAB; 16],
    )
}

/// A single-segment path of [`HOPS`] hops, every one of them reserved.
fn path(now: SystemTime) -> ScionPath {
    let timestamp = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_secs() as u32;

    let standard = StandardPath {
        current_info_field: 0,
        current_hop_field: 0,
        segments: [Segment {
            info_field: InfoField {
                flags: InfoFieldFlags::CONS_DIR,
                segment_id: 0x1337,
                timestamp,
            },
            hop_fields: (0..HOPS as u16)
                .map(|index| {
                    HopField {
                        flags: HopFieldFlags::empty(),
                        expiration_units: 63,
                        cons_ingress: index,
                        cons_egress: index + 1,
                        mac: HopFieldMac::new([0x42; 6]),
                    }
                })
                .collect(),
        }]
        .into_iter()
        .collect(),
    };

    let mut path = ScionPath::new(
        ia(0x110),
        ia(0x112),
        ScionDpPathView::Standard(standard.try_encode_to_owned_view().expect("encodes")),
        None,
        None,
    );
    for hop in 0..HOPS {
        path.add_reservation_at(hop, reservation(hop, now))
            .expect("a standard path takes an indexed reservation");
    }
    path
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    None,
    TokenBucket,
    Probabilistic,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::None => "none",
            Kind::TokenBucket => "tokenbucket",
            Kind::Probabilistic => "probabilistic",
        }
    }

    fn tracker(self) -> Option<Arc<dyn ReservationTracker>> {
        match self {
            Kind::None => None,
            Kind::TokenBucket => Some(Arc::new(TokenBucketTracker::new())),
            Kind::Probabilistic => Some(Arc::new(ProbabilisticTracker::new())),
        }
    }
}

/// Resolves and encodes one packet, returning its encoded length.
///
/// This is the whole of what a sender does per packet, and the whole of what is timed.
fn send_one(path: &ScionPath, frame: PacketFrame, buf: &mut [u8]) -> usize {
    let resolved = path.resolve(frame).expect("path resolves");
    let size = resolved.required_size();
    resolved.try_encode(&mut buf[..size]).expect("encodes");
    size
}

/// How many flyover hop fields an encoded path carries.
///
/// Only ever called during warm-up: parsing is not part of sending, and doing it in the timed loop
/// would charge every arm for it and flatten the differences the arms exist to show.
fn flyovers_in(encoded: &[u8]) -> usize {
    match HbirdPathView::try_from_slice(encoded) {
        Ok((view, _rest)) => {
            let view: &HbirdPathView = view;
            view.hop_fields()
                .filter(HbirdHopFieldView::is_flyover)
                .count()
        }
        Err(_) => 0,
    }
}

/// Runs `threads` senders for `secs` and returns (total packets, per-thread).
///
/// `shared` decides whether they contend: one tracker for all of them, or one each. With no
/// tracker the flag is meaningless and the arm runs once.
fn measure(kind: Kind, shared: bool, threads: usize, secs: u64) -> (u64, Vec<u64>) {
    let shared_tracker = if shared { kind.tracker() } else { None };
    let barrier = Arc::new(Barrier::new(threads));
    let counts: Vec<Arc<AtomicU64>> = (0..threads).map(|_| Arc::new(AtomicU64::new(0))).collect();

    std::thread::scope(|scope| {
        for counter in counts.iter() {
            let barrier = Arc::clone(&barrier);
            let counter = Arc::clone(counter);
            let tracker = match (&shared_tracker, shared) {
                (Some(tracker), true) => Some(Arc::clone(tracker)),
                (_, false) => kind.tracker(),
                _ => None,
            };

            scope.spawn(move || {
                let now = SystemTime::now();
                let mut path = path(now);
                if let Some(tracker) = tracker {
                    path.set_tracker(tracker).expect("standard path");
                }
                let frame = PacketFrame::new(&address(), PAYLOAD_LEN, now);
                let mut buf = vec![0u8; 1024];

                // Every thread sends once before the barrier, so first-touch costs (template
                // allocation, bucket creation, page faults) land outside the measured window
                // rather than inside its first milliseconds. The assertion is the same one the
                // benchmark makes: a degraded encode is far cheaper, and would be reported as a
                // Hummingbird figure.
                let size = send_one(&path, frame, &mut buf);
                assert_eq!(
                    flyovers_in(&buf[..size]),
                    HOPS,
                    "not every reservation was applied; this would time a degraded encode"
                );

                barrier.wait();
                let deadline = Instant::now() + Duration::from_secs(secs);
                let mut sent: u64 = 0;
                loop {
                    for _ in 0..CHECK_EVERY {
                        black_box(send_one(&path, black_box(frame), &mut buf));
                    }
                    sent += CHECK_EVERY;
                    if Instant::now() >= deadline {
                        break;
                    }
                }
                counter.store(sent, Ordering::Relaxed);
            });
        }
    });

    let per: Vec<u64> = counts.iter().map(|c| c.load(Ordering::Relaxed)).collect();
    (per.iter().sum(), per)
}

fn main() {
    let secs: u64 = std::env::args()
        .nth(1)
        .and_then(|arg| arg.parse().ok())
        .unwrap_or(5);

    println!(
        "arm,tracker,shared,threads,secs,total_packets,packets_per_sec,\
         ns_per_packet_per_thread,thread_min,thread_max,gbps_at_1200B"
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
            let per_sec = total as f64 / secs as f64;
            // Per-thread service time: what one packet costs a thread while `threads` of them are
            // running. Flat means it scales; rising means they are queueing on each other.
            let ns = 1e9 / (per_sec / threads as f64);
            println!(
                "{arm},{tracker},{shared},{threads},{secs},{total},{per_sec:.0},{ns:.1},{min},{max},{gbps:.2}",
                tracker = kind.label(),
                min = per.iter().min().expect("at least one thread"),
                max = per.iter().max().expect("at least one thread"),
                gbps = per_sec * PAYLOAD_LEN as f64 * 8.0 / 1e9,
            );
        }
    }
}
