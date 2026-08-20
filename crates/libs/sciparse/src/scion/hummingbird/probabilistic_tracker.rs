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

//! Bandwidth-proportional reservation selection, without bandwidth enforcement.

use std::time::SystemTime;

use super::{
    Reservation,
    tracker::{ReservationTracker, ReservationTrackerError, Selected},
};

/// Spreads traffic across a hop's reservations in proportion to their reserved bandwidth, keeping
/// no per-reservation state.
///
/// Over many packets each reservation carries a share of the traffic equal to its share of the
/// reserved bandwidth. Selection costs a validity check per candidate and a single random draw:
/// no map, no hashing, no accounting, so [`commit`][Self::commit] does nothing.
///
/// # Enforcement
///
/// This tracker does **not** limit the rate at which a reservation is used. It matches the
/// *expected* split between reservations, but nothing bounds the absolute rate, so a sender can
/// overrun a reservation and have the on-path routers drop those packets. Use
/// [`TokenBucketTracker`][super::token_bucket_tracker::TokenBucketTracker] where client-side
/// enforcement is required; this one trades enforcement for speed.
///
/// # Concurrency
///
/// The tracker carries no state: selection draws from the thread-local generator, so it takes
/// `&self`, needs no lock, and threads resolve fully in parallel. A generator per thread spreads
/// traffic exactly as well as one shared between them.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProbabilisticTracker;

impl ProbabilisticTracker {
    /// Creates a tracker.
    ///
    /// Selection draws from the thread-local generator and is therefore not reproducible from a
    /// seed; the tests assert the distribution over many draws rather than an exact sequence.
    pub fn new() -> Self {
        Self
    }
}

impl ReservationTracker for ProbabilisticTracker {
    /// Draws one of the currently valid `reservations`, each with probability proportional to its
    /// reserved bandwidth.
    ///
    /// `max_pkt_len` is ignored: this tracker enforces no bandwidth limit, so packet size does not
    /// affect which reservation is usable.
    fn select<'a>(
        &self,
        reservations: &'a [Reservation],
        now: SystemTime,
        _max_pkt_len: usize,
    ) -> Result<Option<Selected<'a>>, ReservationTrackerError> {
        if reservations.is_empty() {
            return Ok(None);
        }

        // Weighted reservoir sampling: one pass, no allocation, and no need to know the total
        // bandwidth up front. Replacing the running choice with probability w/total-so-far leaves
        // each candidate selected with probability w/total, which is what proportional spreading
        // means.
        let mut total: u64 = 0;
        let mut num_expired = 0;
        let mut selected = None;

        for reservation in reservations {
            if !reservation.is_valid_at(now) {
                num_expired += 1;
                continue;
            }

            let weight = reservation.info().bandwidth.to_bytes_per_sec();
            if weight == 0 {
                continue;
            }

            total += weight;
            if rand::random_range(0..total) < weight {
                selected = Some(reservation);
            }
        }

        match selected {
            Some(reservation) => Ok(Some(Selected::untracked(reservation))),
            // Expiry is the more useful diagnosis than exhaustion when nothing was even in its
            // validity window.
            None if num_expired == reservations.len() => {
                Err(ReservationTrackerError::ReservationExpired)
            }
            // Every remaining candidate reserved no bandwidth at all.
            None => Err(ReservationTrackerError::BandwidthExceeded),
        }
    }

    /// Does nothing: this tracker keeps no state to account against.
    fn commit(&self, _selected: &Selected<'_>, _pkt_len: usize) {}
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::{
        super::test_support::{reservation, reservation_for},
        *,
    };

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    const START: u64 = 1_700_000_000;
    const DRAWS: usize = 10_000;

    #[test]
    fn traffic_splits_in_proportion_to_reserved_bandwidth() {
        // The draw is from the thread-local generator, so this asserts the distribution over many
        // draws rather than an exact sequence. The band is wide enough that the test does not
        // flake: at a 1:3 split over 10_000 draws the standard deviation is about 0.4%.
        let candidates = vec![
            reservation(1, 1024, at(START)),
            reservation(2, 3072, at(START)),
        ];
        let tracker = ProbabilisticTracker::new();

        let mut second = 0usize;
        for _ in 0..DRAWS {
            let selected = tracker
                .select(&candidates, at(START), 100)
                .expect("both are valid")
                .expect("a candidate was available");
            if selected.reservation.info().res_id == 2 {
                second += 1;
            }
        }

        let share = second as f64 / DRAWS as f64;
        assert!((0.70..0.80).contains(&share), "expected ~0.75, got {share}");
    }

    #[test]
    fn an_expired_candidate_is_never_selected() {
        // A filter that passed everything would still produce a plausible-looking split above.
        let candidates = vec![
            reservation_for(1, 1_000_000, at(START), 60),
            reservation(2, 1024, at(START)),
        ];
        let tracker = ProbabilisticTracker::new();

        for _ in 0..DRAWS {
            let selected = tracker
                .select(&candidates, at(START + 3600), 100)
                .expect("one candidate is still valid")
                .expect("a candidate was available");
            assert_eq!(selected.reservation.info().res_id, 2);
        }
    }

    #[test]
    fn a_zero_bandwidth_candidate_is_never_selected() {
        // A zero weight contributes nothing to the total, so drawing against it would divide by
        // zero on the first candidate and otherwise select it with probability zero anyway.
        let candidates = vec![
            reservation(1, 0, at(START)),
            reservation(2, 1024, at(START)),
        ];
        let tracker = ProbabilisticTracker::new();

        for _ in 0..DRAWS {
            let selected = tracker
                .select(&candidates, at(START), 100)
                .expect("one candidate reserves bandwidth")
                .expect("a candidate was available");
            assert_eq!(selected.reservation.info().res_id, 2);
        }
    }

    #[test]
    fn all_candidates_expired_reports_expiry() {
        // Renewing the reservation and buying more bandwidth are different actions for the
        // caller, so the two refusals stay distinguishable.
        let candidates = vec![reservation_for(1, 1024, at(START), 60)];

        assert!(matches!(
            ProbabilisticTracker::new().select(&candidates, at(START + 3600), 100),
            Err(ReservationTrackerError::ReservationExpired)
        ));
    }

    #[test]
    fn candidates_reserving_no_bandwidth_report_exhaustion() {
        let candidates = vec![reservation(1, 0, at(START))];

        assert!(matches!(
            ProbabilisticTracker::new().select(&candidates, at(START), 100),
            Err(ReservationTrackerError::BandwidthExceeded)
        ));
    }

    #[test]
    fn a_hop_with_no_reservations_yields_no_selection() {
        // Distinct from a refusal: there was nothing to choose from, which is not a failure.
        assert!(matches!(
            ProbabilisticTracker::new().select(&[], at(START), 100),
            Ok(None)
        ));
    }

    #[test]
    fn the_packet_length_does_not_affect_selection() {
        // This tracker enforces no limit, so a packet larger than the whole reservation is still
        // carried by it — the routers, not the sender, drop the overrun.
        let candidates = vec![reservation(1, 1024, at(START))];
        let tracker = ProbabilisticTracker::new();

        let selected = tracker
            .select(&candidates, at(START), 1_000_000)
            .expect("the length is ignored")
            .expect("a candidate was available");

        assert_eq!(selected.reservation.info().res_id, 1);
    }
}
