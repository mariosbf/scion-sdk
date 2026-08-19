//! Bandwidth-proportional reservation selection, without bandwidth enforcement.

use std::time::SystemTime;

use super::reservation_tracker::{ReservationTracker, ReservationTrackerError, Selected};
use crate::hummingbird::Reservation;

/// Spreads traffic across a hop's reservations in proportion to their reserved
/// bandwidth, keeping no per-reservation state.
///
/// Over many packets each reservation carries a share of the traffic equal to
/// its share of the reserved bandwidth. Selection costs a validity check per
/// candidate and a single random draw — there is no map, no hashing, and no
/// token accounting, so [`Self::commit`] does nothing.
///
/// # Enforcement
///
/// This tracker does **not** limit the rate at which a reservation is used. It
/// matches the *expected* split between reservations, but nothing bounds the
/// absolute rate, so a sender can overrun a reservation and have the on-path
/// routers drop those packets. Use
/// [`TokenBucketTracker`][super::TokenBucketTracker] where client-side
/// enforcement is required; this one trades enforcement for speed.
///
/// # Concurrency
///
/// The tracker carries no state: selection draws from the thread-local
/// generator, so it takes `&self`, needs no lock, and threads encode fully in
/// parallel.
///
/// One tracker belongs to one path, so there was never cross-thread state to
/// keep here — only a generator, and a generator per thread spreads traffic
/// exactly as well as one shared between them.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProbabilisticTracker;

impl ProbabilisticTracker {
    /// Creates a tracker.
    ///
    /// Selection draws from the thread-local generator and is therefore not
    /// reproducible from a seed; the tests assert the distribution over many
    /// draws rather than an exact sequence.
    pub fn new() -> Self {
        Self
    }
}

impl ReservationTracker for ProbabilisticTracker {
    /// Draws one of the currently valid `reservations`, each with probability
    /// proportional to its reserved bandwidth.
    ///
    /// `max_pkt_len` is ignored: this tracker enforces no bandwidth limit, so
    /// packet size does not affect which reservation is usable.
    fn select<'a>(
        &self,
        reservations: &'a [Reservation],
        now: SystemTime,
        _max_pkt_len: usize,
    ) -> Result<Option<Selected<'a>>, ReservationTrackerError> {
        if reservations.is_empty() {
            return Ok(None);
        }

        // Weighted reservoir sampling: one pass, no allocation, and no need to
        // know the total bandwidth up front. Replacing the running choice with
        // probability w/total-so-far leaves each candidate selected with
        // probability w/total, which is what proportional spreading means.
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
            // Report expiry over exhaustion: if nothing was even in its validity
            // window, that is the more useful diagnosis.
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
    use chrono::{DateTime, Duration as ChronoDuration, Utc};

    use super::*;
    use crate::{
        address::{Asn, Isd, IsdAsn},
        hummingbird::{Bandwidth, ReservationInfo},
        path::hummingbird::{HbirdAuthKey, reservation_tracker::Ticket},
    };

    fn reservation(res_id: u32, bw_bytes_per_sec: u64, start: DateTime<Utc>) -> Reservation {
        Reservation::new(
            ReservationInfo {
                isd_as: IsdAsn::new(Isd::new(1), Asn::new(1)),
                ingress_interface: 1,
                egress_interface: 2,
                res_id,
                bandwidth: Bandwidth::from_bytes_per_sec(bw_bytes_per_sec).unwrap(),
                start,
                duration: 600,
            },
            HbirdAuthKey::from([0xAB; 16]),
        )
    }

    fn valid(res_id: u32, bw_bytes_per_sec: u64) -> Reservation {
        reservation(
            res_id,
            bw_bytes_per_sec,
            Utc::now() - ChronoDuration::seconds(1),
        )
    }

    fn expired(res_id: u32, bw_bytes_per_sec: u64) -> Reservation {
        reservation(
            res_id,
            bw_bytes_per_sec,
            Utc::now() - ChronoDuration::hours(2),
        )
    }

    /// Selects `trials` times and returns how often each reservation won, by index.
    fn tally(
        tracker: &mut ProbabilisticTracker,
        candidates: &[Reservation],
        trials: u32,
    ) -> Vec<u32> {
        let mut counts = vec![0; candidates.len()];
        let now = SystemTime::now();

        for _ in 0..trials {
            let selected = tracker.select(candidates, now, 1024).unwrap().unwrap();
            let idx = candidates
                .iter()
                .position(|c| c.info().res_id == selected.reservation.info().res_id)
                .unwrap();
            counts[idx] += 1;
        }

        counts
    }

    #[test]
    fn selection_is_proportional_to_bandwidth() {
        // 3:1 bandwidth ratio, so roughly a 75/25 split.
        let candidates = vec![valid(1, 3072), valid(2, 1024)];
        let mut tracker = ProbabilisticTracker::new();

        const TRIALS: u32 = 20_000;
        let counts = tally(&mut tracker, &candidates, TRIALS);

        let share = counts[0] as f64 / TRIALS as f64;
        assert!(
            (share - 0.75).abs() < 0.02,
            "expected ~75% on the wider reservation, got {share:.3}"
        );
    }

    #[test]
    fn every_candidate_is_reachable() {
        // Even a much narrower reservation must be selected sometimes,
        // otherwise the draw has collapsed to always picking the widest.
        let candidates = vec![valid(1, 65536), valid(2, 1024)];
        let mut tracker = ProbabilisticTracker::new();

        let counts = tally(&mut tracker, &candidates, 5_000);
        assert!(counts[1] > 0, "the narrow reservation was never selected");
    }

    #[test]
    fn expired_candidates_are_never_selected() {
        let candidates = vec![expired(1, 1_000_000), valid(2, 1024)];
        let mut tracker = ProbabilisticTracker::new();

        // The expired one has a thousand times the bandwidth, so weighting
        // alone would pick it almost every time.
        let counts = tally(&mut tracker, &candidates, 1_000);
        assert_eq!(counts[0], 0);
        assert_eq!(counts[1], 1_000);
    }

    #[test]
    fn all_expired_reports_expiry() {
        let candidates = vec![expired(1, 1024), expired(2, 1024)];
        let tracker = ProbabilisticTracker::new();

        assert!(matches!(
            tracker.select(&candidates, SystemTime::now(), 1024),
            Err(ReservationTrackerError::ReservationExpired)
        ));
    }

    #[test]
    fn empty_candidates_is_none_not_error() {
        let tracker = ProbabilisticTracker::new();
        assert!(
            tracker
                .select(&[], SystemTime::now(), 1024)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn selection_issues_no_ticket_and_commit_is_inert() {
        let candidates = vec![valid(1, 1024)];
        let tracker = ProbabilisticTracker::new();

        let selected = tracker
            .select(&candidates, SystemTime::now(), 1024)
            .unwrap()
            .unwrap();
        assert_eq!(selected.ticket, Ticket::NONE);

        // Committing must not make the reservation any less selectable.
        tracker.commit(&selected, 1024);
        assert!(
            tracker
                .select(&candidates, SystemTime::now(), 1024)
                .unwrap()
                .is_some()
        );
    }
}
