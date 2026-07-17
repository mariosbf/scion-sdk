use std::{
    collections::HashMap,
    time::{Duration, Instant, SystemTime},
};

use chrono::{DateTime, Utc};

use crate::{address::IsdAsn, hummingbird::ReservationInfo};

use super::token_bucket::TokenBucket;

/// Error returned by a Hummingbird reservation tracker.
#[derive(Debug, thiserror::Error)]
pub enum ReservationTrackerError {
    /// The reservation has expired.
    #[error("reservation expired")]
    ReservationExpired,
    /// Reserved bandwidth exceeded.
    #[error("bandwidth exceeded")]
    BandwidthExceeded,
}

/// Client-side token-bucket enforcer for Hummingbird reservations.
#[derive(Debug)]
pub struct ReservationTracker {
    token_buckets: HashMap<(IsdAsn, u32, DateTime<Utc>), (SystemTime, TokenBucket)>,
    last_cleanup: Instant,
    cleanup_interval: Duration,
}

impl ReservationTracker {
    /// Creates a new [`ReservationTracker`].
    pub fn new() -> Self {
        Self {
            token_buckets: HashMap::new(),
            last_cleanup: Instant::now(),
            cleanup_interval: Duration::from_secs(60),
        }
    }

    fn cleanup_if_due(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) >= self.cleanup_interval {
            let sys_now = SystemTime::now();
            self.token_buckets.retain(|_, (end, _)| *end > sys_now);
            self.last_cleanup = now;
        }
    }

    fn bucket_for(&mut self, reservation: &ReservationInfo) -> &mut TokenBucket {
        &mut self
            .token_buckets
            .entry((reservation.isd_as, reservation.res_id, reservation.start))
            .or_insert_with(|| {
                (
                    reservation.end().into(),
                    TokenBucket::new(
                        reservation.start().into(),
                        reservation.bandwidth.to_bytes_per_sec() as i64,
                        reservation.bandwidth,
                    ),
                )
            })
            .1
    }

    /// Check time validity and bandwidth availability without deducting tokens.
    ///
    /// Call [`deduct_reservation`] after a successful check to consume the tokens.
    pub fn check_reservation(
        &mut self,
        reservation: &ReservationInfo,
        num_bytes: usize,
    ) -> Result<(), ReservationTrackerError> {
        self.cleanup_if_due();
        let now = Utc::now();

        if reservation.start() > now || now > reservation.end() {
            return Err(ReservationTrackerError::ReservationExpired);
        }

        if self.bucket_for(reservation).check(num_bytes, now.into()) {
            Ok(())
        } else {
            Err(ReservationTrackerError::BandwidthExceeded)
        }
    }

    /// Deduct `num_bytes` from the reservation's token bucket.
    ///
    /// Caller must have called [`check_reservation`] first to confirm availability.
    /// No-op if the bucket does not exist.
    pub fn deduct_reservation(&mut self, reservation: &ReservationInfo, num_bytes: usize) {
        if let Some((_, bucket)) = self.token_buckets.get_mut(&(
            reservation.isd_as,
            reservation.res_id,
            reservation.start,
        )) {
            bucket.use_unchecked(num_bytes);
        }
    }

    /// Returns the number of bytes currently available for `reservation` at this instant.
    ///
    /// Returns 0 if the reservation is expired or has no remaining tokens.
    pub fn available_bytes(&mut self, reservation: &ReservationInfo) -> usize {
        let now = Utc::now();

        if reservation.start() > now || now > reservation.end() {
            return 0;
        }

        self.bucket_for(reservation).available_at(now.into()).max(0) as usize
    }

    /// Check and, on success, deduct `pkt_size` bytes from the reservation's token bucket.
    pub fn use_reservation(
        &mut self,
        reservation: &ReservationInfo,
        num_bytes: usize,
    ) -> Result<(), ReservationTrackerError> {
        let now = Utc::now();

        if reservation.start() > now || now > reservation.end() {
            return Err(ReservationTrackerError::ReservationExpired);
        }

        if self
            .bucket_for(reservation)
            .use_checked(num_bytes, now.into())
        {
            Ok(())
        } else {
            Err(ReservationTrackerError::BandwidthExceeded)
        }
    }
}

impl Default for ReservationTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration as ChronoDuration;

    use super::*;
    use crate::{
        address::{Asn, Isd},
        hummingbird::Bandwidth,
    };

    fn make_reservation(
        res_id: u32,
        start: DateTime<Utc>,
        bw_bytes_per_sec: u64,
    ) -> ReservationInfo {
        ReservationInfo {
            isd_as: IsdAsn::new(Isd::new(1), Asn::new(1)),
            ingress_interface: 1,
            egress_interface: 2,
            res_id,
            bandwidth: Bandwidth::from_bytes_per_sec(bw_bytes_per_sec).unwrap(),
            start,
            duration: 60,
        }
    }

    #[test]
    fn different_start_times_get_independent_buckets() {
        let mut tracker = ReservationTracker::new();
        let now = Utc::now();

        let res_a = make_reservation(42, now - ChronoDuration::seconds(10), 1024);
        let res_b = make_reservation(42, now - ChronoDuration::seconds(5), 1024);

        // Exhaust res_a's bucket entirely.
        tracker.use_reservation(&res_a, 1024).unwrap();
        assert!(tracker.use_reservation(&res_a, 1).is_err());

        // res_b shares (isd_as, res_id) with res_a but has a different start time, so it
        // must have gotten its own, untouched bucket.
        tracker.use_reservation(&res_b, 1024).unwrap();
    }

    #[test]
    fn same_start_time_shares_bucket() {
        let mut tracker = ReservationTracker::new();
        let start = Utc::now() - ChronoDuration::seconds(10);

        let res_a = make_reservation(42, start, 1024);
        let res_a_again = make_reservation(42, start, 1024);

        tracker.use_reservation(&res_a, 1024).unwrap();
        assert!(matches!(
            tracker.use_reservation(&res_a_again, 1),
            Err(ReservationTrackerError::BandwidthExceeded)
        ));
    }
}
