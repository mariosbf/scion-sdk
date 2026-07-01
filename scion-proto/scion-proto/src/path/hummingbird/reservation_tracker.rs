use std::{
    collections::HashMap,
    time::{Duration, Instant, SystemTime},
};

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
    token_buckets: HashMap<(IsdAsn, u32), (SystemTime, TokenBucket)>,
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

    fn bucket_for(
        &mut self,
        reservation: &ReservationInfo,
        res_start: SystemTime,
        res_end: SystemTime,
    ) -> &mut TokenBucket {
        &mut self
            .token_buckets
            .entry((reservation.isd_as, reservation.res_id))
            .or_insert_with(|| {
                (
                    res_end,
                    TokenBucket::new(
                        res_start,
                        (reservation.bandwidth.to_kbps() * 125) as i64,
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
        let res_start = std::time::UNIX_EPOCH + Duration::from_secs(reservation.start as u64);
        let res_end = res_start + Duration::from_secs(reservation.duration as u64);
        let now = SystemTime::now();

        if res_start > now || now > res_end {
            return Err(ReservationTrackerError::ReservationExpired);
        }

        if self
            .bucket_for(reservation, res_start, res_end)
            .check(num_bytes, now)
        {
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
        if let Some((_, bucket)) = self
            .token_buckets
            .get_mut(&(reservation.isd_as, reservation.res_id))
        {
            bucket.use_unchecked(num_bytes);
        }
    }

    /// Returns the number of bytes currently available for `reservation` at this instant.
    ///
    /// Returns 0 if the reservation is expired or has no remaining tokens.
    pub fn available_bytes(&mut self, reservation: &ReservationInfo) -> usize {
        let res_start = std::time::UNIX_EPOCH + Duration::from_secs(reservation.start as u64);
        let res_end = res_start + Duration::from_secs(reservation.duration as u64);
        let now = SystemTime::now();

        if res_start > now || now > res_end {
            return 0;
        }

        self.bucket_for(reservation, res_start, res_end)
            .available_at(now)
            .max(0) as usize
    }

    /// Check and, on success, deduct `pkt_size` bytes from the reservation's token bucket.
    pub fn use_reservation(
        &mut self,
        reservation: &ReservationInfo,
        num_bytes: usize,
    ) -> Result<(), ReservationTrackerError> {
        let res_start = std::time::UNIX_EPOCH + Duration::from_secs(reservation.start as u64);
        let res_end = res_start + Duration::from_secs(reservation.duration as u64);
        let now = SystemTime::now();

        if res_start > now || now > res_end {
            return Err(ReservationTrackerError::ReservationExpired);
        }

        if self
            .bucket_for(reservation, res_start, res_end)
            .use_checked(num_bytes, now)
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
