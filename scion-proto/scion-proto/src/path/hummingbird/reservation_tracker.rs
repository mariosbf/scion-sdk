use std::{
    collections::HashMap,
    ops::Deref,
    time::{Duration, Instant, SystemTime},
};

use crate::path::hummingbird::{EncodedFlyoverHopField, EncodedHummingbirdPath};

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
///
/// Keyed by `(res_id, hop_index)` so that different ASes on the path each have
/// an independent bucket, even when they share the same reservation ID.
#[derive(Debug)]
pub struct ReservationTracker {
    token_buckets: HashMap<(u32, usize), (SystemTime, TokenBucket)>,
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

    /// Returns the number of bytes that can be sent right now along `path` without
    /// exceeding any reservation, i.e., the minimum available tokens across all
    /// flyover hops.
    ///
    /// Returns `Ok(usize::MAX)` if the path has no flyover hops (no constraint).
    /// Returns `Err(ReservationTrackerError::ReservationExpired)` if any reservation
    /// has expired.
    ///
    /// Buckets that have not been seen before are initialised to their full burst
    /// capacity, so this method is safe to call before the first `apply`.
    pub fn available_bytes_for_path<T: Deref<Target = [u8]>>(
        &mut self,
        path: &EncodedHummingbirdPath<T>,
    ) -> Result<usize, ReservationTrackerError> {
        self.cleanup_if_due();

        let now = SystemTime::now();

        let flyover_hops: Vec<(usize, &EncodedFlyoverHopField)> = path
            .hop_fields()
            .enumerate()
            .filter_map(|(i, h)| {
                if h.is_flyover() {
                    h.try_into().ok().map(|fh| (i, fh))
                } else {
                    None
                }
            })
            .collect();

        if flyover_hops.is_empty() {
            return Ok(usize::MAX);
        }

        let mut min_available = i64::MAX;

        for (hop_idx, hop) in &flyover_hops {
            let reservation_duration = Duration::from_secs(hop.reservation_duration() as u64);
            if hop.reservation_start_offset() > reservation_duration {
                return Err(ReservationTrackerError::ReservationExpired);
            }

            let res_id = hop.reservation_id();
            let bandwidth = hop.bandwidth();
            let key = (res_id, *hop_idx);

            let reservation_start = path
                .meta_header()
                .base_timestamp_as_system_time()
                .checked_sub(hop.reservation_start_offset())
                .ok_or(ReservationTrackerError::ReservationExpired)?;

            let reservation_end = reservation_start.checked_add(reservation_duration).unwrap();

            let available = self
                .token_buckets
                .entry(key)
                .or_insert_with(|| {
                    (
                        reservation_end,
                        TokenBucket::new(
                            reservation_start,
                            (bandwidth.to_kbps() * 125) as i64,
                            bandwidth,
                        ),
                    )
                })
                .1
                .available_at(now);

            min_available = min_available.min(available);
        }

        Ok(min_available.max(0) as usize)
    }

    fn cleanup_if_due(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) >= self.cleanup_interval {
            let sys_now = SystemTime::now();
            self.token_buckets.retain(|_, (end, _)| *end > sys_now);
            self.last_cleanup = now;
        }
    }

    /// Check and, on success, deduct `pkt_size` bytes from each flyover hop's
    /// token bucket.
    ///
    /// `pkt_size` must be the total SCION packet size in bytes (common header +
    /// address header + path header + L4 header + L4 payload).
    pub fn apply<T: Deref<Target = [u8]>>(
        &mut self,
        path: &EncodedHummingbirdPath<T>,
        pkt_size: usize,
    ) -> Result<(), ReservationTrackerError> {
        self.cleanup_if_due();

        let pkt_timestamp = path.meta_header().timestamp();

        // Collect flyover hops with their original indices so each (res_id, hop_index)
        // pair maps to its own token bucket, even when multiple hops share a res_id.
        let flyover_hops: Vec<(usize, &EncodedFlyoverHopField)> = path
            .hop_fields()
            .enumerate()
            .filter_map(|(i, h)| {
                if h.is_flyover() {
                    h.try_into().ok().map(|fh| (i, fh))
                } else {
                    None
                }
            })
            .collect();

        // First pass: check every flyover hop's bucket without deducting.
        for (hop_idx, hop) in &flyover_hops {
            let reservation_duration = Duration::from_secs(hop.reservation_duration() as u64);
            if hop.reservation_start_offset() > reservation_duration {
                return Err(ReservationTrackerError::ReservationExpired);
            }

            let res_id = hop.reservation_id();
            let bandwidth = hop.bandwidth();
            let key = (res_id, *hop_idx);

            let reservation_start = path
                .meta_header()
                .base_timestamp_as_system_time()
                .checked_sub(hop.reservation_start_offset())
                .ok_or(ReservationTrackerError::ReservationExpired)?;

            let reservation_end = reservation_start.checked_add(reservation_duration).unwrap();

            if !self
                .token_buckets
                .entry(key)
                .or_insert_with(|| {
                    (
                        reservation_end,
                        TokenBucket::new(
                            reservation_start,
                            (bandwidth.to_kbps() * 125) as i64,
                            bandwidth,
                        ),
                    )
                })
                .1
                .check(pkt_size, pkt_timestamp)
            {
                return Err(ReservationTrackerError::BandwidthExceeded);
            }
        }

        // Second pass: deduct from every bucket that passed the check.
        for (hop_idx, hop) in &flyover_hops {
            let key = (hop.reservation_id(), *hop_idx);
            self.token_buckets
                .get_mut(&key)
                .unwrap()
                .1
                .use_unchecked(pkt_size);
        }

        Ok(())
    }
}

impl Default for ReservationTracker {
    fn default() -> Self {
        Self::new()
    }
}
