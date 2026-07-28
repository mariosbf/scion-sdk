use std::time::SystemTime;

use crate::hummingbird::Bandwidth;

#[derive(Debug)]
pub(super) struct TokenBucket {
    current_token: i64,
    current_nano_tokens: i64,
    last_time_applied: SystemTime,
    committed_burst_size: i64,
    committed_information_rate: i64,
}

impl TokenBucket {
    pub fn new(initial_time: SystemTime, burst_size: i64, rate: Bandwidth) -> Self {
        let rate_bytes_per_sec = bandwidth_to_bytes_per_sec(rate);
        Self {
            current_token: rate_bytes_per_sec,
            current_nano_tokens: 0,
            last_time_applied: initial_time,
            committed_burst_size: burst_size,
            committed_information_rate: rate_bytes_per_sec,
        }
    }

    /// Returns `true` if enough tokens are available and updates the replenishment clock.
    ///
    /// Does NOT deduct tokens; call `use_unchecked` after a successful check.
    pub fn check(&mut self, size: usize, now: SystemTime) -> bool {
        let size = size as i64;
        if let Ok(elapsed) = now.duration_since(self.last_time_applied) {
            // Saturating on purpose: elapsed_nanos * rate overflows i64 once
            // elapsed > i64::MAX / rate — at high reservation rates (e.g.
            // 66.6 GB/s, near the encoding max) that is only ~138 ms of
            // idle time. Saturation is semantically a full bucket: the token
            // count is clamped to committed_burst_size right below anyway.
            let new_nano_tokens = (elapsed.as_nanos() as i64)
                .saturating_mul(self.committed_information_rate)
                .saturating_add(self.current_nano_tokens);

            let new_full_tokens = new_nano_tokens / 1_000_000_000;
            self.current_nano_tokens = new_nano_tokens % 1_000_000_000;
            self.current_token =
                (self.current_token + new_full_tokens).min(self.committed_burst_size);
            self.last_time_applied = now;
        }
        self.current_token >= size
    }

    /// Deducts `size` bytes. Call only after `check` returns `true`.
    pub fn use_unchecked(&mut self, size: usize) {
        self.current_token -= size as i64;
    }

    /// Deducts `size` bytes if available. Returns whether the bytes were deducted.
    pub fn use_checked(&mut self, size: usize, now: SystemTime) -> bool {
        if self.check(size, now) {
            self.use_unchecked(size);
            true
        } else {
            false
        }
    }

    /// Returns the number of bytes available at `now` after replenishing, clamped to 0.
    ///
    /// Updates the replenishment clock (same side-effect as `check`).
    pub(super) fn available_at(&mut self, now: SystemTime) -> i64 {
        if let Ok(elapsed) = now.duration_since(self.last_time_applied) {
            // Saturating for the same overflow reason as in `check`.
            let new_nano_tokens = (elapsed.as_nanos() as i64)
                .saturating_mul(self.committed_information_rate)
                .saturating_add(self.current_nano_tokens);
            let new_full_tokens = new_nano_tokens / 1_000_000_000;
            self.current_nano_tokens = new_nano_tokens % 1_000_000_000;
            self.current_token =
                (self.current_token + new_full_tokens).min(self.committed_burst_size);
            self.last_time_applied = now;
        }
        self.current_token.max(0)
    }
}

fn bandwidth_to_bytes_per_sec(bw: Bandwidth) -> i64 {
    bw.to_bytes_per_sec() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn t(nanos: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_nanos(nanos)
    }

    // 1024 bytes/s is exactly representable in the 10-bit encoding.
    const RATE_BYTES_PER_SEC: i64 = 1024;

    fn bw(bytes_per_sec: u64) -> Bandwidth {
        Bandwidth::from_bytes_per_sec(bytes_per_sec).unwrap()
    }

    #[test]
    fn high_rate_long_gap_does_not_overflow() {
        // Regression: at rates near the encoding max (~66.6 GB/s),
        // elapsed_nanos * rate overflows i64 after ~138 ms of idle time.
        // The old checked_mul().unwrap() panicked here; saturation must
        // instead leave a (clamped) full bucket.
        let rate = 66_571_993_088u64; // 31 * 2^31 B/s, the 10-bit encoding max
        let mut bucket = TokenBucket::new(t(0), rate as i64, bw(rate));
        // One second of idle time: far past the overflow horizon.
        assert!(bucket.check(1500, t(1_000_000_000)));
        bucket.use_unchecked(1500);
        // Bucket is clamped to burst size, not saturated garbage.
        assert!(bucket.available_at(t(1_000_000_001)) <= rate as i64);
    }

    #[test]
    fn apply_allows_arrival_behind_last_arrival() {
        let mut bucket = TokenBucket::new(t(1), RATE_BYTES_PER_SEC, bw(RATE_BYTES_PER_SEC as u64));
        assert!(bucket.check(1, SystemTime::UNIX_EPOCH));
        bucket.use_unchecked(1);
    }

    #[test]
    fn full_bandwidth_consumed_at_once() {
        let mut bucket = TokenBucket::new(t(0), RATE_BYTES_PER_SEC, bw(RATE_BYTES_PER_SEC as u64));
        assert!(bucket.check(RATE_BYTES_PER_SEC as usize, t(0)));
        bucket.use_unchecked(RATE_BYTES_PER_SEC as usize);
        assert!(!bucket.check(1, t(0)));
    }

    #[test]
    fn full_bandwidth_consumed_over_multiple_packets() {
        let mut bucket = TokenBucket::new(t(0), RATE_BYTES_PER_SEC, bw(RATE_BYTES_PER_SEC as u64));
        assert!(bucket.check(512, t(0)));
        bucket.use_unchecked(512);
        assert!(bucket.check(512, t(0)));
        bucket.use_unchecked(512);
        assert!(!bucket.check(1, t(0)));
    }

    #[test]
    fn current_tokens_regenerate() {
        let mut bucket = TokenBucket::new(t(0), RATE_BYTES_PER_SEC, bw(RATE_BYTES_PER_SEC as u64));
        assert!(bucket.check(RATE_BYTES_PER_SEC as usize, t(0)));
        bucket.use_unchecked(RATE_BYTES_PER_SEC as usize);
        assert!(bucket.check(512, t(500_000_000)));
        bucket.use_unchecked(512);
        assert!(!bucket.check(1, t(500_000_000)));
    }

    #[test]
    fn current_tokens_limited_by_cbs() {
        let mut bucket = TokenBucket::new(t(0), 2000, bw(RATE_BYTES_PER_SEC as u64));
        let t1 = t(1_000_000_000);
        assert!(!bucket.check(2001, t1));
        assert!(bucket.check(2000, t1));
        bucket.use_unchecked(2000);
        assert!(!bucket.check(1, t1));
    }
}
