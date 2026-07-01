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
            let new_nano_tokens = (elapsed.as_nanos() as i64)
                .checked_mul(self.committed_information_rate)
                .unwrap()
                .checked_add(self.current_nano_tokens)
                .unwrap();

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
            let new_nano_tokens = (elapsed.as_nanos() as i64)
                .checked_mul(self.committed_information_rate)
                .unwrap()
                .checked_add(self.current_nano_tokens)
                .unwrap();
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
    bw.to_kbps() as i64 * 125
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn t(nanos: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_nanos(nanos)
    }

    const RATE_8KBPS: u64 = 8;
    const RATE_8KBPS_BYTES: i64 = 1000;

    fn bw_kbps(kbps: u64) -> Bandwidth {
        Bandwidth::from_kbps(kbps).unwrap()
    }

    #[test]
    fn apply_allows_arrival_behind_last_arrival() {
        let mut bucket = TokenBucket::new(t(1), RATE_8KBPS_BYTES, bw_kbps(RATE_8KBPS));
        assert!(bucket.check(1, SystemTime::UNIX_EPOCH));
        bucket.use_unchecked(1);
    }

    #[test]
    fn full_bandwidth_consumed_at_once() {
        let mut bucket = TokenBucket::new(t(0), RATE_8KBPS_BYTES, bw_kbps(RATE_8KBPS));
        assert!(bucket.check(RATE_8KBPS_BYTES as usize, t(0)));
        bucket.use_unchecked(RATE_8KBPS_BYTES as usize);
        assert!(!bucket.check(1, t(0)));
    }

    #[test]
    fn full_bandwidth_consumed_over_multiple_packets() {
        let mut bucket = TokenBucket::new(t(0), RATE_8KBPS_BYTES, bw_kbps(RATE_8KBPS));
        assert!(bucket.check(500, t(0)));
        bucket.use_unchecked(500);
        assert!(bucket.check(500, t(0)));
        bucket.use_unchecked(500);
        assert!(!bucket.check(1, t(0)));
    }

    #[test]
    fn current_tokens_regenerate() {
        let mut bucket = TokenBucket::new(t(0), RATE_8KBPS_BYTES, bw_kbps(RATE_8KBPS));
        assert!(bucket.check(RATE_8KBPS_BYTES as usize, t(0)));
        bucket.use_unchecked(RATE_8KBPS_BYTES as usize);
        assert!(bucket.check(500, t(500_000_000)));
        bucket.use_unchecked(500);
        assert!(!bucket.check(1, t(500_000_000)));
    }

    #[test]
    fn current_tokens_limited_by_cbs() {
        let mut bucket = TokenBucket::new(t(0), 2000, bw_kbps(RATE_8KBPS));
        let t1 = t(1_000_000_000);
        assert!(!bucket.check(2001, t1));
        assert!(bucket.check(2000, t1));
        bucket.use_unchecked(2000);
        assert!(!bucket.check(1, t1));
    }
}
