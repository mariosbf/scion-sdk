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

//! One reservation's bandwidth allowance, as a token bucket.
//!
//! Tokens are bytes. The bucket refills at the reservation's rate, is capped at its burst size,
//! and refuses a packet it cannot cover. It knows nothing about reservations, paths, or packets —
//! [`TokenBucketTracker`][super::token_bucket_tracker::TokenBucketTracker] owns that mapping.

use std::time::SystemTime;

use super::Bandwidth;

/// A byte allowance that refills over time.
///
/// Token counts are signed: [`use_unchecked`][Self::use_unchecked] deducts without checking, so a
/// caller that skips the check can overdraw the bucket, and the debt is repaid out of subsequent
/// refills rather than forgotten.
#[derive(Debug)]
pub(super) struct TokenBucket {
    current_token: i64,
    current_nano_tokens: i64,
    last_time_applied: SystemTime,
    committed_burst_size: i64,
    committed_information_rate: i64,
}

impl TokenBucket {
    /// Creates a bucket that refills at `rate` and holds at most `burst_size` bytes.
    ///
    /// Starts full to one second's worth of `rate`, so a reservation is usable the instant its
    /// window opens rather than after a second of refilling.
    pub(super) fn new(initial_time: SystemTime, burst_size: i64, rate: Bandwidth) -> Self {
        let rate_bytes_per_sec = rate.to_bytes_per_sec() as i64;
        Self {
            current_token: rate_bytes_per_sec,
            current_nano_tokens: 0,
            last_time_applied: initial_time,
            committed_burst_size: burst_size,
            committed_information_rate: rate_bytes_per_sec,
        }
    }

    /// Replenishes up to `now` and returns the resulting token count, which is negative if the
    /// bucket was overdrawn.
    ///
    /// [`check`][Self::check] and [`available_at`][Self::available_at] are thin wrappers over
    /// this, so a caller wanting both answers replenishes once and derives them.
    ///
    /// A `now` that precedes the last replenishment leaves the bucket untouched: two threads can
    /// read the clock in one order and reach the bucket in the other, and a packet arriving "in
    /// the past" must neither drain the bucket backwards nor panic.
    pub(super) fn replenish_at(&mut self, now: SystemTime) -> i64 {
        if let Ok(elapsed) = now.duration_since(self.last_time_applied) {
            // elapsed_nanos * rate overflows i64 once elapsed exceeds i64::MAX / rate — at rates
            // near the encoding maximum of ~67 GB/s, roughly 138 ms of idle time. Saturation is
            // semantically a full bucket, and the count is clamped to the burst size just below.
            let new_nano_tokens = (elapsed.as_nanos() as i64)
                .saturating_mul(self.committed_information_rate)
                .saturating_add(self.current_nano_tokens);

            let new_full_tokens = new_nano_tokens / 1_000_000_000;
            self.current_nano_tokens = new_nano_tokens % 1_000_000_000;
            self.current_token =
                (self.current_token + new_full_tokens).min(self.committed_burst_size);
            self.last_time_applied = now;
        }
        self.current_token
    }

    /// Whether `size` bytes are available at `now`, after replenishing.
    ///
    /// Deducts nothing; pair with [`use_unchecked`][Self::use_unchecked].
    pub(super) fn check(&mut self, size: usize, now: SystemTime) -> bool {
        self.replenish_at(now) >= size as i64
    }

    /// Deducts `size` bytes, whether or not they were available.
    pub(super) fn use_unchecked(&mut self, size: usize) {
        self.current_token -= size as i64;
    }

    /// Deducts `size` bytes if they are available at `now`, reporting whether it happened.
    pub(super) fn use_checked(&mut self, size: usize, now: SystemTime) -> bool {
        if self.check(size, now) {
            self.use_unchecked(size);
            true
        } else {
            false
        }
    }

    /// The bytes available at `now` after replenishing, with an overdrawn bucket reported as 0.
    pub(super) fn available_at(&mut self, now: SystemTime) -> i64 {
        self.replenish_at(now).max(0)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn t(nanos: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_nanos(nanos)
    }

    /// Exactly representable in the 10-bit encoding, so the bucket's rate is the number written.
    const RATE_BYTES_PER_SEC: i64 = 1024;

    fn bw(bytes_per_sec: u64) -> Bandwidth {
        Bandwidth::from_bytes_per_sec(bytes_per_sec).expect("representable")
    }

    fn bucket_at_rate() -> TokenBucket {
        TokenBucket::new(t(0), RATE_BYTES_PER_SEC, bw(RATE_BYTES_PER_SEC as u64))
    }

    #[test]
    fn high_rate_long_gap_does_not_overflow() {
        // At rates near the encoding maximum, elapsed_nanos * rate overflows i64 after ~138 ms of
        // idle time. An earlier `checked_mul().unwrap()` panicked here.
        let rate = Bandwidth::decode(Bandwidth::MASK).to_bytes_per_sec();
        let mut bucket = TokenBucket::new(t(0), rate as i64, bw(rate));

        // One second of idle time, far past the overflow horizon.
        assert!(bucket.check(1500, t(1_000_000_000)));
        bucket.use_unchecked(1500);

        // Clamped to the burst size rather than saturated to garbage.
        assert!(bucket.available_at(t(1_000_000_001)) <= rate as i64);
    }

    #[test]
    fn a_packet_arriving_behind_the_last_one_is_still_served() {
        // Concurrent senders read the clock in one order and reach the bucket in another.
        let mut bucket = TokenBucket::new(t(1), RATE_BYTES_PER_SEC, bw(RATE_BYTES_PER_SEC as u64));
        assert!(bucket.check(1, SystemTime::UNIX_EPOCH));
        bucket.use_unchecked(1);
    }

    #[test]
    fn full_bandwidth_consumed_at_once() {
        let mut bucket = bucket_at_rate();
        assert!(bucket.check(RATE_BYTES_PER_SEC as usize, t(0)));
        bucket.use_unchecked(RATE_BYTES_PER_SEC as usize);
        assert!(!bucket.check(1, t(0)));
    }

    #[test]
    fn full_bandwidth_consumed_over_multiple_packets() {
        let mut bucket = bucket_at_rate();
        assert!(bucket.check(512, t(0)));
        bucket.use_unchecked(512);
        assert!(bucket.check(512, t(0)));
        bucket.use_unchecked(512);
        assert!(!bucket.check(1, t(0)));
    }

    #[test]
    fn tokens_regenerate_over_time() {
        let mut bucket = bucket_at_rate();
        assert!(bucket.check(RATE_BYTES_PER_SEC as usize, t(0)));
        bucket.use_unchecked(RATE_BYTES_PER_SEC as usize);

        // Half a second at 1024 B/s is 512 bytes, and no more.
        assert!(bucket.check(512, t(500_000_000)));
        bucket.use_unchecked(512);
        assert!(!bucket.check(1, t(500_000_000)));
    }

    #[test]
    fn the_burst_size_caps_the_bucket() {
        // A bucket idle long enough to refill past its burst size holds only the burst size.
        let mut bucket = TokenBucket::new(t(0), 2000, bw(RATE_BYTES_PER_SEC as u64));
        let t1 = t(1_000_000_000);

        assert!(!bucket.check(2001, t1));
        assert!(bucket.check(2000, t1));
        bucket.use_unchecked(2000);
        assert!(!bucket.check(1, t1));
    }

    #[test]
    fn an_overdrawn_bucket_repays_its_debt_before_serving_again() {
        // use_unchecked lets a caller that skipped the check overdraw. The debt has to come out
        // of later refills, or an over-accounted packet would be free.
        let mut bucket = bucket_at_rate();
        bucket.use_unchecked(3 * RATE_BYTES_PER_SEC as usize);

        assert_eq!(
            bucket.available_at(t(0)),
            0,
            "overdrawn buckets report zero, not a negative"
        );
        assert!(
            !bucket.check(1, t(1_000_000_000)),
            "one second of refill only reduces the debt"
        );
        assert!(bucket.check(1, t(3_000_000_000)), "three seconds clears it");
    }
}
