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

//! Token-bucket enforcement of Hummingbird reservations.

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime},
};

use super::{
    Reservation, ReservationInfo,
    token_bucket::TokenBucket,
    tracker::{PacketSession, ReservationTracker, ReservationTrackerError, Selected, Ticket},
};
use crate::identifier::isd_asn::IsdAsn;

/// Identifies the bucket a reservation draws from.
///
/// Reservations sharing an ISD-AS, reservation ID and start time are renewals or duplicates of one
/// allowance and share a bucket. The start time is part of the key because a reissued reservation
/// with the same ID is a fresh allowance, not a continuation of the old one.
type BucketKey = (IsdAsn, u32, SystemTime);

/// A token bucket together with the key it is indexed by and the instant after which it may be
/// dropped.
#[derive(Debug)]
struct BucketEntry {
    key: BucketKey,
    end: SystemTime,
    bucket: TokenBucket,
}

/// Client-side token-bucket enforcer for Hummingbird reservations.
///
/// Keeps one bucket per reservation and refuses hops whose reservations are all expired or out of
/// tokens, which fails the resolution. Wrap in [`Lenient`][super::tracker::Lenient] to fall back
/// to standard hop fields instead.
///
/// # Concurrency
///
/// This tracker owns a mutex because it is the implementation that genuinely needs one: holding
/// senders to a reserved bandwidth is a claim about their *combined* rate, which cannot be
/// maintained without shared state. Trackers with nothing to coordinate pay nothing for this
/// one's requirements, which is why the lock lives here rather than around every tracker.
///
/// [`begin_packet`][ReservationTracker::begin_packet] takes the lock once for the whole packet and
/// holds it across selection and commit, so a bandwidth check cannot be overtaken by another
/// thread's deduction. That is what makes enforcement exact rather than approximate.
#[derive(Debug)]
pub struct TokenBucketTracker {
    inner: Mutex<Inner>,
}

impl TokenBucketTracker {
    /// Creates a tracker holding no buckets.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::new()),
        }
    }

    /// Takes the lock, recovering from a panic in another holder.
    ///
    /// A poisoned tracker is not a reason to fail a send: the state behind it is a set of token
    /// buckets, and the worst a partially applied update can do is misjudge one bucket's level
    /// until it next refills.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Drops buckets whose reservations have expired, if the cleanup interval has elapsed.
    pub fn cleanup_if_due(&self) {
        self.lock().cleanup_if_due()
    }

    /// Whether `num_bytes` may be sent over `reservation` now.
    pub fn check_reservation(
        &self,
        reservation: &ReservationInfo,
        num_bytes: usize,
    ) -> Result<(), ReservationTrackerError> {
        self.lock().check_reservation(reservation, num_bytes)
    }

    /// [`check_reservation`][Self::check_reservation] at an explicit instant, skipping the
    /// periodic cleanup.
    ///
    /// Checking several reservations for one packet should read the clock once and call this, so
    /// that every reservation is judged at the same instant. Pair with one
    /// [`cleanup_if_due`][Self::cleanup_if_due] per batch.
    pub fn check_reservation_at(
        &self,
        reservation: &ReservationInfo,
        num_bytes: usize,
        now: SystemTime,
    ) -> Result<(), ReservationTrackerError> {
        self.lock()
            .check_reservation_at(reservation, num_bytes, now)
    }

    /// Deducts `num_bytes` from `reservation`'s bucket, or does nothing if it has none.
    pub fn deduct_reservation(&self, reservation: &ReservationInfo, num_bytes: usize) {
        self.lock().deduct_reservation(reservation, num_bytes)
    }

    /// How many bytes may currently be sent over `reservation`. Zero if it is expired or drained.
    pub fn available_bytes(&self, reservation: &ReservationInfo) -> usize {
        self.lock().available_bytes(reservation)
    }

    /// [`available_bytes`][Self::available_bytes] at an explicit instant.
    pub fn available_bytes_at(&self, reservation: &ReservationInfo, now: SystemTime) -> usize {
        self.lock().available_bytes_at(reservation, now)
    }

    /// Checks and, on success, deducts `num_bytes` in one locked step.
    pub fn use_reservation(
        &self,
        reservation: &ReservationInfo,
        num_bytes: usize,
    ) -> Result<(), ReservationTrackerError> {
        self.lock().use_reservation(reservation, num_bytes)
    }
}

impl Default for TokenBucketTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Holds [`TokenBucketTracker`]'s lock for the duration of one packet.
struct TokenBucketSession<'s> {
    guard: MutexGuard<'s, Inner>,
}

impl PacketSession for TokenBucketSession<'_> {
    fn select<'a>(
        &mut self,
        reservations: &'a [Reservation],
        now: SystemTime,
        max_pkt_len: usize,
    ) -> Result<Option<Selected<'a>>, ReservationTrackerError> {
        self.guard.select(reservations, now, max_pkt_len)
    }

    fn commit(&mut self, selected: &Selected<'_>, pkt_len: usize) {
        self.guard.commit(selected, pkt_len)
    }
}

impl ReservationTracker for TokenBucketTracker {
    /// Opens a session holding the lock for the whole packet.
    ///
    /// One acquisition per packet rather than one per hop, with selection and commit in a single
    /// critical section. The `&self` methods below still serve callers holding a single hop;
    /// resolution does not use them.
    fn begin_packet(&self, now: SystemTime) -> Option<Box<dyn PacketSession + '_>> {
        let mut guard = self.lock();
        guard.begin_packet(now);
        Some(Box::new(TokenBucketSession { guard }))
    }

    fn select<'a>(
        &self,
        reservations: &'a [Reservation],
        now: SystemTime,
        max_pkt_len: usize,
    ) -> Result<Option<Selected<'a>>, ReservationTrackerError> {
        self.lock().select(reservations, now, max_pkt_len)
    }

    fn commit(&self, selected: &Selected<'_>, pkt_len: usize) {
        self.lock().commit(selected, pkt_len)
    }

    fn available_bytes_for(&self, reservations: &[Reservation], now: SystemTime) -> Option<usize> {
        self.lock().available_bytes_for(reservations, now)
    }
}

/// The mutable state behind [`TokenBucketTracker`], which owns the lock.
///
/// Buckets live in a slab rather than directly in the map, so a selection can hand its slot to the
/// matching commit through a [`Ticket`] instead of hashing the key a second time.
#[derive(Debug)]
struct Inner {
    buckets: Vec<BucketEntry>,
    slots: HashMap<BucketKey, usize>,
    /// Bumped whenever cleanup moves buckets within the slab, invalidating every ticket issued
    /// before it.
    generation: u32,
    last_cleanup: Instant,
    cleanup_interval: Duration,
}

impl Inner {
    fn new() -> Self {
        Self {
            buckets: Vec::new(),
            slots: HashMap::new(),
            generation: 0,
            last_cleanup: Instant::now(),
            cleanup_interval: Duration::from_secs(60),
        }
    }

    /// Drops expired token buckets, if the cleanup interval has elapsed.
    fn cleanup_if_due(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) >= self.cleanup_interval {
            self.cleanup(SystemTime::now());
            self.last_cleanup = now;
        }
    }

    /// Drops every bucket whose reservation ended before `now`, reindexing the slab if anything
    /// was removed.
    fn cleanup(&mut self, now: SystemTime) {
        let before = self.buckets.len();
        self.buckets.retain(|entry| entry.end > now);

        if self.buckets.len() == before {
            return;
        }

        // Retaining shifted the surviving buckets down, so every slot recorded in the map — and in
        // any ticket already issued — now names a different bucket.
        self.slots.clear();
        for (slot, entry) in self.buckets.iter().enumerate() {
            self.slots.insert(entry.key, slot);
        }
        self.generation = self.generation.wrapping_add(1);
    }

    /// The slot of `reservation`'s bucket, creating the bucket if it has none.
    fn slot_for(&mut self, reservation: &ReservationInfo) -> usize {
        let key = (reservation.isd_as, reservation.res_id, reservation.start);

        if let Some(&slot) = self.slots.get(&key) {
            return slot;
        }

        let slot = self.buckets.len();
        self.buckets.push(BucketEntry {
            key,
            end: reservation.end(),
            bucket: TokenBucket::new(
                reservation.start,
                reservation.bandwidth.to_bytes_per_sec() as i64,
                reservation.bandwidth,
            ),
        });
        self.slots.insert(key, slot);
        slot
    }

    fn bucket_for(&mut self, reservation: &ReservationInfo) -> &mut TokenBucket {
        let slot = self.slot_for(reservation);
        &mut self.buckets[slot].bucket
    }

    /// Issues a ticket for `slot`, valid until the next cleanup that moves buckets.
    fn ticket_for(&self, slot: usize) -> Ticket {
        Ticket::new((u64::from(self.generation) << 32) | slot as u64)
    }

    /// Resolves a ticket back to a slot, or `None` if it was not issued by this tracker's current
    /// generation.
    fn slot_of(&self, ticket: Ticket) -> Option<usize> {
        let value = ticket.value();
        if value == Ticket::NONE.value() || (value >> 32) as u32 != self.generation {
            return None;
        }

        let slot = (value & u64::from(u32::MAX)) as usize;
        (slot < self.buckets.len()).then_some(slot)
    }

    fn check_reservation(
        &mut self,
        reservation: &ReservationInfo,
        num_bytes: usize,
    ) -> Result<(), ReservationTrackerError> {
        self.cleanup_if_due();
        self.check_reservation_at(reservation, num_bytes, SystemTime::now())
    }

    fn check_reservation_at(
        &mut self,
        reservation: &ReservationInfo,
        num_bytes: usize,
        now: SystemTime,
    ) -> Result<(), ReservationTrackerError> {
        if !is_valid_at(reservation, now) {
            return Err(ReservationTrackerError::ReservationExpired);
        }

        if self.bucket_for(reservation).check(num_bytes, now) {
            Ok(())
        } else {
            Err(ReservationTrackerError::BandwidthExceeded)
        }
    }

    fn deduct_reservation(&mut self, reservation: &ReservationInfo, num_bytes: usize) {
        if let Some(&slot) =
            self.slots
                .get(&(reservation.isd_as, reservation.res_id, reservation.start))
        {
            self.buckets[slot].bucket.use_unchecked(num_bytes);
        }
    }

    fn available_bytes(&mut self, reservation: &ReservationInfo) -> usize {
        self.available_bytes_at(reservation, SystemTime::now())
    }

    fn available_bytes_at(&mut self, reservation: &ReservationInfo, now: SystemTime) -> usize {
        if !is_valid_at(reservation, now) {
            return 0;
        }

        self.bucket_for(reservation).available_at(now).max(0) as usize
    }

    fn use_reservation(
        &mut self,
        reservation: &ReservationInfo,
        num_bytes: usize,
    ) -> Result<(), ReservationTrackerError> {
        let now = SystemTime::now();

        if !is_valid_at(reservation, now) {
            return Err(ReservationTrackerError::ReservationExpired);
        }

        if self.bucket_for(reservation).use_checked(num_bytes, now) {
            Ok(())
        } else {
            Err(ReservationTrackerError::BandwidthExceeded)
        }
    }
}

/// The per-packet tracker operations, on the locked state.
impl Inner {
    fn begin_packet(&mut self, _now: SystemTime) {
        self.cleanup_if_due();
    }

    /// Picks the valid candidate with the fewest available bytes — the tightest bucket that can
    /// still carry the packet — leaving headroom in larger buckets for bigger packets.
    fn select<'a>(
        &mut self,
        reservations: &'a [Reservation],
        now: SystemTime,
        max_pkt_len: usize,
    ) -> Result<Option<Selected<'a>>, ReservationTrackerError> {
        if reservations.is_empty() {
            return Ok(None);
        }

        let mut num_expired = 0;
        let mut selected: Option<(&Reservation, i64, usize)> = None;

        for reservation in reservations {
            // The reservation's validity window is cached at construction, unlike the
            // `ReservationInfo` form below which recomputes its end on every call.
            if !reservation.is_valid_at(now) {
                num_expired += 1;
                continue;
            }

            // One lookup and one replenishment answer both questions: whether the bucket can carry
            // the packet, and how much room it has left for the tie-break below.
            let slot = self.slot_for(reservation.info());
            let tokens = self.buckets[slot].bucket.replenish_at(now);

            if tokens < max_pkt_len as i64 {
                continue;
            }

            if selected.is_none_or(|(_, other, _)| other > tokens) {
                selected = Some((reservation, tokens, slot));
            }
        }

        match selected {
            Some((reservation, _, slot)) => {
                Ok(Some(Selected {
                    reservation,
                    ticket: self.ticket_for(slot),
                }))
            }
            // Expiry is the more useful diagnosis than exhaustion when nothing was even in its
            // validity window.
            None if num_expired == reservations.len() => {
                Err(ReservationTrackerError::ReservationExpired)
            }
            None => Err(ReservationTrackerError::BandwidthExceeded),
        }
    }

    fn commit(&mut self, selected: &Selected<'_>, pkt_len: usize) {
        match self.slot_of(selected.ticket) {
            Some(slot) => self.buckets[slot].bucket.use_unchecked(pkt_len),
            // The ticket predates a cleanup, or came from another tracker. The keyed lookup finds
            // the reservation's current bucket; the slot the ticket names now holds another's.
            None => self.deduct_reservation(selected.reservation.info(), pkt_len),
        }
    }

    fn available_bytes_for(
        &mut self,
        reservations: &[Reservation],
        now: SystemTime,
    ) -> Option<usize> {
        reservations
            .iter()
            .map(|r| self.available_bytes_at(r.info(), now))
            .max()
    }
}

/// Whether `reservation`'s validity window contains `now`.
///
/// Both bounds are inclusive, matching [`Reservation::is_valid_at`] and unlike
/// [`ReservationInfo::is_valid_now`], whose upper bound is exclusive.
fn is_valid_at(reservation: &ReservationInfo, now: SystemTime) -> bool {
    reservation.start <= now && now <= reservation.end()
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use super::{
        super::test_support::{reservation, reservation_for},
        *,
    };

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    const START: u64 = 1_700_000_000;

    #[test]
    fn a_session_holds_the_lock_across_select_and_commit() {
        // Enforcement is exact only while one packet's check and deduction cannot be interleaved
        // with another thread's. A session that re-acquired per call would let two threads both
        // pass a bandwidth check before either deducted.
        let tracker = TokenBucketTracker::new();
        let session = tracker
            .begin_packet(at(START))
            .expect("this tracker always opens a session");

        assert!(tracker.inner.try_lock().is_err());
        drop(session);
        assert!(tracker.inner.try_lock().is_ok());
    }

    #[test]
    fn the_tightest_usable_bucket_is_selected() {
        // Spending the smallest sufficient allowance first leaves the larger ones for packets
        // that only they can carry.
        let tracker = TokenBucketTracker::new();
        let candidates = vec![
            reservation(1, 8192, at(START)),
            reservation(2, 1024, at(START)),
            reservation(3, 4096, at(START)),
        ];

        let selected = tracker
            .select(&candidates, at(START), 512)
            .expect("all are valid and have room")
            .expect("a candidate was available");

        assert_eq!(selected.reservation.info().res_id, 2);
    }

    #[test]
    fn a_bucket_too_small_for_the_packet_is_skipped() {
        let tracker = TokenBucketTracker::new();
        let candidates = vec![
            reservation(1, 100, at(START)),
            reservation(2, 8192, at(START)),
        ];

        let selected = tracker
            .select(&candidates, at(START), 4096)
            .expect("one candidate has room")
            .expect("a candidate was available");

        assert_eq!(selected.reservation.info().res_id, 2);
    }

    #[test]
    fn expired_candidates_report_expiry_and_drained_ones_report_bandwidth() {
        // The two diagnoses lead to different actions: renew the reservation, or buy more
        // bandwidth.
        let tracker = TokenBucketTracker::new();

        let stale = vec![reservation_for(1, 8192, at(START), 60)];
        assert!(matches!(
            tracker.select(&stale, at(START + 3600), 100),
            Err(ReservationTrackerError::ReservationExpired)
        ));

        let small = vec![reservation(2, 100, at(START))];
        assert!(matches!(
            tracker.select(&small, at(START), 4096),
            Err(ReservationTrackerError::BandwidthExceeded)
        ));
    }

    #[test]
    fn a_committed_packet_is_deducted_from_the_selected_bucket() {
        let tracker = TokenBucketTracker::new();
        let candidates = vec![reservation(1, 1024, at(START))];

        let before = tracker
            .available_bytes_for(&candidates, at(START))
            .expect("this tracker reports bandwidth");

        let selected = tracker
            .select(&candidates, at(START), 512)
            .unwrap()
            .unwrap();
        tracker.commit(&selected, 512);

        let after = tracker
            .available_bytes_for(&candidates, at(START))
            .expect("this tracker reports bandwidth");

        assert_eq!(before - after, 512);
    }

    #[test]
    fn a_stale_ticket_still_deducts_from_the_right_bucket() {
        // Cleanup compacts the slab, so a ticket issued before it names a slot now holding a
        // different reservation's bucket. Deducting there would charge the wrong reservation.
        let tracker = TokenBucketTracker::new();
        let expiring = reservation_for(1, 8192, at(START), 60);
        let surviving = reservation(2, 1024, at(START));

        // Two buckets exist; the surviving reservation sits in slot 1.
        let selected = {
            let mut inner = tracker.lock();
            inner.slot_for(expiring.info());
            let slot = inner.slot_for(surviving.info());
            assert_eq!(slot, 1);
            Selected {
                reservation: &surviving,
                ticket: inner.ticket_for(slot),
            }
        };

        // Cleanup drops the expired bucket and shifts the survivor down to slot 0, so the ticket
        // now names a slot past the end of the slab. START + 100 is past the 60-second
        // reservation's end and well inside the hour-long one's.
        tracker.lock().cleanup(at(START + 100));
        assert_eq!(tracker.lock().buckets.len(), 1);
        assert!(tracker.lock().slot_of(selected.ticket).is_none());

        let before = tracker.available_bytes_at(surviving.info(), at(START));
        tracker.commit(&selected, 512);
        let after = tracker.available_bytes_at(surviving.info(), at(START));

        assert_eq!(
            before - after,
            512,
            "the keyed fallback charged the right bucket"
        );
    }

    #[test]
    fn two_handles_on_one_allowance_share_a_bucket_but_a_reissue_does_not() {
        // The key is (AS, id, start). Two handles on the same allowance must not double the
        // bandwidth; a reservation reissued for a later window is a fresh allowance.
        let tracker = TokenBucketTracker::new();
        let original = reservation(1, 1024, at(START));
        let duplicate = reservation(1, 1024, at(START));
        let reissued = reservation(1, 1024, at(START + 1));

        // The bucket is created on first sight of the reservation.
        let full = tracker.available_bytes_at(original.info(), at(START));
        tracker.deduct_reservation(original.info(), 512);

        assert_eq!(
            tracker.available_bytes_at(duplicate.info(), at(START)),
            full - 512,
        );
        assert_eq!(
            tracker.available_bytes_at(reissued.info(), at(START + 1)),
            full,
        );
    }

    #[test]
    fn deducting_from_an_unseen_reservation_creates_no_bucket() {
        // deduct_reservation is the commit path's keyed fallback, reached only after a selection
        // has already created the bucket. Creating one here would let a stray commit mint an
        // allowance out of nothing.
        let tracker = TokenBucketTracker::new();
        let unseen = reservation(1, 1024, at(START));

        tracker.deduct_reservation(unseen.info(), 512);

        assert!(tracker.lock().buckets.is_empty());
    }
}
