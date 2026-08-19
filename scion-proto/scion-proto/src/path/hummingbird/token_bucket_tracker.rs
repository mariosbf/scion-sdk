//! Token-bucket enforcement of Hummingbird reservations.

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime},
};

use chrono::{DateTime, Utc};

use super::{
    reservation_tracker::{
        PacketSession, ReservationTracker, ReservationTrackerError, Selected, Ticket,
    },
    token_bucket::TokenBucket,
};
use crate::{
    address::IsdAsn,
    hummingbird::{Reservation, ReservationInfo},
};

/// Identifies the bucket a reservation draws from. Reservations sharing an
/// ISD-AS, reservation ID and start time share a bucket.
type BucketKey = (IsdAsn, u32, DateTime<Utc>);

/// A token bucket together with the key it is indexed by and the instant after
/// which it may be dropped.
#[derive(Debug)]
struct BucketEntry {
    key: BucketKey,
    end: SystemTime,
    bucket: TokenBucket,
}

/// Client-side token-bucket enforcer for Hummingbird reservations.
///
/// Keeps one bucket per reservation and refuses hops whose reservations are all
/// expired or out of tokens, which fails the encode. Wrap in
/// [`Lenient`][super::reservation_tracker::Lenient] to fall back to standard hop
/// fields instead.
///
/// # Concurrency
///
/// This tracker owns a mutex, because it is the implementation that genuinely
/// needs one: holding senders to a reserved bandwidth is a claim about their
/// *combined* rate, which cannot be maintained without shared state. Trackers
/// with nothing to coordinate — [`ProbabilisticTracker`][super::ProbabilisticTracker]
/// — pay nothing for this one's requirements, which is why the lock lives here
/// and not around every tracker in [`HummingbirdPath`][super::HummingbirdPath].
///
/// The lock is taken per call rather than across selection and commit together,
/// so two threads can both pass a check before either deducts, overdrawing a
/// bucket by at most one packet each before refill catches up. See the
/// [module documentation][super::reservation_tracker] for why that trade is
/// made.
#[derive(Debug)]
pub struct TokenBucketTracker {
    inner: Mutex<Inner>,
}

impl TokenBucketTracker {
    /// Creates a new [`TokenBucketTracker`].
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::new()),
        }
    }

    /// Takes the lock, recovering from a panic in another holder.
    ///
    /// A poisoned tracker is not a reason to fail an encode: the state behind
    /// it is a set of token buckets, and the worst a partially applied update
    /// can do is misjudge one bucket's level until it next refills.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Drops buckets whose reservations have expired, if enough time has passed
    /// since the last sweep.
    pub fn cleanup_if_due(&self) {
        self.lock().cleanup_if_due()
    }

    /// Returns whether `num_bytes` may be sent over `reservation` now.
    pub fn check_reservation(
        &self,
        reservation: &ReservationInfo,
        num_bytes: usize,
    ) -> Result<(), ReservationTrackerError> {
        self.lock().check_reservation(reservation, num_bytes)
    }

    /// [`Self::check_reservation`] at an explicit instant.
    pub fn check_reservation_at(
        &self,
        reservation: &ReservationInfo,
        num_bytes: usize,
        now: SystemTime,
    ) -> Result<(), ReservationTrackerError> {
        self.lock()
            .check_reservation_at(reservation, num_bytes, now)
    }

    /// Deducts `num_bytes` from `reservation`'s bucket.
    pub fn deduct_reservation(&self, reservation: &ReservationInfo, num_bytes: usize) {
        self.lock().deduct_reservation(reservation, num_bytes)
    }

    /// Returns how many bytes may currently be sent over `reservation`.
    pub fn available_bytes(&self, reservation: &ReservationInfo) -> usize {
        self.lock().available_bytes(reservation)
    }

    /// [`Self::available_bytes`] at an explicit instant.
    pub fn available_bytes_at(&self, reservation: &ReservationInfo, now: SystemTime) -> usize {
        self.lock().available_bytes_at(reservation, now)
    }

    /// Checks and deducts in one step.
    pub fn use_reservation(
        &self,
        reservation: &ReservationInfo,
        num_bytes: usize,
    ) -> Result<(), ReservationTrackerError> {
        self.lock().use_reservation(reservation, num_bytes)
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
    /// This is the point of the session mechanism for this tracker: one
    /// acquisition per packet instead of one per hop, and selection and commit
    /// in a single critical section, so a bandwidth check cannot be overtaken
    /// by another thread's deduction. The `&self` `select`/`commit` above still
    /// work for callers holding a single hop; encoding does not use them.
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
/// Buckets live in a slab rather than directly in the map, so that a selection
/// can hand its slot to the matching commit through a [`Ticket`] instead of
/// hashing the key a second time.
#[derive(Debug)]
struct Inner {
    buckets: Vec<BucketEntry>,
    slots: HashMap<BucketKey, usize>,
    /// Bumped whenever cleanup moves buckets within the slab, invalidating every
    /// ticket issued before it.
    generation: u32,
    last_cleanup: Instant,
    cleanup_interval: Duration,
}

impl Inner {
    /// Creates empty tracker state.
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
    ///
    /// [`Self::check_reservation`] does this itself, as does
    /// [`ReservationTracker::begin_packet`]. Callers that use the `_at` variants
    /// in a loop should call this once per batch instead, so that the monotonic
    /// clock is read once rather than per reservation.
    pub fn cleanup_if_due(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) >= self.cleanup_interval {
            self.cleanup(SystemTime::now());
            self.last_cleanup = now;
        }
    }

    /// Drops every bucket whose reservation ended before `now`, reindexing the
    /// slab if anything was removed.
    fn cleanup(&mut self, now: SystemTime) {
        let before = self.buckets.len();
        self.buckets.retain(|entry| entry.end > now);

        if self.buckets.len() == before {
            return;
        }

        // Retaining shifted the surviving buckets down, so every slot recorded
        // in the map — and in any ticket already issued — now points elsewhere.
        self.slots.clear();
        for (slot, entry) in self.buckets.iter().enumerate() {
            self.slots.insert(entry.key, slot);
        }
        self.generation = self.generation.wrapping_add(1);
    }

    /// Returns the slot of `reservation`'s bucket, creating it if needed.
    fn slot_for(&mut self, reservation: &ReservationInfo) -> usize {
        let key = (reservation.isd_as, reservation.res_id, reservation.start);

        if let Some(&slot) = self.slots.get(&key) {
            return slot;
        }

        let slot = self.buckets.len();
        self.buckets.push(BucketEntry {
            key,
            end: reservation.end().into(),
            bucket: TokenBucket::new(
                reservation.start().into(),
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

    /// Resolves a ticket back to a slot, or `None` if it was not issued by this
    /// tracker's current generation.
    fn slot_of(&self, ticket: Ticket) -> Option<usize> {
        let value = ticket.value();
        if value == Ticket::NONE.value() || (value >> 32) as u32 != self.generation {
            return None;
        }

        let slot = (value & u64::from(u32::MAX)) as usize;
        (slot < self.buckets.len()).then_some(slot)
    }

    /// Check time validity and bandwidth availability without deducting tokens.
    ///
    /// Call [`deduct_reservation`][Self::deduct_reservation] after a successful
    /// check to consume the tokens.
    pub fn check_reservation(
        &mut self,
        reservation: &ReservationInfo,
        num_bytes: usize,
    ) -> Result<(), ReservationTrackerError> {
        self.cleanup_if_due();
        self.check_reservation_at(reservation, num_bytes, SystemTime::now())
    }

    /// Same as [`Self::check_reservation`], but takes the current time instead
    /// of reading the clock, and skips the periodic cleanup.
    ///
    /// Checking several reservations for one packet should read the clock once
    /// and call this, both to avoid the repeated clock reads and so that every
    /// reservation is judged at the same instant. Pair with one
    /// [`Self::cleanup_if_due`] call per batch.
    pub fn check_reservation_at(
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

    /// Deduct `num_bytes` from the reservation's token bucket.
    ///
    /// Caller must have called [`check_reservation`][Self::check_reservation]
    /// first to confirm availability. No-op if the bucket does not exist.
    pub fn deduct_reservation(&mut self, reservation: &ReservationInfo, num_bytes: usize) {
        if let Some(&slot) =
            self.slots
                .get(&(reservation.isd_as, reservation.res_id, reservation.start))
        {
            self.buckets[slot].bucket.use_unchecked(num_bytes);
        }
    }

    /// Returns the number of bytes currently available for `reservation` at this instant.
    ///
    /// Returns 0 if the reservation is expired or has no remaining tokens.
    pub fn available_bytes(&mut self, reservation: &ReservationInfo) -> usize {
        self.available_bytes_at(reservation, SystemTime::now())
    }

    /// Same as [`Self::available_bytes`], but takes the current time instead of
    /// reading the clock.
    pub fn available_bytes_at(&mut self, reservation: &ReservationInfo, now: SystemTime) -> usize {
        if !is_valid_at(reservation, now) {
            return 0;
        }

        self.bucket_for(reservation).available_at(now).max(0) as usize
    }

    /// Check and, on success, deduct `pkt_size` bytes from the reservation's token bucket.
    pub fn use_reservation(
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

    /// Picks the candidate with the fewest available bytes (the tightest bucket),
    /// preserving headroom in larger buckets for bigger packets.
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
            // Uses the reservation's precomputed window rather than the
            // `ReservationInfo` overload below, which has to convert out of
            // the chrono calendar representation on every call.
            if !reservation.is_valid_at(now) {
                num_expired += 1;
                continue;
            }

            // One lookup and one replenishment answer both questions: whether
            // the bucket can carry the packet, and how much room it has left
            // for the tie-break below.
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
            // Report expiry over exhaustion: if nothing was even in its validity
            // window, that is the more useful diagnosis.
            None if num_expired == reservations.len() => {
                Err(ReservationTrackerError::ReservationExpired)
            }
            None => Err(ReservationTrackerError::BandwidthExceeded),
        }
    }

    fn commit(&mut self, selected: &Selected<'_>, pkt_len: usize) {
        match self.slot_of(selected.ticket) {
            Some(slot) => self.buckets[slot].bucket.use_unchecked(pkt_len),
            // The ticket predates a cleanup, or came from another tracker.
            // Fall back to the keyed lookup rather than deducting from a
            // bucket that is no longer the one that was selected.
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
/// Both bounds are inclusive, matching the checks this tracker has always
/// performed — unlike [`ReservationInfo::is_valid_now`], whose upper bound is
/// exclusive.
fn is_valid_at(reservation: &ReservationInfo, now: SystemTime) -> bool {
    let start: SystemTime = reservation.start().into();
    let end: SystemTime = reservation.end().into();

    start <= now && now <= end
}

impl Default for TokenBucketTracker {
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
        path::hummingbird::{HbirdAuthKey, reservation_tracker::Lenient},
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

    fn make_reservation_lasting(
        res_id: u32,
        start: DateTime<Utc>,
        bw_bytes_per_sec: u64,
        duration: u16,
    ) -> ReservationInfo {
        ReservationInfo {
            duration,
            ..make_reservation(res_id, start, bw_bytes_per_sec)
        }
    }

    fn reservation(info: ReservationInfo) -> Reservation {
        Reservation::new(info, HbirdAuthKey::from([0xAB; 16]))
    }

    #[test]
    fn different_start_times_get_independent_buckets() {
        let tracker = TokenBucketTracker::new();
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
        let tracker = TokenBucketTracker::new();
        let start = Utc::now() - ChronoDuration::seconds(10);

        let res_a = make_reservation(42, start, 1024);
        let res_a_again = make_reservation(42, start, 1024);

        tracker.use_reservation(&res_a, 1024).unwrap();
        assert!(matches!(
            tracker.use_reservation(&res_a_again, 1),
            Err(ReservationTrackerError::BandwidthExceeded)
        ));
    }

    #[test]
    fn select_picks_the_tightest_bucket() {
        let tracker = TokenBucketTracker::new();
        let start = Utc::now() - ChronoDuration::seconds(1);
        let now = SystemTime::now();

        let roomy = reservation(make_reservation(1, start, 8192));
        let tight = reservation(make_reservation(2, start, 2048));
        let candidates = vec![roomy, tight];

        let selected = tracker.select(&candidates, now, 1024).unwrap().unwrap();
        assert_eq!(selected.reservation.info().res_id, 2);
    }

    #[test]
    fn select_reports_exhaustion_and_expiry_distinctly() {
        let tracker = TokenBucketTracker::new();
        let now = SystemTime::now();

        let exhausted = reservation(make_reservation(
            1,
            Utc::now() - ChronoDuration::seconds(1),
            1024,
        ));
        let candidates = vec![exhausted];
        // Ask for more than the bucket can ever hold.
        assert!(matches!(
            tracker.select(&candidates, now, 1_000_000),
            Err(ReservationTrackerError::BandwidthExceeded)
        ));

        // `duration` is 60s, so a start two hours ago is long expired.
        let expired = reservation(make_reservation(
            2,
            Utc::now() - ChronoDuration::hours(2),
            1024,
        ));
        let candidates = vec![expired];
        assert!(matches!(
            tracker.select(&candidates, now, 1024),
            Err(ReservationTrackerError::ReservationExpired)
        ));
    }

    #[test]
    fn select_on_empty_candidates_is_none_not_error() {
        let tracker = TokenBucketTracker::new();
        assert!(
            tracker
                .select(&[], SystemTime::now(), 1024)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn lenient_turns_failure_into_no_selection() {
        let tracker = Lenient(TokenBucketTracker::new());
        let expired = reservation(make_reservation(
            1,
            Utc::now() - ChronoDuration::hours(2),
            1024,
        ));
        let candidates = vec![expired];

        assert!(
            tracker
                .select(&candidates, SystemTime::now(), 1024)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn commit_deducts_from_the_selected_bucket() {
        let tracker = TokenBucketTracker::new();
        let start = Utc::now() - ChronoDuration::seconds(1);
        let now = SystemTime::now();

        let candidates = vec![reservation(make_reservation(1, start, 1024))];

        let selected = tracker.select(&candidates, now, 1024).unwrap().unwrap();
        let before = tracker.available_bytes_at(candidates[0].info(), now);
        tracker.commit(&selected, 512);
        let after = tracker.available_bytes_at(candidates[0].info(), now);

        assert!(before >= after + 512);
    }

    #[test]
    fn commit_with_a_ticket_from_another_tracker_still_deducts() {
        let start = Utc::now() - ChronoDuration::seconds(1);
        let now = SystemTime::now();
        let candidates = vec![reservation(make_reservation(1, start, 1024))];

        // A tracker that has never seen this reservation issues slot 0 for it;
        // pointing that ticket at a different tracker must not silently deduct
        // from whatever happens to sit in that tracker's slot 0.
        let other = TokenBucketTracker::new();
        let selected = other.select(&candidates, now, 1024).unwrap().unwrap();

        let tracker = TokenBucketTracker::new();
        tracker.commit(&selected, 512);
        let after = tracker.available_bytes_at(candidates[0].info(), now);

        // The fallback found no bucket for this reservation, so nothing was
        // deducted and a fresh bucket reads as full.
        assert_eq!(after, 1024);
    }

    #[test]
    fn cleanup_invalidates_tickets_that_would_point_at_another_bucket() {
        let start = Utc::now() - ChronoDuration::seconds(30);
        let now = SystemTime::now();

        // The first reservation expires well before the others, so dropping it
        // shifts every later bucket down one slot.
        let short = reservation(make_reservation_lasting(1, start, 1024, 60));
        let long = |res_id| reservation(make_reservation_lasting(res_id, start, 1024, u16::MAX));
        let (b, c, d) = (long(2), long(3), long(4));

        let tracker = TokenBucketTracker::new();
        for candidate in [&short, &b, &c, &d] {
            let candidates = std::slice::from_ref(candidate);
            tracker.select(candidates, now, 1).unwrap().unwrap();
        }

        // Select c, which currently sits in slot 2.
        let candidates = vec![c.clone()];
        let selected = tracker.select(&candidates, now, 1024).unwrap().unwrap();

        // Drop the short reservation: c moves to slot 1, and slot 2 becomes d.
        tracker.lock().cleanup(now + Duration::from_secs(120));

        tracker.commit(&selected, 512);

        // The deduction must have followed c, not the bucket now in slot 2.
        assert!(tracker.available_bytes_at(c.info(), now) <= 1024 - 512);
        assert_eq!(tracker.available_bytes_at(d.info(), now), 1024);
    }
}
