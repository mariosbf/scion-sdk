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

//! The reservation tracker interface, consulted while resolving a Hummingbird path.
//!
//! A hop may hold several reservations. Resolving a packet consults the tracker twice per such
//! hop: [`ReservationTracker::select`] picks which reservation to use, and
//! [`ReservationTracker::commit`] accounts for the packet once its exact length is known.
//!
//! The two are separate because selection determines how many hop fields become flyovers, which
//! in turn determines the packet length. Selection therefore necessarily runs against an *upper
//! bound*, and only the commit sees the real figure. 
//!
//! Implementations decide their own enforcement policy. A tracker that returns an error fails the
//! resolution; wrap it in [`Lenient`] to have unusable hops fall back to standard hop fields
//! instead.
//!
//! # Sharing between threads
//!
//! Every method takes `&self`, and the trait requires [`Sync`], so a tracker is shared between
//! sender threads as a plain `Arc` with no lock around it. This is deliberate: taking `&mut self`
//! would force *every* implementation to sit behind one mutex on the per-packet path, including
//! those with nothing to synchronise. [`ProbabilisticTracker`] holds only a random-number
//! generator — two threads drawing independently spread traffic exactly as well as two threads
//! sharing one draw — so an exclusive lock there buys nothing and serialises resolution for no
//! reason.
//!
//! Implementations that *do* need shared mutable state take that cost themselves, and only where
//! they need it. [`TokenBucketTracker`] does: its whole purpose is to hold senders to a bandwidth
//! limit, which cannot be done without coordination when reservations are shared between
//! multiple paths used from multiple threads.
//!
//! ## Granularity
//!
//! A tracker that needs a lock should take it **once per packet**, not once per hop, by returning
//! a [`PacketSession`] from [`ReservationTracker::begin_packet`]. Resolution routes that packet's
//! selections and commits through the session and drops it at the end, so the guard is held
//! across the whole packet. Answering `None` instead — the default, and the right answer for a
//! lock-free tracker — costs nothing and sends every call down the `&self` path.
//!
//! ## Atomicity
//!
//! A tracker that opens a session sees selection and commit for one packet as one critical
//! section: no other thread can interleave, so a bandwidth check cannot be overtaken by another
//! thread's commit. [`TokenBucketTracker`] does this, which is what makes its enforcement exact
//! rather than approximate.
//!
//! A tracker that declines a session gets no such guarantee — but a tracker declines precisely
//! because it has no shared state to be atomic about.
//!
//! [`ProbabilisticTracker`]: super::probabilistic_tracker::ProbabilisticTracker
//! [`TokenBucketTracker`]: super::token_bucket_tracker::TokenBucketTracker

use std::time::SystemTime;

use super::Reservation;

/// Why a tracker refused a hop.
///
/// The distinction is the point: "renew the reservation" and "buy more bandwidth" are different
/// actions for the caller, and both reach the socket as typed variants rather than as a formatted
/// string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReservationTrackerError {
    /// Every candidate reservation was outside its validity window.
    #[error("reservation expired")]
    ReservationExpired,
    /// Candidates were valid, but none had bandwidth remaining for this packet.
    #[error("bandwidth exceeded")]
    BandwidthExceeded,
}

/// An opaque handle to whatever state a tracker resolved while selecting a reservation, handed
/// back to [`ReservationTracker::commit`] so the tracker need not look it up a second time.
///
/// The meaning of the value is entirely up to the tracker that issued it — no other code may
/// interpret it. Trackers that keep no per-reservation state issue [`Ticket::NONE`] and ignore it
/// on commit.
///
/// This is deliberately a concrete type rather than an associated type on the trait: a path stores
/// its tracker as a trait object, and an associated type would make the trait unusable as `dyn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket(u64);

impl Ticket {
    /// The ticket issued by trackers that carry no state between select and commit.
    pub const NONE: Ticket = Ticket(u64::MAX);

    /// Creates a ticket carrying `value`.
    #[inline]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the value this ticket carries.
    #[inline]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// A reservation a tracker chose for one hop, together with the tracker's [`Ticket`] for it.
#[derive(Debug, Clone, Copy)]
pub struct Selected<'a> {
    /// The chosen reservation, borrowed from the slice passed to [`ReservationTracker::select`].
    pub reservation: &'a Reservation,
    /// The issuing tracker's handle for the state behind `reservation`.
    pub ticket: Ticket,
}

impl<'a> Selected<'a> {
    /// Creates a selection of `reservation` with no associated tracker state.
    #[inline]
    pub const fn untracked(reservation: &'a Reservation) -> Self {
        Self {
            reservation,
            ticket: Ticket::NONE,
        }
    }
}

/// One packet's worth of tracker context, opened by [`ReservationTracker::begin_packet`] and
/// dropped when the packet has been resolved.
///
/// A tracker that guards shared state returns a session holding its lock, so the lock is taken
/// once for the packet instead of once per hop, and selection and commit for that packet cannot
/// interleave with another thread's.
///
/// The methods mirror [`ReservationTracker::select`] and [`ReservationTracker::commit`] and mean
/// exactly the same thing; they take `&mut self` because a session is owned by the one packet
/// being resolved.
pub trait PacketSession {
    /// As [`ReservationTracker::select`], for this packet.
    fn select<'a>(
        &mut self,
        reservations: &'a [Reservation],
        now: SystemTime,
        max_pkt_len: usize,
    ) -> Result<Option<Selected<'a>>, ReservationTrackerError>;

    /// As [`ReservationTracker::commit`], for this packet.
    fn commit(&mut self, selected: &Selected<'_>, pkt_len: usize);
}

/// Chooses which reservation to apply to each hop of a Hummingbird path, and accounts for the
/// packets sent using them.
///
/// The trait is used through `dyn`, so it takes reservations as a slice and returns the concrete
/// [`Ticket`] type rather than being generic over either.
///
/// Methods take `&self` and the trait is [`Sync`]: see the [module documentation][self] for why
/// the synchronisation belongs to the implementation rather than to every caller.
pub trait ReservationTracker: Send + Sync {
    /// Opens a context for one packet, before the first selection for it. `now` is the same
    /// instant every selection for this packet will see.
    ///
    /// Not called at all for paths that carry no reservations, so such a path never pays a
    /// tracker's per-packet setup.
    ///
    /// Returning `Some` hands resolution a [`PacketSession`] to route this packet's selections and
    /// commits through, dropped when the packet is done. That is how a tracker takes a lock
    /// **once per packet** and holds it across selection and commit — which both keeps the
    /// per-packet cost to one acquisition rather than one per hop, and makes select-then-commit
    /// atomic, so two threads cannot both pass a bandwidth check before either deducts.
    ///
    /// Returning `None` — the default — means the tracker has no per-packet context, and
    /// resolution calls [`Self::select`] and [`Self::commit`] on `&self` directly. A lock-free
    /// tracker should do this: it costs nothing, where a session costs one allocation for the
    /// trait object.
    fn begin_packet(&self, now: SystemTime) -> Option<Box<dyn PacketSession + '_>> {
        let _ = now;
        None
    }

    /// Chooses which of a hop's `reservations` to use, if any.
    ///
    /// `max_pkt_len` is an upper bound on the length of the packet being built: the exact length
    /// is not yet known at selection time, and the value passed to [`Self::commit`] is never
    /// larger. Accounting is therefore conservative rather than over-permissive.
    ///
    /// Returns `Ok(None)` when there was nothing to choose from, and an error when candidates
    /// existed but none was usable — which fails the resolution. Wrap the tracker in [`Lenient`]
    /// to fall back to a standard hop field instead.
    fn select<'a>(
        &self,
        reservations: &'a [Reservation],
        now: SystemTime,
        max_pkt_len: usize,
    ) -> Result<Option<Selected<'a>>, ReservationTrackerError>;

    /// Accounts for a packet of exactly `pkt_len` bytes sent using a reservation previously
    /// returned by [`Self::select`].
    fn commit(&self, selected: &Selected<'_>, pkt_len: usize);

    /// Returns how many bytes may currently be sent over the best of `reservations`, if the
    /// tracker tracks that at all.
    ///
    /// Purely a query: it neither selects nor commits. The default returns `None`, for trackers
    /// that enforce no bandwidth limit.
    fn available_bytes_for(&self, reservations: &[Reservation], now: SystemTime) -> Option<usize> {
        let _ = (reservations, now);
        None
    }
}

/// Wraps a tracker so that a hop with no usable reservation degrades to a standard hop field
/// instead of failing the resolution.
///
/// Nothing degrades silently unless asked to: an unwrapped tracker reports
/// [`ReservationTrackerError`] and the send fails, which is what a caller who needs the
/// reservation honoured wants to hear.
#[derive(Debug, Clone, Default)]
pub struct Lenient<T>(pub T);

/// A [`Lenient`] wrapper around another tracker's session, applying the same downgrade: a hop
/// whose reservations are all unusable yields no selection instead of failing the packet.
struct LenientSession<'s>(Box<dyn PacketSession + 's>);

impl PacketSession for LenientSession<'_> {
    fn select<'a>(
        &mut self,
        reservations: &'a [Reservation],
        now: SystemTime,
        max_pkt_len: usize,
    ) -> Result<Option<Selected<'a>>, ReservationTrackerError> {
        Ok(self
            .0
            .select(reservations, now, max_pkt_len)
            .unwrap_or(None))
    }

    fn commit(&mut self, selected: &Selected<'_>, pkt_len: usize) {
        self.0.commit(selected, pkt_len)
    }
}

impl<T: ReservationTracker> ReservationTracker for Lenient<T> {
    /// Wraps the inner tracker's session, if it opens one.
    ///
    /// Answering `None` here would send every selection down the inner tracker's `&self` path,
    /// giving up whatever per-packet locking it does — for a locking tracker, most of its value.
    /// When the inner tracker opens no session there is nothing to wrap, and this type's own
    /// [`select`][Self::select] applies the downgrade instead.
    fn begin_packet(&self, now: SystemTime) -> Option<Box<dyn PacketSession + '_>> {
        self.0
            .begin_packet(now)
            .map(|s| Box::new(LenientSession(s)) as Box<dyn PacketSession + '_>)
    }

    fn select<'a>(
        &self,
        reservations: &'a [Reservation],
        now: SystemTime,
        max_pkt_len: usize,
    ) -> Result<Option<Selected<'a>>, ReservationTrackerError> {
        Ok(self
            .0
            .select(reservations, now, max_pkt_len)
            .unwrap_or(None))
    }

    fn commit(&self, selected: &Selected<'_>, pkt_len: usize) {
        self.0.commit(selected, pkt_len)
    }

    fn available_bytes_for(&self, reservations: &[Reservation], now: SystemTime) -> Option<usize> {
        self.0.available_bytes_for(reservations, now)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    /// Refuses every selection.
    struct AlwaysExpired;
    impl ReservationTracker for AlwaysExpired {
        fn select<'a>(
            &self,
            _: &'a [Reservation],
            _: SystemTime,
            _: usize,
        ) -> Result<Option<Selected<'a>>, ReservationTrackerError> {
            Err(ReservationTrackerError::ReservationExpired)
        }

        fn commit(&self, _: &Selected<'_>, _: usize) {}
    }

    /// Opens a session and counts the openings, making [`Lenient`]'s forwarding observable.
    #[derive(Default)]
    struct SessionCounter {
        opened: AtomicUsize,
    }

    struct CountingSession;
    impl PacketSession for CountingSession {
        fn select<'a>(
            &mut self,
            _: &'a [Reservation],
            _: SystemTime,
            _: usize,
        ) -> Result<Option<Selected<'a>>, ReservationTrackerError> {
            Err(ReservationTrackerError::BandwidthExceeded)
        }

        fn commit(&mut self, _: &Selected<'_>, _: usize) {}
    }

    impl ReservationTracker for SessionCounter {
        fn begin_packet(&self, _: SystemTime) -> Option<Box<dyn PacketSession + '_>> {
            self.opened.fetch_add(1, Ordering::Relaxed);
            Some(Box::new(CountingSession))
        }

        fn select<'a>(
            &self,
            _: &'a [Reservation],
            _: SystemTime,
            _: usize,
        ) -> Result<Option<Selected<'a>>, ReservationTrackerError> {
            Err(ReservationTrackerError::BandwidthExceeded)
        }

        fn commit(&self, _: &Selected<'_>, _: usize) {}
    }

    #[test]
    fn lenient_turns_a_refusal_into_no_selection() {
        let tracker = Lenient(AlwaysExpired);
        assert!(matches!(
            tracker.select(&[], SystemTime::UNIX_EPOCH, 100),
            Ok(None)
        ));
    }

    #[test]
    fn a_strict_tracker_still_refuses() {
        // `AlwaysExpired` refuses on its own account, so the downgrade above is `Lenient`'s doing.
        assert!(matches!(
            AlwaysExpired.select(&[], SystemTime::UNIX_EPOCH, 100),
            Err(ReservationTrackerError::ReservationExpired)
        ));
    }

    #[test]
    fn lenient_forwards_the_inner_trackers_session() {
        // A wrapper that opened no session routes every selection down the inner tracker's
        // `&self` path, leaving its per-packet lock unheld and its enforcement approximate.
        let tracker = Lenient(SessionCounter::default());
        let session = tracker.begin_packet(SystemTime::UNIX_EPOCH);

        assert!(session.is_some());
        assert_eq!(tracker.0.opened.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_lenient_session_downgrades_the_inner_sessions_refusal() {
        // A locking tracker's selections travel through the session, never through `&self`, so
        // the downgrade lives on both paths.
        let tracker = Lenient(SessionCounter::default());
        let mut session = tracker
            .begin_packet(SystemTime::UNIX_EPOCH)
            .expect("forwards the inner session");

        assert!(matches!(
            session.select(&[], SystemTime::UNIX_EPOCH, 100),
            Ok(None)
        ));
    }

    #[test]
    fn a_tracker_is_object_safe() {
        // `Ticket` is concrete rather than an associated type precisely so this compiles: a path
        // holds its tracker as `dyn ReservationTracker`.
        let _: Arc<dyn ReservationTracker> = Arc::new(Lenient(AlwaysExpired));
    }

    #[test]
    fn the_defaults_open_no_session_and_report_no_bandwidth() {
        // The two defaults a lock-free tracker rests on: no session allocation, and no claim to
        // track bandwidth.
        assert!(AlwaysExpired.begin_packet(SystemTime::UNIX_EPOCH).is_none());
        assert!(
            AlwaysExpired
                .available_bytes_for(&[], SystemTime::UNIX_EPOCH)
                .is_none()
        );
    }

    #[test]
    fn an_untracked_selection_carries_the_none_ticket() {
        let reservation = super::super::test_support::reservation(1, 1024, SystemTime::UNIX_EPOCH);
        assert_eq!(Selected::untracked(&reservation).ticket, Ticket::NONE);
    }
}
