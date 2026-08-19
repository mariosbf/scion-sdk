//! The reservation tracker interface used when encoding Hummingbird paths.
//!
//! Encoding a packet consults the tracker twice per hop: [`ReservationTracker::select`]
//! picks which of the hop's reservations to use, and [`ReservationTracker::commit`]
//! accounts for the packet once its exact length is known. The two are separate
//! because reservation selection determines how many hop fields become flyovers,
//! which in turn determines the packet length — so selection necessarily runs
//! against an upper bound, and only the commit sees the real figure.
//!
//! Implementations decide their own enforcement policy. A tracker that returns an
//! error makes encoding fail; wrap it in [`Lenient`] to have unusable hops fall
//! back to standard hop fields instead.
//!
//! # Sharing between threads
//!
//! Every method takes `&self`, and the trait requires [`Sync`], so a tracker is
//! shared between sender threads as a plain `Arc` with no lock around it. This
//! is deliberate: taking `&mut self` would force *every* implementation to sit
//! behind one mutex on the per-packet path, including those with nothing to
//! synchronise. [`ProbabilisticTracker`] holds only a random-number generator —
//! two threads drawing independently spread traffic exactly as well as two
//! threads sharing one draw — so an exclusive lock there buys nothing and
//! serialises encoding for no reason.
//!
//! Implementations that *do* need shared mutable state take that cost
//! themselves, and only where they need it. [`TokenBucketTracker`] does: its
//! whole purpose is to hold senders to a bandwidth limit, which cannot be done
//! without coordination.
//!
//! ## Granularity
//!
//! A tracker that needs a lock should take it **once per packet**, not once per
//! hop, by returning a [`PacketSession`] from
//! [`ReservationTracker::begin_packet`]. Encoding routes that packet's
//! selections and commits through the session and drops it at the end, so the
//! guard is held across the whole packet. Answering `None` instead — the
//! default, and the right answer for a lock-free tracker — costs nothing and
//! sends every call down the `&self` path.
//!
//! ## Atomicity
//!
//! A tracker that opens a session sees selection and commit for one packet as
//! one critical section, exactly as before this trait took `&self`: no other
//! thread can interleave, so a bandwidth check cannot be overtaken by another
//! thread's commit. [`TokenBucketTracker`] does this, which is what makes its
//! enforcement exact rather than approximate.
//!
//! A tracker that declines a session gets no such guarantee — but a tracker
//! declines precisely because it has no shared state to be atomic about.
//!
//! [`ProbabilisticTracker`]: super::ProbabilisticTracker
//! [`TokenBucketTracker`]: super::TokenBucketTracker

use std::time::SystemTime;

use crate::hummingbird::Reservation;

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

/// An opaque reference to whatever state a tracker resolved while selecting a
/// reservation, handed back to [`ReservationTracker::commit`] so that the tracker
/// need not look it up a second time.
///
/// The meaning of the value is entirely up to the tracker that issued it — no
/// other code may interpret it. Trackers that keep no per-reservation state
/// issue [`Ticket::NONE`] and ignore it on commit.
///
/// This is deliberately a concrete type rather than an associated type on the
/// trait: [`HummingbirdPath`] stores its tracker as a trait object, and an
/// associated type would make the trait unusable as `dyn`.
///
/// [`HummingbirdPath`]: crate::path::hummingbird::HummingbirdPath
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket(u64);

impl Ticket {
    /// The ticket issued by trackers that carry no state between select and commit.
    pub const NONE: Ticket = Ticket(u64::MAX);

    /// Creates a ticket carrying `value`.
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the value this ticket carries.
    pub fn value(self) -> u64 {
        self.0
    }
}

/// A reservation chosen by a tracker for one hop, together with the tracker's
/// [`Ticket`] for it.
#[derive(Debug, Clone, Copy)]
pub struct Selected<'a> {
    /// The chosen reservation, borrowed from the slice passed to
    /// [`ReservationTracker::select`].
    pub reservation: &'a Reservation,
    /// The issuing tracker's handle for the state behind `reservation`.
    pub ticket: Ticket,
}

impl<'a> Selected<'a> {
    /// Creates a selection of `reservation` with no associated tracker state.
    pub fn untracked(reservation: &'a Reservation) -> Self {
        Self {
            reservation,
            ticket: Ticket::NONE,
        }
    }
}

/// One packet's worth of tracker context, opened by
/// [`ReservationTracker::begin_packet`] and dropped when the packet is encoded.
///
/// A tracker that guards shared state returns a session holding its lock, so
/// the lock is taken once for the packet instead of once per hop, and selection
/// and commit for that packet cannot interleave with another thread's.
///
/// The methods mirror [`ReservationTracker::select`] and
/// [`ReservationTracker::commit`] and mean exactly the same thing; they take
/// `&mut self` because a session is owned by the one packet being encoded.
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

/// Chooses which reservation to apply to each hop of a Hummingbird path, and
/// accounts for the packets that are sent using them.
///
/// The trait is used through `dyn`, so it takes reservations as a slice and
/// returns the concrete [`Ticket`] type rather than being generic over either.
///
/// Methods take `&self` and the trait is [`Sync`]: see the module documentation
/// for why the synchronisation belongs to the implementation rather than to
/// every caller.
pub trait ReservationTracker: Send + Sync {
    /// Opens a context for one packet, before the first selection for it.
    /// `now` is the same instant every selection for this packet will see.
    ///
    /// Not called at all for paths that carry no reservations.
    ///
    /// Returning `Some` hands encoding a [`PacketSession`] to route this
    /// packet's selections and commits through, and it is dropped when the
    /// packet is done. That is how a tracker takes a lock **once per packet**
    /// and holds it across selection, encoding and the commit — which both
    /// keeps the per-packet cost to one acquisition rather than one per hop,
    /// and makes select-then-commit atomic, so two threads cannot both pass a
    /// bandwidth check before either deducts.
    ///
    /// Returning `None` — the default — means the tracker has no per-packet
    /// context, and encoding calls [`Self::select`] and [`Self::commit`] on
    /// `&self` directly. A lock-free tracker should do this: it costs nothing,
    /// where a session costs one allocation for the trait object.
    fn begin_packet(&self, now: SystemTime) -> Option<Box<dyn PacketSession + '_>> {
        let _ = now;
        None
    }

    /// Chooses which of a hop's `reservations` to use, if any.
    ///
    /// `max_pkt_len` is an upper bound on the length of the packet being built:
    /// the exact length is not yet known at selection time, and the value passed
    /// to [`Self::commit`] is never larger.
    ///
    /// Returns `Ok(None)` when there is nothing to choose from, and an error when
    /// candidates existed but none was usable — which fails the encode. Wrap the
    /// tracker in [`Lenient`] to fall back to a standard hop field instead.
    fn select<'a>(
        &self,
        reservations: &'a [Reservation],
        now: SystemTime,
        max_pkt_len: usize,
    ) -> Result<Option<Selected<'a>>, ReservationTrackerError>;

    /// Accounts for a packet of exactly `pkt_len` bytes sent using a reservation
    /// previously returned by [`Self::select`].
    fn commit(&self, selected: &Selected<'_>, pkt_len: usize);

    /// Returns how many bytes may currently be sent over the best of
    /// `reservations`, if the tracker tracks that at all.
    ///
    /// Purely a query: it neither selects nor commits. The default returns `None`,
    /// for trackers that enforce no bandwidth limit.
    fn available_bytes_for(&self, reservations: &[Reservation], now: SystemTime) -> Option<usize> {
        let _ = (reservations, now);
        None
    }
}

/// Wraps a tracker so that a hop with no usable reservation degrades to a
/// standard hop field instead of failing the encode.
#[derive(Debug, Clone, Default)]
pub struct Lenient<T>(pub T);

/// A [`Lenient`] wrapper around another tracker's session, applying the same
/// downgrade: a hop whose reservations are all unusable yields no selection
/// instead of failing the packet.
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
    /// Forwarding matters: answering `None` here would send every selection
    /// down the inner tracker's `&self` path and give up whatever per-packet
    /// locking it does, which for a locking tracker is most of the point.
    /// When the inner tracker opens no session there is nothing to wrap, and
    /// this type's own `select` applies the downgrade instead.
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
