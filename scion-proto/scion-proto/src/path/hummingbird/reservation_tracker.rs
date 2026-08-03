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

/// Chooses which reservation to apply to each hop of a Hummingbird path, and
/// accounts for the packets that are sent using them.
///
/// The trait is used through `dyn`, so it takes reservations as a slice and
/// returns the concrete [`Ticket`] type rather than being generic over either.
pub trait ReservationTracker: Send {
    /// Called once per packet, before the first [`Self::select`] for that packet
    /// and under the same lock, for trackers that keep per-packet or periodic
    /// state. `now` is the same instant every `select` for this packet will see.
    ///
    /// Not called at all for paths that carry no reservations.
    fn begin_packet(&mut self, now: SystemTime) {
        let _ = now;
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
        &mut self,
        reservations: &'a [Reservation],
        now: SystemTime,
        max_pkt_len: usize,
    ) -> Result<Option<Selected<'a>>, ReservationTrackerError>;

    /// Accounts for a packet of exactly `pkt_len` bytes sent using a reservation
    /// previously returned by [`Self::select`].
    fn commit(&mut self, selected: &Selected<'_>, pkt_len: usize);

    /// Returns how many bytes may currently be sent over the best of
    /// `reservations`, if the tracker tracks that at all.
    ///
    /// Purely a query: it neither selects nor commits. The default returns `None`,
    /// for trackers that enforce no bandwidth limit.
    fn available_bytes_for(
        &mut self,
        reservations: &[Reservation],
        now: SystemTime,
    ) -> Option<usize> {
        let _ = (reservations, now);
        None
    }
}

/// Wraps a tracker so that a hop with no usable reservation degrades to a
/// standard hop field instead of failing the encode.
#[derive(Debug, Clone, Default)]
pub struct Lenient<T>(pub T);

impl<T: ReservationTracker> ReservationTracker for Lenient<T> {
    fn begin_packet(&mut self, now: SystemTime) {
        self.0.begin_packet(now)
    }

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

    fn available_bytes_for(
        &mut self,
        reservations: &[Reservation],
        now: SystemTime,
    ) -> Option<usize> {
        self.0.available_bytes_for(reservations, now)
    }
}
