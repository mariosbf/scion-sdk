//! Hummingbird SCION paths.

pub mod hop_field;
pub use hop_field::*;

pub mod meta_header;
pub use meta_header::*;

pub mod path;
pub use path::*;

pub mod crypto;
pub use crypto::*;

pub mod flyover_mac_path;
pub use flyover_mac_path::*;

pub(super) mod token_bucket;

/// Chooses which reservation to apply to each hop when encoding a path.
pub mod reservation_tracker;
pub use reservation_tracker::{
    Lenient, ReservationTracker, ReservationTrackerError, Selected, Ticket,
};

/// Tracks per-flow Hummingbird reservations and enforces bandwidth limits.
pub mod token_bucket_tracker;
pub use token_bucket_tracker::TokenBucketTracker;

/// Spreads traffic across reservations by bandwidth, without enforcing limits.
pub mod probabilistic_tracker;
pub use probabilistic_tracker::ProbabilisticTracker;
