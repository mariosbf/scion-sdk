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

//! Hummingbird send-side state, layered on top of a standard path.
//!
//! A *received* Hummingbird path and a *sendable* one are different things. The first is a
//! snapshot of one packet, parsed off the wire, with fixed bytes and no state. The second is a
//! generator of per-packet encodings: its flyover MACs cover the destination AS, the packet
//! length and the send time, so its bytes do not exist until a packet does, and it carries
//! reservations and a tracker that outlive any single packet.
//!
//! This module is the second of those. It hangs off a [`ScionPath`](super::ScionPath) whose
//! dataplane path is *standard*, and everything Hummingbird-specific lives here, so a path
//! without an overlay pays nothing.

use std::{sync::Arc, time::SystemTime};

use crate::{
    core::convert::FromView,
    dataplane_path::standard::{model::HopField, view::StandardPathView},
    hummingbird::{Reservation, tracker::ReservationTracker},
    identifier::isd_asn::IsdAsn,
    path::metadata::PathMetadata,
};

/// One hop of a path that can carry a flyover.
#[derive(Debug, Clone)]
pub struct HbirdHop {
    /// The standard hop field this hop encodes to when it carries no usable
    /// reservations.
    pub(crate) hop_field: HopField,

    /// Index of the segment this hop belongs to, needed to accumulate segment lengths when the
    /// path is laid out.
    pub(crate) seg_idx: usize,

    /// The AS this hop belongs to, when the path's metadata identified it. Used to match
    /// reservations with hops (the interface pair need not be unique).
    pub(crate) isd_asn: Option<IsdAsn>,

    /// The interface this hop is entered through, in traversal order.
    pub(crate) ingress: u16,

    /// The interface this hop is left through, in traversal order.
    ///
    /// For the last hop of a segment this is the *next* segment's first hop's egress: a segment
    /// change is one AS terminating one segment and starting the next, and the reservation covers
    /// the pair of interfaces the traffic actually enters and leaves by.
    pub(crate) egress: u16,

    /// The reservations attached to this hop. Any of them can turn it into a flyover; which one
    /// a given packet uses is the tracker's decision.
    pub(crate) reservations: Vec<Reservation>,
}

impl HbirdHop {
    /// The standard hop field this hop encodes to without a flyover.
    pub fn hop_field(&self) -> &HopField {
        &self.hop_field
    }

    /// The AS this hop belongs to, if the path's metadata identified it.
    pub fn isd_asn(&self) -> Option<IsdAsn> {
        self.isd_asn
    }

    /// The reservations attached to this hop.
    pub fn reservations(&self) -> &[Reservation] {
        &self.reservations
    }

    /// Whether this hop has a reservation that could turn it into a flyover.
    pub fn has_reservation(&self) -> bool {
        !self.reservations.is_empty()
    }

    /// The interface this hop is entered through, in traversal order.
    pub fn ingress(&self) -> u16 {
        self.ingress
    }

    /// The interface this hop is left through, in traversal order.
    ///
    /// For the last hop of a segment ending in an ordinary crossover this is the *next* segment's
    /// first hop's egress, since one AS owns both hop fields. Across a peering link the two hop
    /// fields belong to different ASes and this is the hop's own egress.
    pub fn egress(&self) -> u16 {
        self.egress
    }

    /// Index of the segment this hop belongs to.
    pub fn segment_index(&self) -> usize {
        self.seg_idx
    }
}

/// Hummingbird overlay: attached reservations and the reservation tracker that chooses between
/// them.
///
/// Always an overlay on a *standard* path. A path parsed from a received Hummingbird packet never
/// has one, because its bytes are already fixed and it is not something that gets sent onward
/// without being reversed first.
#[derive(Clone)]
pub struct HbirdOverlay {
    /// The path's hops in encode order, each owning its own reservations. They are nested inside
    /// the hop rather than held in a parallel array, so they cannot desynchronise from it.
    pub(crate) hops: Vec<HbirdHop>,

    /// Decides which of a hop's reservations a given packet uses, if any.
    ///
    /// Shared: one tracker may police several paths against one allowance.
    pub(crate) tracker: Option<Arc<dyn ReservationTracker>>,
}

impl std::fmt::Debug for HbirdOverlay {
    /// A tracker is a trait object with no useful representation, so it appears as whether one is
    /// attached.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HbirdOverlay")
            .field("hops", &self.hops)
            .field("tracker", &self.tracker.is_some())
            .finish()
    }
}

impl HbirdOverlay {
    /// Builds an overlay over `view`'s hops, with no reservations and no tracker.
    ///
    /// `metadata` supplies the per-hop AS attribution; without it no reservation can ever be
    /// matched to a hop by [`try_add_reservation`](Self::try_add_reservation), though
    /// [`add_reservation_at`](Self::add_reservation_at) still works.
    pub(crate) fn new(
        view: &StandardPathView,
        src_ia: IsdAsn,
        metadata: Option<&PathMetadata>,
    ) -> Self {
        let as_sequence = as_sequence(src_ia, metadata);
        let mut hops: Vec<HbirdHop> = Vec::new();
        let mut segment_peering: Vec<bool> = Vec::new();
        let mut as_idx = 0;

        for (seg_idx, (info_field, hop_fields)) in view.segments().enumerate() {
            let peering = info_field.flags().peering();
            segment_peering.push(peering);

            for (hop_idx, hop_field) in hop_fields.iter().enumerate() {
                hops.push(HbirdHop {
                    hop_field: HopField::from_view(hop_field),
                    seg_idx,
                    isd_asn: as_sequence.get(as_idx).copied(),
                    ingress: hop_field.ingress_interface(info_field),
                    egress: hop_field.egress_interface(info_field),
                    reservations: Vec::new(),
                });

                // The AS terminating a segment also starts the next one, so its two hop fields
                // share an entry in the AS sequence — except across a peering link, which joins
                // an AS to its *peer*. There the next segment begins in a different AS, and the
                // sequence advances as it would between any two hops.
                if hop_idx + 1 < hop_fields.len() || peering {
                    as_idx += 1;
                }
            }
        }

        // Across an ordinary crossover one AS owns both hop fields, and traffic leaves it through
        // the next segment's interface, so that is the egress a reservation covers. Across a
        // peering link the two hop fields belong to different ASes and each already carries its
        // own egress; overwriting would replace the peering interface with the peer's.
        for index in 0..hops.len() {
            let crosses_segment = hops
                .get(index + 1)
                .is_some_and(|next| next.seg_idx != hops[index].seg_idx);

            if crosses_segment && !segment_peering[hops[index].seg_idx] {
                hops[index].egress = hops[index + 1].egress;
            }
        }

        Self {
            hops,
            tracker: None,
        }
    }

    /// Attaches `reservation` to whichever hops it covers, matching by AS and interface pair.
    ///
    /// Returns whether any hop matched, so a caller can distinguish "attached" from "this
    /// reservation is not for this path" without inspecting the path.
    ///
    /// A reservation covering an ordinary segment change matches the last hop of the earlier
    /// segment, because that hop's egress was resolved to the next segment's at construction. A
    /// peering crossover is not a segment change for this purpose: its two hop fields sit in
    /// different ASes and each matches on its own interfaces.
    pub(crate) fn try_add_reservation(&mut self, reservation: Reservation) -> bool {
        let info = reservation.info().clone();
        let mut matched = false;

        for hop in &mut self.hops {
            if hop.ingress == info.ingress_interface
                && hop.egress == info.egress_interface
                && hop.isd_asn.is_some_and(|isd_asn| isd_asn == info.isd_as)
            {
                hop.reservations.push(reservation.clone());
                matched = true;
            }
        }

        matched
    }

    /// Attaches `reservation` to the hop at flat index `hop_idx`, counting hops across all
    /// segments in order, without matching it against the hop's interfaces.
    ///
    /// Returns whether the index named a hop.
    pub(crate) fn add_reservation_at(&mut self, hop_idx: usize, reservation: Reservation) -> bool {
        match self.hops.get_mut(hop_idx) {
            Some(hop) => {
                hop.reservations.push(reservation);
                true
            }
            None => false,
        }
    }

    /// Drops every reservation whose validity window has passed by `now`.
    pub(crate) fn remove_expired_reservations(&mut self, now: SystemTime) {
        for hop in &mut self.hops {
            hop.reservations
                .retain(|reservation| reservation.is_valid_at(now));
        }
    }

    /// The path's hops in encode order, with their AS attribution and attached reservations.
    pub fn hops(&self) -> &[HbirdHop] {
        &self.hops
    }

    /// Whether any hop carries a reservation.
    ///
    /// `false` means every send over this path is a plain copy of the standard path's bytes: no
    /// tracker session is opened and no MAC is computed.
    pub(crate) fn has_reservations(&self) -> bool {
        self.hops.iter().any(HbirdHop::has_reservation)
    }
}

/// The ASes a path traverses, in order, one entry per AS rather than per hop field.
///
/// Metadata lists interfaces per *link*: the first is the source AS's egress, then each pair is
/// one AS's ingress and egress, and the last is the destination AS's ingress. So the AS of the
/// `k`th entry is the ISD-AS of interface `2k - 1`, and of the first is the source itself.
fn as_sequence(src_ia: IsdAsn, metadata: Option<&PathMetadata>) -> Vec<IsdAsn> {
    let Some(interfaces) = metadata.and_then(|metadata| metadata.interfaces.as_ref()) else {
        return Vec::new();
    };

    if interfaces.is_empty() {
        return Vec::new();
    }

    let mut sequence = vec![src_ia];
    sequence.extend(
        interfaces[1..]
            .iter()
            .step_by(2)
            .map(|interface| interface.interface.isd_asn),
    );
    sequence
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use tinyvec::array_vec;

    use super::*;
    use crate::{
        core::model::Model,
        dataplane_path::{
            hbird::model::{HbirdHopField, HbirdSegment, HummingbirdPath},
            resolve::PathResolveError,
            standard::{
                model::{InfoField, Segment, StandardPath},
                types::{HopFieldFlags, HopFieldMac, InfoFieldFlags},
            },
            view::ScionDpPathView,
        },
        hummingbird::{
            Bandwidth, Reservation, ReservationInfo, probabilistic_tracker::ProbabilisticTracker,
        },
        path::{
            ScionPath,
            metadata::{PathMetadata, path_interface::PathInterface},
        },
    };

    const START: u64 = 1_700_000_000;

    fn ia(asn: u64) -> IsdAsn {
        IsdAsn(0x1_ff00_0000_0000 | asn)
    }

    fn hop(cons_ingress: u16, cons_egress: u16) -> HopField {
        HopField {
            flags: HopFieldFlags::empty(),
            expiration_units: 63,
            cons_ingress,
            cons_egress,
            mac: HopFieldMac::zero(),
        }
    }

    fn info() -> InfoField {
        InfoField {
            flags: InfoFieldFlags::CONS_DIR,
            segment_id: 7,
            timestamp: START as u32,
        }
    }

    fn segment(hops: &[(u16, u16)]) -> Segment {
        Segment {
            info_field: info(),
            hop_fields: hops.iter().map(|&(i, e)| hop(i, e)).collect(),
        }
    }

    /// `1-ff00:0:110` -(1)-> `1-ff00:0:111` -(3)-> `1-ff00:0:112`, in one segment.
    fn one_segment_path() -> ScionPath {
        let path = StandardPath {
            current_info_field: 0,
            current_hop_field: 0,
            segments: array_vec!([Segment; 3] => segment(&[(0, 1), (2, 3), (4, 0)])),
        };

        ScionPath::new(
            ia(0x110),
            ia(0x112),
            ScionDpPathView::Standard(path.try_encode_to_owned_view().expect("encodes")),
            Some(metadata(&[
                (ia(0x110), 1),
                (ia(0x111), 2),
                (ia(0x111), 3),
                (ia(0x112), 4),
            ])),
            None,
        )
    }

    /// The same three ASes across two segments, so `1-ff00:0:111` terminates the first and starts
    /// the second and therefore owns two hop fields.
    fn two_segment_path() -> ScionPath {
        let path = StandardPath {
            current_info_field: 0,
            current_hop_field: 0,
            segments: array_vec!([Segment; 3] =>
                segment(&[(0, 1), (2, 0)]),
                segment(&[(0, 3), (4, 0)]),
            ),
        };

        ScionPath::new(
            ia(0x110),
            ia(0x112),
            ScionDpPathView::Standard(path.try_encode_to_owned_view().expect("encodes")),
            Some(metadata(&[
                (ia(0x110), 1),
                (ia(0x111), 2),
                (ia(0x111), 3),
                (ia(0x112), 4),
            ])),
            None,
        )
    }

    fn metadata(interfaces: &[(IsdAsn, u16)]) -> PathMetadata {
        PathMetadata::new_minimal(
            START + 3600,
            1400,
            interfaces
                .iter()
                .map(|&(isd_asn, id)| PathInterface::new(isd_asn, id))
                .collect(),
        )
    }

    fn reservation(isd_as: IsdAsn, ingress: u16, egress: u16, duration: u16) -> Reservation {
        Reservation::new(
            ReservationInfo {
                isd_as,
                ingress_interface: ingress,
                egress_interface: egress,
                res_id: 0x1234,
                bandwidth: Bandwidth::from_bytes_per_sec(1024).expect("representable"),
                start: UNIX_EPOCH + Duration::from_secs(START),
                duration,
            },
            [0x11; 16],
        )
    }

    /// A path parsed from a received Hummingbird packet.
    fn received_hbird_path() -> ScionPath {
        let path = HummingbirdPath {
            current_info_field: 0,
            current_hop_field: 0,
            segments: vec![HbirdSegment {
                info_field: info(),
                hop_fields: std::iter::repeat_with(|| HbirdHopField::Standard(hop(0, 1)))
                    .take(2)
                    .collect(),
            }],
            base_timestamp: START as u32,
            millis_timestamp: 0,
            counter: 0,
        };

        ScionPath::new(
            ia(0x110),
            ia(0x112),
            ScionDpPathView::Hummingbird(path.try_encode_to_owned_view().expect("encodes")),
            None,
            None,
        )
    }

    #[test]
    fn send_side_operations_are_refused_on_paths_that_cannot_carry_reservations() {
        // A received Hummingbird path is a snapshot of one packet already sent, and an empty path
        // has no hops at all. Accepting a reservation on either would produce a path whose
        // encoding no router accepts.
        for mut path in [
            received_hbird_path(),
            ScionPath::local(ia(0x110)).expect("not a wildcard"),
        ] {
            assert_eq!(
                path.try_add_reservation(reservation(ia(0x110), 0, 1, 3600)),
                Err(PathResolveError::ReservationsUnsupported),
            );
            assert_eq!(
                path.set_tracker(Arc::new(ProbabilisticTracker::new())),
                Err(PathResolveError::ReservationsUnsupported),
            );
        }
    }

    #[test]
    fn a_tracker_can_be_attached_before_any_reservation_arrives() {
        // Deliberately not an error: it creates an empty overlay so a tracker can be installed at
        // path-handout time, and an empty overlay costs nothing at send time.
        let mut path = one_segment_path();

        assert_eq!(
            path.set_tracker(Arc::new(ProbabilisticTracker::new())),
            Ok(())
        );
        assert!(!path.has_reservations());
    }

    #[test]
    fn a_reservation_attaches_to_the_hop_it_covers() {
        let mut path = one_segment_path();

        assert_eq!(
            path.try_add_reservation(reservation(ia(0x111), 2, 3, 3600)),
            Ok(true)
        );
        assert!(path.has_reservations());
    }

    #[test]
    fn a_reservation_for_another_as_does_not_attach() {
        let mut path = one_segment_path();

        assert_eq!(
            path.try_add_reservation(reservation(ia(0x113), 2, 3, 3600)),
            Ok(false)
        );
        assert!(!path.has_reservations());
    }

    #[test]
    fn a_reservation_for_the_wrong_interfaces_does_not_attach() {
        let mut path = one_segment_path();

        assert_eq!(
            path.try_add_reservation(reservation(ia(0x111), 9, 3, 3600)),
            Ok(false)
        );
        assert!(!path.has_reservations());
    }

    #[test]
    fn a_reservation_covering_a_segment_change_attaches_to_the_earlier_segments_last_hop() {
        // The AS that terminates one segment starts the next, so traffic enters through the last
        // hop of the earlier segment and leaves through the first hop of the later one. A matcher
        // reading only the hop's own egress finds nothing, and the reservation is dropped without
        // a word — which looks exactly like never having been issued.
        let mut path = two_segment_path();

        assert_eq!(
            path.try_add_reservation(reservation(ia(0x111), 2, 3, 3600)),
            Ok(true)
        );
        assert!(path.has_reservations());

        let overlay = path.hbird.as_ref().expect("the overlay was created");
        let attached: Vec<usize> = overlay
            .hops
            .iter()
            .enumerate()
            .filter(|(_, hop)| hop.has_reservation())
            .map(|(index, _)| index)
            .collect();

        assert_eq!(attached, vec![1], "the last hop of segment 0");
    }

    #[test]
    fn the_crossover_as_owns_both_of_its_hop_fields() {
        // Metadata lists interfaces per link, so the crossover AS appears once there but twice in
        // the hop fields. An attribution that advanced per hop field would shift every AS after
        // the crossover by one.
        let mut path = two_segment_path();
        path.set_tracker(Arc::new(ProbabilisticTracker::new()))
            .expect("standard path");

        let overlay = path.hbird.as_ref().expect("the overlay was created");
        let ases: Vec<Option<IsdAsn>> = overlay.hops.iter().map(HbirdHop::isd_asn).collect();

        assert_eq!(
            ases,
            vec![
                Some(ia(0x110)),
                Some(ia(0x111)),
                Some(ia(0x111)),
                Some(ia(0x112))
            ],
        );
    }

    /// The peering shape a live topology produces: an up segment ending in the AS that holds the
    /// peering interface, and a down segment starting in its *peer*. Both info fields carry the
    /// peering flag.
    ///
    /// `1-ff00:0:112` -(494)-> `1-ff00:0:111` =peer(100/4)= `1-ff00:0:121`.
    fn peering_path() -> ScionPath {
        let up = Segment {
            info_field: InfoField {
                flags: InfoFieldFlags::PEERING,
                segment_id: 7,
                timestamp: START as u32,
            },
            hop_fields: [hop(494, 0), hop(100, 103)].into_iter().collect(),
        };
        let down = Segment {
            info_field: InfoField {
                flags: InfoFieldFlags::CONS_DIR | InfoFieldFlags::PEERING,
                segment_id: 9,
                timestamp: START as u32,
            },
            hop_fields: [hop(4, 0)].into_iter().collect(),
        };

        let path = StandardPath {
            current_info_field: 0,
            current_hop_field: 0,
            segments: array_vec!([Segment; 3] => up, down),
        };

        ScionPath::new(
            ia(0x112),
            ia(0x121),
            ScionDpPathView::Standard(path.try_encode_to_owned_view().expect("encodes")),
            Some(metadata(&[
                (ia(0x112), 494),
                (ia(0x111), 103),
                (ia(0x111), 100),
                (ia(0x121), 4),
            ])),
            None,
        )
    }

    #[test]
    fn a_peering_crossover_joins_two_different_ases() {
        // A peering link connects an AS to its *peer*, so unlike an ordinary crossover the two
        // hop fields either side of it belong to different ASes. Treating it as an ordinary
        // crossover shifts every hop from there on one place too early, and every reservation
        // past the peering link silently fails to match.
        let mut path = peering_path();
        path.set_tracker(Arc::new(ProbabilisticTracker::new()))
            .expect("standard path");

        let overlay = path.hbird.as_ref().expect("the overlay was created");
        let ases: Vec<Option<IsdAsn>> = overlay.hops.iter().map(HbirdHop::isd_asn).collect();

        assert_eq!(
            ases,
            vec![Some(ia(0x112)), Some(ia(0x111)), Some(ia(0x121))]
        );
    }

    #[test]
    fn a_peering_hop_keeps_its_own_egress() {
        // The egress carry-over exists because an ordinary crossover's two hop fields are one AS
        // entered and left by different segments' interfaces. Applying it across a peering link
        // would overwrite the peering interface with the peer's.
        let mut path = peering_path();
        path.set_tracker(Arc::new(ProbabilisticTracker::new()))
            .expect("standard path");

        let overlay = path.hbird.as_ref().expect("the overlay was created");
        let egresses: Vec<u16> = overlay.hops.iter().map(|hop| hop.egress).collect();

        assert_eq!(egresses, vec![494, 100, 0]);
    }

    #[test]
    fn a_reservation_for_a_peering_hop_attaches_to_it() {
        let mut path = peering_path();

        assert_eq!(
            path.try_add_reservation(reservation(ia(0x111), 103, 100, 3600)),
            Ok(true)
        );

        let overlay = path.hbird.as_ref().expect("the overlay was created");
        let attached: Vec<usize> = overlay
            .hops
            .iter()
            .enumerate()
            .filter(|(_, hop)| hop.has_reservation())
            .map(|(index, _)| index)
            .collect();

        assert_eq!(attached, vec![1]);
    }

    #[test]
    fn a_reservation_beyond_a_peering_link_attaches_to_the_peer() {
        // The hop the misattribution used to hand to the wrong AS.
        let mut path = peering_path();

        assert_eq!(
            path.try_add_reservation(reservation(ia(0x121), 4, 0, 3600)),
            Ok(true)
        );
        assert_eq!(
            path.try_add_reservation(reservation(ia(0x111), 4, 0, 3600)),
            Ok(false)
        );
    }

    #[test]
    fn a_single_segment_path_attributes_one_hop_field_per_as() {
        let mut path = one_segment_path();
        path.set_tracker(Arc::new(ProbabilisticTracker::new()))
            .expect("standard path");

        let overlay = path.hbird.as_ref().expect("the overlay was created");
        let ases: Vec<Option<IsdAsn>> = overlay.hops.iter().map(HbirdHop::isd_asn).collect();

        assert_eq!(
            ases,
            vec![Some(ia(0x110)), Some(ia(0x111)), Some(ia(0x112))]
        );
    }

    #[test]
    fn a_path_without_metadata_matches_nothing_but_still_takes_an_indexed_reservation() {
        // Without metadata no hop has a known AS, so the interface matcher can never fire. The
        // indexed form is the escape hatch for exactly this case.
        let path = StandardPath {
            current_info_field: 0,
            current_hop_field: 0,
            segments: array_vec!([Segment; 3] => segment(&[(0, 1), (2, 0)])),
        };
        let mut path = ScionPath::new(
            ia(0x110),
            ia(0x112),
            ScionDpPathView::Standard(path.try_encode_to_owned_view().expect("encodes")),
            None,
            None,
        );

        assert_eq!(
            path.try_add_reservation(reservation(ia(0x110), 0, 1, 3600)),
            Ok(false)
        );
        assert_eq!(
            path.add_reservation_at(0, reservation(ia(0x110), 0, 1, 3600)),
            Ok(())
        );
        assert!(path.has_reservations());
    }

    #[test]
    fn an_out_of_range_hop_index_is_refused() {
        let mut path = one_segment_path();

        assert_eq!(
            path.add_reservation_at(99, reservation(ia(0x110), 0, 1, 3600)),
            Err(PathResolveError::HopIndexOutOfRange {
                index: 99,
                hop_count: 3,
            }),
        );
    }

    #[test]
    fn attaching_a_reservation_changes_neither_the_fingerprint_nor_the_expiration() {
        // Reservations are credentials layered over a route, not part of it. A path that changed
        // identity whenever a reservation was renewed would churn the whole path set.
        let mut path = one_segment_path();
        let (fingerprint, expiration) = (path.fingerprint(), path.expiration());

        path.try_add_reservation(reservation(ia(0x111), 2, 3, 3600))
            .expect("standard path");

        assert_eq!(path.fingerprint(), fingerprint);
        assert_eq!(path.expiration(), expiration);
    }

    #[test]
    fn two_paths_differing_only_in_their_reservations_are_equal() {
        // The same distinction, at the `PartialEq` boundary this time: path-set dedup must not
        // start treating one route as two because one copy has a reservation attached.
        let mut with_reservation = one_segment_path();
        with_reservation
            .try_add_reservation(reservation(ia(0x111), 2, 3, 3600))
            .expect("standard path");

        assert_eq!(with_reservation, one_segment_path());
    }

    #[test]
    fn reversing_a_path_drops_its_reservations() {
        // Flyover reservations are directional: the reverse path traverses the same ASes by
        // different interfaces, so keeping them would mint MACs no router accepts.
        let mut path = one_segment_path();
        path.try_add_reservation(reservation(ia(0x111), 2, 3, 3600))
            .expect("standard path");
        assert!(path.has_reservations());

        path.try_reverse().expect("a standard path reverses");

        assert!(!path.has_reservations());
    }

    #[test]
    fn expired_reservations_are_pruned_and_valid_ones_kept() {
        let mut path = one_segment_path();
        path.try_add_reservation(reservation(ia(0x111), 2, 3, 60))
            .expect("standard path");
        path.try_add_reservation(reservation(ia(0x111), 2, 3, 7200))
            .expect("standard path");

        path.remove_expired_reservations(UNIX_EPOCH + Duration::from_secs(START + 3600));

        let overlay = path.hbird.as_ref().expect("the overlay was created");
        let remaining: Vec<u16> = overlay
            .hops
            .iter()
            .flat_map(|hop| hop.reservations())
            .map(|reservation| reservation.info().duration)
            .collect();

        assert_eq!(remaining, vec![7200]);
    }

    #[test]
    fn pruning_a_hops_last_reservation_leaves_the_path_bare() {
        let mut path = one_segment_path();
        path.try_add_reservation(reservation(ia(0x111), 2, 3, 60))
            .expect("standard path");

        path.remove_expired_reservations(UNIX_EPOCH + Duration::from_secs(START + 3600));

        assert!(!path.has_reservations());
    }

    #[test]
    fn several_reservations_can_share_one_hop() {
        // A hop may hold more than one allowance; choosing between them is the tracker's job.
        let mut path = one_segment_path();
        path.try_add_reservation(reservation(ia(0x111), 2, 3, 3600))
            .expect("standard path");
        path.try_add_reservation(reservation(ia(0x111), 2, 3, 1800))
            .expect("standard path");

        let overlay = path.hbird.as_ref().expect("the overlay was created");
        assert_eq!(overlay.hops[1].reservations().len(), 2);
    }
}
