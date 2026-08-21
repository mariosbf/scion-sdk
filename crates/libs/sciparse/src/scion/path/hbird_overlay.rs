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
    core::{convert::FromView, encode::WireEncode},
    dataplane_path::{
        hbird::{
            layout::FlyoverHopFieldLayout,
            model::{FlyoverHopField, HbirdEncodeError, HbirdHopField, HbirdMetaFields},
        },
        standard::{
            layout::HopFieldLayout,
            model::{HopField, InfoField},
            view::StandardPathView,
        },
    },
    hummingbird::{Reservation, tracker::ReservationTracker},
    identifier::isd_asn::IsdAsn,
    path::metadata::PathMetadata,
};

/// A precomputed encoding of the path header for the shape in which every hop that carries a
/// reservation is a flyover hop field.
///
/// Everything that varies from packet to packet is left zero: the meta header's timestamp and
/// counter, and in each flyover hop field the aggregated MAC together with the
/// reservation-dependent fields. Resolution copies this and patches those regions, which is why
/// it depends on neither the destination, nor the payload length, nor which reservation a tracker
/// happens to pick.
///
/// It describes the path's *structure*, so it holds until the structure changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Template {
    /// The encoded path header with every per-packet field zeroed and the meta header's layout
    /// fields — segment lengths and current hop field offset — already final.
    pub(crate) encoded: Vec<u8>,

    /// Those layout fields on their own, so resolution writes a complete meta header in one pass
    /// rather than patching around the ones the template baked in.
    pub(crate) meta: HbirdMetaFields,

    /// Byte offset of each flyover hop field from the start of the encoded path, in encode order.
    /// Patching walks these instead of rediscovering hop field boundaries.
    pub(crate) flyover_offsets: Vec<usize>,
}

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

    /// The path's info fields, in encode order. Copied at construction because they are the part
    /// of the header that neither a packet nor a reservation ever changes.
    pub(crate) info_fields: Vec<InfoField>,

    /// The info field the path is currently at, carried through from the standard path unchanged.
    pub(crate) current_info_field: u8,

    /// The hop field the path is currently at, as an index into the standard path's uniform
    /// 12-byte hops. Widening an earlier hop into a flyover moves this hop's byte offset but not
    /// its position in the sequence, so the index is what survives a change of shape.
    pub(crate) current_hop_field_index: usize,

    /// Decides which of a hop's reservations a given packet uses, if any.
    ///
    /// Shared: one tracker may police several paths against one allowance.
    pub(crate) tracker: Option<Arc<dyn ReservationTracker>>,

    /// The encoding of the all-flyover shape, rebuilt whenever the set of hops carrying
    /// reservations changes.
    ///
    /// `None` when that shape does not fit the meta header, whose segment lengths are 7-bit line
    /// counts (127 lines, 508 bytes) and whose current hop field is an 8-bit one (255 lines, 1020
    /// bytes). Both need many flyovers on a long path, and neither rules the path out: resolution
    /// lays out the shape it actually selected, which is never wider.
    pub(crate) template: Option<Template>,
}

impl std::fmt::Debug for HbirdOverlay {
    /// A tracker is a trait object with no useful representation, so it appears as whether one is
    /// attached.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HbirdOverlay")
            .field("hops", &self.hops)
            .field("info_fields", &self.info_fields)
            .field("current_info_field", &self.current_info_field)
            .field("current_hop_field_index", &self.current_hop_field_index)
            .field("tracker", &self.tracker.is_some())
            .field("template", &self.template)
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
        let mut info_fields: Vec<InfoField> = Vec::new();
        let mut segment_peering: Vec<bool> = Vec::new();
        let mut as_idx = 0;

        for (seg_idx, (info_field, hop_fields)) in view.segments().enumerate() {
            let peering = info_field.flags().peering();
            segment_peering.push(peering);
            info_fields.push(InfoField::from_view(info_field));

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

        let mut overlay = Self {
            hops,
            info_fields,
            current_info_field: view.curr_info_field_idx(),
            current_hop_field_index: view.curr_hop_field_idx() as usize,
            tracker: None,
            template: None,
        };
        overlay.rebuild_template();
        overlay
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

        if matched {
            self.rebuild_template();
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
                self.rebuild_template();
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

        self.rebuild_template();
    }

    /// The path's hops in encode order, with their AS attribution and attached reservations.
    pub fn hops(&self) -> &[HbirdHop] {
        &self.hops
    }

    /// Attaches `tracker`, replacing any previous one.
    pub(crate) fn set_tracker(&mut self, tracker: Arc<dyn ReservationTracker>) {
        self.tracker = Some(tracker);
    }

    /// Recomputes the cached template.
    ///
    /// Called by every method that can change which hops carry reservations; a mutator that
    /// forgets leaves the path encoding to its previous shape.
    fn rebuild_template(&mut self) {
        self.template = self.compute_template();
    }

    /// Builds the template for the current set of reservations.
    ///
    /// A shape that does not fit the meta header yields `None` rather than an error: the caller is
    /// a cache rebuild with nowhere to report it, and resolution rediscovers the same failure —
    /// with the real selection, which may well fit — when it lays the path out for a packet.
    fn compute_template(&self) -> Option<Template> {
        let mut meta = HbirdMetaFields {
            current_info_field: self.current_info_field,
            ..Default::default()
        };
        let encoded_len = self
            .apply_header_layout(&mut meta, |_, hop| hop.has_reservation())
            .ok()?;

        let mut encoded = vec![0u8; encoded_len];
        let mut at = meta.try_encode(&mut encoded).ok()?;
        for info_field in &self.info_fields {
            at += info_field.try_encode(&mut encoded[at..]).ok()?;
        }

        let mut flyover_offsets = Vec::new();
        for hop in &self.hops {
            if hop.has_reservation() {
                let buf: &mut [u8; FlyoverHopFieldLayout::SIZE_BYTES] = encoded
                    .get_mut(at..at + FlyoverHopFieldLayout::SIZE_BYTES)?
                    .try_into()
                    .ok()?;
                FlyoverHopField::encode_template(&hop.hop_field, buf);
                flyover_offsets.push(at);
                at += FlyoverHopFieldLayout::SIZE_BYTES;
            } else {
                // Wrapped rather than encoded directly so that a standard hop field carrying the
                // reserved bit that Hummingbird reads as the flyover discriminator is rejected
                // here, instead of being read back as a 20-byte field that swallows its successor.
                at += HbirdHopField::Standard(hop.hop_field)
                    .try_encode(&mut encoded[at..])
                    .ok()?;
            }
        }
        debug_assert_eq!(at, encoded_len, "the layout and the encoder disagree");

        Some(Template {
            encoded,
            meta,
            flyover_offsets,
        })
    }

    /// Computes the byte layout of the encoded path header for one particular choice of which
    /// hops become flyover hop fields, writing the resulting segment lengths and current hop field
    /// offset into `meta` and returning the header's total encoded length.
    ///
    /// `is_flyover` is asked once per hop in encode order, receiving the hop's flat index and the
    /// hop itself. The template answers from whether the hop carries any reservation at all;
    /// resolution answers from what its tracker selected.
    pub(crate) fn apply_header_layout(
        &self,
        meta: &mut HbirdMetaFields,
        is_flyover: impl Fn(usize, &HbirdHop) -> bool,
    ) -> Result<usize, HbirdEncodeError> {
        let mut curr_hop_field_bytes = self.current_hop_field_index * HopFieldLayout::SIZE_BYTES;
        let mut segment_bytes = [0usize; 3];

        for (index, hop) in self.hops.iter().enumerate() {
            let hop_len = if is_flyover(index, hop) {
                // The meta header addresses hop fields by line offset rather than by index, so
                // widening one that sits before the current hop field pushes the current one two
                // lines along. A layout that skips this encodes cleanly and is then processed at
                // the wrong hop by the first router.
                if index < self.current_hop_field_index {
                    curr_hop_field_bytes +=
                        FlyoverHopFieldLayout::SIZE_BYTES - HopFieldLayout::SIZE_BYTES;
                }
                FlyoverHopFieldLayout::SIZE_BYTES
            } else {
                HopFieldLayout::SIZE_BYTES
            };

            segment_bytes[hop.seg_idx] += hop_len;
        }

        meta.set_segment_lengths_bytes(segment_bytes)?;
        meta.set_current_hop_field_bytes(curr_hop_field_bytes)?;

        Ok(meta.encoded_len())
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

    use tinyvec::{ArrayVec, array_vec};

    use super::*;
    use crate::{
        core::{model::Model, view::View},
        dataplane_path::{
            hbird::{
                layout::HbirdPathMetaLayout,
                model::{HbirdHopField, HbirdSegment, HummingbirdPath},
                view::HbirdPathView,
            },
            resolve::PathResolveError,
            standard::{
                layout::InfoFieldLayout,
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

    /// A single segment of `hop_count` hops, with no metadata: the shapes that exercise the meta
    /// header's limits are far longer than any real path, and AS attribution plays no part in
    /// them.
    fn long_segment_path(hop_count: usize) -> ScionPath {
        let hops: Vec<(u16, u16)> = (0..hop_count as u16).map(|i| (i, i + 1)).collect();
        let path = StandardPath {
            current_info_field: 0,
            current_hop_field: 0,
            segments: array_vec!([Segment; 3] => segment(&hops)),
        };

        ScionPath::new(
            ia(0x110),
            ia(0x112),
            ScionDpPathView::Standard(path.try_encode_to_owned_view().expect("encodes")),
            None,
            None,
        )
    }

    /// The encoded header length for `info_fields` segments totalling `hop_bytes` of hop fields.
    fn template_len(info_fields: usize, hop_bytes: usize) -> usize {
        HbirdPathMetaLayout::SIZE_BYTES + info_fields * InfoFieldLayout::SIZE_BYTES + hop_bytes
    }

    /// A four-hop single-segment path already advanced to the hop field at `index`, as it would be
    /// mid-flight.
    fn path_with_current_hop_field(index: u8) -> ScionPath {
        let path = StandardPath {
            current_info_field: 0,
            current_hop_field: index,
            segments: array_vec!([Segment; 3] => segment(&[(0, 1), (2, 3), (4, 5), (6, 0)])),
        };

        ScionPath::new(
            ia(0x110),
            ia(0x112),
            ScionDpPathView::Standard(path.try_encode_to_owned_view().expect("encodes")),
            None,
            None,
        )
    }

    /// The path's overlay, built on demand for the cases that never attach a reservation and so
    /// never trigger the lazy one a `ScionPath` keeps.
    fn overlay_of(path: &ScionPath) -> HbirdOverlay {
        match path.hbird_overlay() {
            Some(overlay) => overlay.clone(),
            None => {
                let ScionDpPathView::Standard(view) = path.dp_path() else {
                    panic!("the path is not standard and cannot carry an overlay");
                };
                HbirdOverlay::new(view, path.src_ia(), path.metadata())
            }
        }
    }

    /// The all-flyover shape as a path model, with every per-packet field left zero exactly as the
    /// template leaves it. The independent encoder the template is checked against.
    fn expected_template_model(overlay: &HbirdOverlay) -> HummingbirdPath {
        let mut segments: Vec<HbirdSegment> = overlay
            .info_fields
            .iter()
            .map(|info_field| {
                HbirdSegment {
                    info_field: *info_field,
                    hop_fields: Default::default(),
                }
            })
            .collect();

        for hop in &overlay.hops {
            let hop_field = if hop.has_reservation() {
                HbirdHopField::Flyover(FlyoverHopField {
                    flags: hop.hop_field.flags,
                    expiration_units: hop.hop_field.expiration_units,
                    cons_ingress: hop.hop_field.cons_ingress,
                    cons_egress: hop.hop_field.cons_egress,
                    // The five per-packet fields, zero in a template.
                    mac: HopFieldMac::zero(),
                    res_id: 0,
                    bw: 0,
                    res_start_offset: 0,
                    res_duration: 0,
                })
            } else {
                HbirdHopField::Standard(hop.hop_field)
            };
            segments[hop.seg_idx].hop_fields.push(hop_field);
        }

        HummingbirdPath {
            current_info_field: overlay.current_info_field,
            current_hop_field: overlay
                .template
                .as_ref()
                .expect("the shape fits")
                .meta
                .current_hop_field,
            segments,
            base_timestamp: 0,
            millis_timestamp: 0,
            counter: 0,
        }
    }

    #[test]
    fn the_template_is_never_stale() {
        // The template is a cache, and the failure mode of a cache is staleness. Asserting the
        // invariant directly means a mutating method added later that forgets to rebuild fails
        // here, rather than silently encoding the path's previous shape.
        let mut path = two_segment_path();
        let check = |path: &ScionPath, after: &str| {
            let overlay = overlay_of(path);
            assert_eq!(
                overlay.template,
                overlay.compute_template(),
                "stale after {after}"
            );
        };

        path.set_tracker(Arc::new(ProbabilisticTracker::new()))
            .expect("standard path");
        check(&path, "set_tracker");

        assert!(
            path.try_add_reservation(reservation(ia(0x111), 2, 3, 600))
                .expect("standard path")
        );
        check(&path, "the first reservation on a hop");

        assert!(
            path.try_add_reservation(reservation(ia(0x111), 2, 3, 1200))
                .expect("standard path")
        );
        check(&path, "a second reservation on the same hop");

        path.add_reservation_at(0, reservation(ia(0x110), 0, 1, 600))
            .expect("standard path");
        check(&path, "add_reservation_at");

        path.remove_expired_reservations(UNIX_EPOCH + Duration::from_secs(START + 100_000));
        check(&path, "remove_expired_reservations");
    }

    #[test]
    fn the_template_marks_exactly_the_hops_that_carry_reservations() {
        let mut path = one_segment_path();
        path.add_reservation_at(0, reservation(ia(0x110), 0, 1, 600))
            .expect("standard path");
        path.add_reservation_at(2, reservation(ia(0x112), 4, 0, 600))
            .expect("standard path");

        let overlay = overlay_of(&path);
        let template = overlay.template.as_ref().expect("the shape fits");

        // Offsets, not indices: the second flyover sits past one flyover and one standard hop.
        let hop_fields = HbirdPathMetaLayout::SIZE_BYTES + InfoFieldLayout::SIZE_BYTES;
        assert_eq!(
            template.flyover_offsets,
            vec![
                hop_fields,
                hop_fields + FlyoverHopFieldLayout::SIZE_BYTES + HopFieldLayout::SIZE_BYTES,
            ]
        );
    }

    #[test]
    fn the_template_encodes_exactly_like_the_path_model() {
        // The template assembles the header field by field; the model encoder walks segments. The
        // two must agree byte for byte, or a packet's validity would depend on which one ran.
        // Exercised across shapes because the layout depends on where the flyovers sit.
        for hops_with_reservations in [vec![], vec![0], vec![3], vec![1, 2], vec![0, 1, 2, 3]] {
            let mut path = two_segment_path();
            for &hop_idx in &hops_with_reservations {
                path.add_reservation_at(hop_idx, reservation(ia(0x110), 0, 1, 600))
                    .expect("standard path");
            }

            let overlay = overlay_of(&path);
            let template = overlay.template.as_ref().expect("the shape fits");
            let expected = expected_template_model(&overlay)
                .try_encode_to_owned_view()
                .expect("encodes");

            assert_eq!(
                template.encoded,
                expected.as_slice(),
                "flyovers at {hops_with_reservations:?}"
            );
        }
    }

    #[test]
    fn a_template_parses_back_as_a_hummingbird_path() {
        let mut path = one_segment_path();
        path.add_reservation_at(1, reservation(ia(0x111), 2, 3, 600))
            .expect("standard path");

        let overlay = overlay_of(&path);
        let template = overlay.template.as_ref().expect("the shape fits");
        let (view, rest): (&HbirdPathView, _) =
            HbirdPathView::try_from_slice(&template.encoded).expect("parses as Hummingbird");

        assert!(rest.is_empty(), "the template is exactly one path header");
        assert_eq!(view.hop_fields().count(), 3);
    }

    #[test]
    fn the_template_leaves_the_timestamp_and_the_counter_zero() {
        // These are written per packet. A template that captured them would leave every packet
        // after the first carrying a stale timestamp — which the flyover MAC covers, so every one
        // of them would be dropped.
        let mut path = one_segment_path();
        path.add_reservation_at(0, reservation(ia(0x110), 0, 1, 600))
            .expect("standard path");

        let overlay = overlay_of(&path);
        let template = overlay.template.as_ref().expect("the shape fits");

        assert_eq!(template.meta.base_timestamp, 0);
        assert_eq!(template.meta.millis_timestamp, 0);
        assert_eq!(template.meta.counter, 0);
        assert!(
            template.encoded[4..HbirdPathMetaLayout::SIZE_BYTES]
                .iter()
                .all(|&byte| byte == 0),
            "the timestamp and counter words are untouched"
        );
    }

    #[test]
    fn a_flyover_before_the_current_hop_field_advances_its_offset() {
        // Hummingbird addresses the current hop field by 4-byte line offset, not by index.
        // Widening an earlier hop from 12 to 20 bytes moves it two lines along. A layout that
        // skips this adjustment encodes cleanly and is then processed at the wrong hop by the
        // first router — the most expensive class of bug here to diagnose from the outside.
        let mut path = path_with_current_hop_field(2);
        path.add_reservation_at(0, reservation(ia(0x110), 0, 1, 600))
            .expect("standard path");

        let overlay = overlay_of(&path);
        let template = overlay.template.as_ref().expect("the shape fits");
        let (view, _): (&HbirdPathView, _) =
            HbirdPathView::try_from_slice(&template.encoded).expect("parses as Hummingbird");
        let model = HummingbirdPath::from_view(view);

        assert_eq!(
            model.current_hop_field_index(),
            2,
            "still the third hop field"
        );
        assert_eq!(
            template.meta.current_hop_field_bytes(),
            FlyoverHopFieldLayout::SIZE_BYTES + HopFieldLayout::SIZE_BYTES,
            "but two lines further along than the 24 bytes it started at"
        );
    }

    #[test]
    fn the_current_hop_field_offset_counts_only_flyovers_in_front_of_it() {
        // Exhaustive over which of four hops are widened, because the adjustment is a running
        // total and a formula that drifts still gets the one-flyover cases right.
        let overlay = overlay_of(&path_with_current_hop_field(3));

        for shape in 0u8..16 {
            let mut meta = HbirdMetaFields::default();
            overlay
                .apply_header_layout(&mut meta, |flat_idx, _| shape & (1 << flat_idx) != 0)
                .expect("the shape fits");

            let flyovers_before = (0..3).filter(|bit| shape & (1 << bit) != 0).count();
            assert_eq!(
                meta.current_hop_field_bytes(),
                3 * HopFieldLayout::SIZE_BYTES
                    + flyovers_before
                        * (FlyoverHopFieldLayout::SIZE_BYTES - HopFieldLayout::SIZE_BYTES),
                "shape {shape:04b}"
            );
        }
    }

    #[test]
    fn a_shape_that_overflows_a_segment_has_no_template() {
        // Seven bits of line count cap a segment at 508 bytes. Twenty-seven flyovers reach 540,
        // so the all-flyover shape does not fit — which is not a broken path, only one that must
        // be laid out with fewer flyovers.
        let mut path = long_segment_path(27);
        for hop_idx in 0..27 {
            path.add_reservation_at(hop_idx, reservation(ia(0x110), 0, 1, 600))
                .expect("standard path");
        }

        assert!(overlay_of(&path).template.is_none());

        // Twenty-three of them fit, at exactly the limit.
        let mut meta = HbirdMetaFields::default();
        let length = overlay_of(&path)
            .apply_header_layout(&mut meta, |flat_idx, _| flat_idx < 23)
            .expect("the shape fits");
        assert_eq!(meta.segment_lengths[0] as usize * 4, 508);
        assert_eq!(length, template_len(1, 508));
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

    // ==============================================================================================
    // Shapes captured from a running SCION topology by
    // `local-tests/src/bin/hbird_template_capture`, run from `1-ff00:0:112`: 236 fetched paths,
    // 25 distinct shapes, longest 11 hops, largest segment 5 hops.
    //
    // The template depends on nothing but the path's shape — how many hops each segment holds,
    // which of them carry a reservation, and where the current hop field sits — so the shapes
    // below stand in for all 236 paths. The four full paths that follow add the AS attribution and
    // segment flags the shapes drop, so the same invariants are also checked on paths built the
    // way a real one is.

    /// Hops per segment of every distinct shape the live topology produced.
    const LIVE_SHAPES: &[&[usize]] = &[
        &[2],
        &[2, 1],
        &[2, 2],
        &[2, 3],
        &[2, 3, 2],
        &[2, 3, 3],
        &[2, 4],
        &[2, 4, 2],
        &[2, 4, 3],
        &[2, 5],
        &[2, 5, 2],
        &[2, 5, 3],
        &[3],
        &[3, 2],
        &[3, 2, 2],
        &[3, 2, 3],
        &[3, 3],
        &[3, 3, 2],
        &[3, 3, 3],
        &[3, 4],
        &[3, 4, 2],
        &[3, 4, 3],
        &[3, 5],
        &[3, 5, 2],
        &[3, 5, 3],
    ];

    /// One segment of a captured path: `(cons_dir, peering, hops)`, each hop
    /// `(cons_ingress, cons_egress)`.
    type LiveSegment = (bool, bool, &'static [(u16, u16)]);

    /// One path captured from the live topology, reduced to everything the overlay reads off it.
    struct LivePath {
        /// The path's interface sequence, to name it in a failure message.
        name: &'static str,
        /// Source AS, as the raw ISD-AS number.
        src: u64,
        /// Destination AS, as the raw ISD-AS number.
        dst: u64,
        /// Per segment: `(cons_dir, peering, hops)`, each hop `(cons_ingress, cons_egress)`.
        segments: &'static [LiveSegment],
        /// The daemon's metadata interface list, as `(ISD-AS, interface id)`.
        interfaces: &'static [(u64, u16)],
    }

    impl LivePath {
        /// Total hop fields across every segment.
        fn hop_count(&self) -> usize {
            self.segments.iter().map(|(_, _, hops)| hops.len()).sum()
        }

        /// Hops per segment.
        fn shape(&self) -> Vec<usize> {
            self.segments
                .iter()
                .map(|(_, _, hops)| hops.len())
                .collect()
        }

        /// The path as the SDK would hold it, advanced to the hop field at `hop_index`.
        ///
        /// Expirations and MACs are stand-ins: neither the layout nor the attribution reads them.
        fn to_path(&self, hop_index: usize) -> ScionPath {
            let segments: ArrayVec<[Segment; 3]> = self
                .segments
                .iter()
                .map(|&(cons_dir, peering, hops)| {
                    let mut flags = InfoFieldFlags::empty();
                    if cons_dir {
                        flags |= InfoFieldFlags::CONS_DIR;
                    }
                    if peering {
                        flags |= InfoFieldFlags::PEERING;
                    }
                    Segment {
                        info_field: InfoField {
                            flags,
                            segment_id: 7,
                            timestamp: START as u32,
                        },
                        hop_fields: hops.iter().map(|&(i, e)| hop(i, e)).collect(),
                    }
                })
                .collect();

            let path = StandardPath {
                current_info_field: segment_of(&self.shape(), hop_index),
                current_hop_field: hop_index as u8,
                segments,
            };
            let interfaces: Vec<(IsdAsn, u16)> = self
                .interfaces
                .iter()
                .map(|&(isd_as, id)| (IsdAsn(isd_as), id))
                .collect();

            ScionPath::new(
                IsdAsn(self.src),
                IsdAsn(self.dst),
                ScionDpPathView::Standard(path.try_encode_to_owned_view().expect("encodes")),
                Some(metadata(&interfaces)),
                None,
            )
        }
    }

    /// `1-ff00:0:112` -> `1-ff00:0:111`, one segment: `1-ff00:0:112 494>103 1-ff00:0:111`.
    const SINGLE_SEGMENT: LivePath = LivePath {
        name: "1-ff00:0:112 494>103 1-ff00:0:111",
        src: 0x0001_ff00_0000_0112,
        dst: 0x0001_ff00_0000_0111,
        segments: &[(false, false, &[(494, 0), (104, 103)])],
        interfaces: &[(0x0001_ff00_0000_0112, 494), (0x0001_ff00_0000_0111, 103)],
    };

    /// `1-ff00:0:112` -> `1-ff00:0:110`, an ordinary crossover in `1-ff00:0:130`:
    /// `1-ff00:0:112 495>113 1-ff00:0:130 104>2 1-ff00:0:110`.
    const ORDINARY_CROSSOVER: LivePath = LivePath {
        name: "1-ff00:0:112 495>113 1-ff00:0:130 104>2 1-ff00:0:110",
        src: 0x0001_ff00_0000_0112,
        dst: 0x0001_ff00_0000_0110,
        segments: &[
            (false, false, &[(495, 0), (0, 113)]),
            (false, false, &[(104, 0), (0, 2)]),
        ],
        interfaces: &[
            (0x0001_ff00_0000_0112, 495),
            (0x0001_ff00_0000_0130, 113),
            (0x0001_ff00_0000_0130, 104),
            (0x0001_ff00_0000_0110, 2),
        ],
    };

    /// `1-ff00:0:112` -> `1-ff00:0:121` across the peering link `1-ff00:0:111` #100 = #4
    /// `1-ff00:0:121`: `1-ff00:0:112 494>103 1-ff00:0:111 100>4 1-ff00:0:121`. Both info fields
    /// carry the peering flag and the second segment holds a single hop.
    const PEERING_CROSSOVER: LivePath = LivePath {
        name: "1-ff00:0:112 494>103 1-ff00:0:111 100>4 1-ff00:0:121",
        src: 0x0001_ff00_0000_0112,
        dst: 0x0001_ff00_0000_0121,
        segments: &[
            (false, true, &[(494, 0), (100, 103)]),
            (true, true, &[(4, 0)]),
        ],
        interfaces: &[
            (0x0001_ff00_0000_0112, 494),
            (0x0001_ff00_0000_0111, 103),
            (0x0001_ff00_0000_0111, 100),
            (0x0001_ff00_0000_0121, 4),
        ],
    };

    /// The longest path the local AS can fetch: eleven hops over three segments, crossing into
    /// ISD 2. `1-ff00:0:112 494>103 1-ff00:0:111 105>112 1-ff00:0:130 105>1 1-ff00:0:120 6>1
    /// 1-ff00:0:110 3>453 2-ff00:0:210 450>503 2-ff00:0:220 500>2 2-ff00:0:221 1>302
    /// 2-ff00:0:222`.
    const LONGEST: LivePath = LivePath {
        name: "1-ff00:0:112 .. 2-ff00:0:222 (11 hops, 3 segments)",
        src: 0x0001_ff00_0000_0112,
        dst: 0x0002_ff00_0000_0222,
        segments: &[
            (false, false, &[(494, 0), (105, 103), (0, 112)]),
            (
                false,
                false,
                &[(105, 0), (6, 1), (3, 1), (450, 453), (0, 503)],
            ),
            (true, false, &[(0, 500), (2, 1), (302, 0)]),
        ],
        interfaces: &[
            (0x0001_ff00_0000_0112, 494),
            (0x0001_ff00_0000_0111, 103),
            (0x0001_ff00_0000_0111, 105),
            (0x0001_ff00_0000_0130, 112),
            (0x0001_ff00_0000_0130, 105),
            (0x0001_ff00_0000_0120, 1),
            (0x0001_ff00_0000_0120, 6),
            (0x0001_ff00_0000_0110, 1),
            (0x0001_ff00_0000_0110, 3),
            (0x0002_ff00_0000_0210, 453),
            (0x0002_ff00_0000_0210, 450),
            (0x0002_ff00_0000_0220, 503),
            (0x0002_ff00_0000_0220, 500),
            (0x0002_ff00_0000_0221, 2),
            (0x0002_ff00_0000_0221, 1),
            (0x0002_ff00_0000_0222, 302),
        ],
    };

    /// Every captured path, for the checks that want all of them.
    const LIVE_PATHS: &[&LivePath] = &[
        &SINGLE_SEGMENT,
        &ORDINARY_CROSSOVER,
        &PEERING_CROSSOVER,
        &LONGEST,
    ];

    /// The segment holding the hop field at `hop_index`, for a path of the given shape.
    fn segment_of(shape: &[usize], hop_index: usize) -> u8 {
        let mut remaining = hop_index;
        for (index, &hops) in shape.iter().enumerate() {
            if remaining < hops {
                return index as u8;
            }
            remaining -= hops;
        }
        0
    }

    /// A path of the given shape — `shape[i]` hops in segment `i` — advanced to `hop_index`.
    ///
    /// No metadata: a shape says nothing about AS attribution, and none of the template's
    /// invariants depend on it.
    fn shape_path(shape: &[usize], hop_index: usize) -> ScionPath {
        let mut next_interface = 1u16;
        let segments: ArrayVec<[Segment; 3]> = shape
            .iter()
            .map(|&hops| {
                let hop_fields = (0..hops)
                    .map(|_| {
                        let hop_field = hop(next_interface, next_interface + 1);
                        next_interface += 2;
                        hop_field
                    })
                    .collect();
                Segment {
                    info_field: info(),
                    hop_fields,
                }
            })
            .collect();

        let path = StandardPath {
            current_info_field: segment_of(shape, hop_index),
            current_hop_field: hop_index as u8,
            segments,
        };

        ScionPath::new(
            ia(0x110),
            ia(0x112),
            ScionDpPathView::Standard(path.try_encode_to_owned_view().expect("encodes")),
            None,
            None,
        )
    }

    /// `path` with a reservation on every hop whose bit is set in `flyover_mask`.
    fn with_flyovers(path: &ScionPath, hop_count: usize, flyover_mask: u32) -> ScionPath {
        let mut path = path.clone();
        for hop_idx in 0..hop_count {
            if flyover_mask & (1 << hop_idx) != 0 {
                path.add_reservation_at(hop_idx, reservation(ia(0x110), 0, 1, 600))
                    .expect("standard path");
            }
        }
        path
    }

    /// Asserts every template invariant on `path`, against values derived from the overlay's own
    /// hops rather than from the layout code the template used.
    ///
    /// `label` names the case, since these run in nested loops.
    fn assert_template_is_sound(path: &ScionPath, label: &str) {
        let overlay = overlay_of(path);
        let hop_count = overlay.hops.len();
        let template = overlay
            .template
            .as_ref()
            .unwrap_or_else(|| panic!("{label}: no template for a shape that must fit"));

        // The header parses back as a Hummingbird path, in full and with nothing over.
        let (view, rest): (&HbirdPathView, _) = HbirdPathView::try_from_slice(&template.encoded)
            .unwrap_or_else(|err| panic!("{label}: the template does not parse: {err:?}"));
        assert!(rest.is_empty(), "{label}: trailing bytes after the header");
        assert_eq!(
            view.hop_fields().count(),
            hop_count,
            "{label}: hop field count changed"
        );

        // Every flyover offset names a hop the parsed view agrees is a flyover, and they are
        // exactly the hops carrying a reservation.
        let expected_flyovers: Vec<usize> = overlay
            .hops
            .iter()
            .enumerate()
            .filter(|(_, hop)| hop.has_reservation())
            .map(|(index, _)| index)
            .collect();
        assert_eq!(
            template.flyover_offsets.len(),
            expected_flyovers.len(),
            "{label}: wrong number of flyover offsets"
        );

        let hop_fields_at = HbirdPathMetaLayout::SIZE_BYTES
            + overlay.info_fields.len() * InfoFieldLayout::SIZE_BYTES;
        for (&offset, &index) in template.flyover_offsets.iter().zip(&expected_flyovers) {
            let relative = offset - hop_fields_at;
            assert_eq!(
                view.is_flyover_checked(relative),
                Some(true),
                "{label}: byte {offset} is not the start of a flyover"
            );
            assert_eq!(
                view.hop_field_index(relative),
                Some(index),
                "{label}: the flyover at byte {offset} is not hop {index}"
            );
        }

        // The current hop field still names the hop it named on the standard path, even though
        // widening earlier hops moved its byte offset.
        assert_eq!(
            HummingbirdPath::from_view(view).current_hop_field_index(),
            overlay.current_hop_field_index,
            "{label}: the current hop field moved to another hop"
        );

        // Segment lengths account for exactly the hops of their own segment.
        let mut segment_bytes = [0usize; 3];
        for hop in &overlay.hops {
            segment_bytes[hop.seg_idx] += if hop.has_reservation() {
                FlyoverHopFieldLayout::SIZE_BYTES
            } else {
                HopFieldLayout::SIZE_BYTES
            };
        }
        for (index, &bytes) in segment_bytes.iter().enumerate() {
            assert_eq!(
                template.meta.segment_lengths[index] as usize * 4,
                bytes,
                "{label}: segment {index} length"
            );
        }
        assert_eq!(
            template.encoded.len(),
            hop_fields_at + segment_bytes.iter().sum::<usize>(),
            "{label}: the header length does not match the segment lengths"
        );
    }

    #[test]
    fn every_live_shape_has_an_all_flyover_template_at_every_current_hop_field() {
        // A missing template means the all-flyover shape overflowed the meta header. Twenty-five
        // shapes, none past 11 hops or 5 hops in a segment, so none of them comes close — but the
        // limit is on *bytes*, and a layout bug that miscounted them would show up here first.
        for shape in LIVE_SHAPES {
            let hop_count: usize = shape.iter().sum();
            for hop_index in 0..hop_count {
                let path = with_flyovers(
                    &shape_path(shape, hop_index),
                    hop_count,
                    (1 << hop_count) - 1,
                );
                assert_template_is_sound(&path, &format!("shape {shape:?} at hop {hop_index}"));
            }
        }
    }

    #[test]
    fn a_live_path_keeps_its_current_hop_field_through_every_flyover_shape() {
        // The check the fetched paths cannot make on their own: every one of them starts at hop 0,
        // where no earlier hop can widen and push the current one along. Walking the current hop
        // field over the whole path, against every subset of hops that could carry a reservation,
        // is what puts flyovers *in front* of it.
        for live in LIVE_PATHS {
            let hop_count = live.hop_count();
            for hop_index in 0..hop_count {
                let standard = live.to_path(hop_index);
                for mask in 0..1u32 << hop_count {
                    let path = with_flyovers(&standard, hop_count, mask);
                    assert_template_is_sound(
                        &path,
                        &format!("{} at hop {hop_index}, flyovers {mask:b}", live.name),
                    );
                }
            }
        }
    }

    #[test]
    fn a_live_paths_hops_are_attributed_to_the_ases_its_interface_list_names() {
        // The fixtures are only worth what their attribution is worth: if these were transcribed
        // wrong, the checks above would still pass while testing a path that does not exist. The
        // endpoints and the crossover rule are what the live binary verified against `gen/`.
        for live in LIVE_PATHS {
            let overlay = overlay_of(&live.to_path(0));
            let ases: Vec<Option<IsdAsn>> = overlay.hops.iter().map(HbirdHop::isd_asn).collect();

            assert_eq!(
                ases.first().copied().flatten(),
                Some(IsdAsn(live.src)),
                "{}: the first hop is the source AS",
                live.name
            );
            assert_eq!(
                ases.last().copied().flatten(),
                Some(IsdAsn(live.dst)),
                "{}: the last hop is the destination AS",
                live.name
            );
            assert!(
                ases.iter().all(Option::is_some),
                "{}: every hop is attributed",
                live.name
            );
        }
    }
}
