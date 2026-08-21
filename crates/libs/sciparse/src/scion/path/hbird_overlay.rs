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

use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    core::{
        convert::FromView,
        encode::{InvalidStructureError, WireEncode},
    },
    dataplane_path::{
        hbird::{
            layout::FlyoverHopFieldLayout,
            model::{FlyoverHopField, HbirdEncodeError, HbirdHopField, HbirdMetaFields},
            types::HbirdHopFieldFlags,
        },
        resolve::{PacketFrame, PathResolveError},
        standard::{
            layout::HopFieldLayout,
            model::{HopField, InfoField},
            types::HopFieldMac,
            view::StandardPathView,
        },
    },
    hummingbird::{
        Reservation,
        tracker::{PacketSession, ReservationTracker, ReservationTrackerError, Selected},
    },
    identifier::isd_asn::IsdAsn,
    path::metadata::PathMetadata,
};

/// The 22-bit duplicate-detection counter wraps here, as it does on the wire.
const COUNTER_MODULUS: u32 = 1 << 22;

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

    /// Whether this hop can carry a flyover at all.
    ///
    /// False for the first hop field after an ordinary crossover. An AS terminating one segment
    /// and starting the next owns both hop fields, but the crossover carries a *single*
    /// reservation, and it lives on the earlier one — whose egress was resolved to this hop's at
    /// construction for exactly that reason. A border router de-aggregates that earlier hop field,
    /// steps to this one and verifies its plain SCION MAC without de-aggregating again, so a
    /// flyover here is rejected as a MAC failure.
    pub(crate) reservable: bool,

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

    /// Whether this hop can carry a flyover.
    ///
    /// False only for the first hop field after an ordinary crossover, whose reservation belongs
    /// to the preceding hop instead.
    pub fn is_reservable(&self) -> bool {
        self.reservable
    }
}

/// Hummingbird overlay: attached reservations and the reservation tracker that chooses between
/// them.
///
/// Always an overlay on a *standard* path. A path parsed from a received Hummingbird packet never
/// has one, because its bytes are already fixed and it is not something that gets sent onward
/// without being reversed first.
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

    /// Duplicate-detection counter, stamped into the meta header and covered by every flyover MAC.
    ///
    /// It is what separates two packets a router would otherwise see as identical: same path, same
    /// length, same millisecond. Atomic because resolution takes `&self`, so one path may be sent
    /// on from several threads at once.
    pub(crate) counter: AtomicU32,

    /// The encoding of the all-flyover shape, rebuilt whenever the set of hops carrying
    /// reservations changes.
    ///
    /// `None` when that shape does not fit the meta header, whose segment lengths are 7-bit line
    /// counts (127 lines, 508 bytes) and whose current hop field is an 8-bit one (255 lines, 1020
    /// bytes). Both need many flyovers on a long path, and neither rules the path out: resolution
    /// lays out the shape it actually selected, which is never wider.
    pub(crate) template: Option<Template>,
}

impl Clone for HbirdOverlay {
    /// The clone continues the original's counter rather than restarting it, so a path that is
    /// cloned and sent on does not immediately re-emit values the original already used.
    fn clone(&self) -> Self {
        Self {
            hops: self.hops.clone(),
            info_fields: self.info_fields.clone(),
            current_info_field: self.current_info_field,
            current_hop_field_index: self.current_hop_field_index,
            tracker: self.tracker.clone(),
            counter: AtomicU32::new(self.counter.load(Ordering::Relaxed)),
            template: self.template.clone(),
        }
    }
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
            .field("counter", &self.counter.load(Ordering::Relaxed))
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
                    reservable: true,
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
                // The pair those two hop fields share is reserved once, here.
                hops[index + 1].reservable = false;
            }
        }

        let mut overlay = Self {
            hops,
            info_fields,
            current_info_field: view.curr_info_field_idx(),
            current_hop_field_index: view.curr_hop_field_idx() as usize,
            tracker: None,
            counter: AtomicU32::new(0),
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
    /// segment, because that hop's egress was resolved to the next segment's at construction, and
    /// the hop after it is skipped as unreservable. A peering crossover is not a segment change for
    /// this purpose: its two hop fields sit in different ASes and each matches on its own
    /// interfaces.
    pub(crate) fn try_add_reservation(&mut self, reservation: Reservation) -> bool {
        let info = reservation.info().clone();
        let mut matched = false;

        for hop in self.hops.iter_mut().filter(|hop| hop.reservable) {
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
    /// Fails if the index names no hop, or names one that cannot carry a flyover.
    pub(crate) fn add_reservation_at(
        &mut self,
        hop_idx: usize,
        reservation: Reservation,
    ) -> Result<(), PathResolveError> {
        let hop_count = self.hops.len();
        let hop = self
            .hops
            .get_mut(hop_idx)
            .ok_or(PathResolveError::HopIndexOutOfRange {
                index: hop_idx,
                hop_count,
            })?;

        if !hop.reservable {
            return Err(PathResolveError::HopCannotCarryReservation { index: hop_idx });
        }

        hop.reservations.push(reservation);
        self.rebuild_template();
        Ok(())
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

    /// Fixes this path's shape, timing and MACs for one packet.
    ///
    /// **Selection and commit are one critical section.** A tracker that opens a
    /// [`PacketSession`] holds its lock across both, so two threads cannot both pass a bandwidth
    /// check before either deducts. The consequence is that a packet resolved and then dropped is
    /// still accounted for: over-accounting only causes an early demotion, where under-accounting
    /// would let the path over-send.
    ///
    /// The order of what follows is fixed by a circularity and must not be rearranged. Selection
    /// is offered `max_pkt_len`, an upper bound, because the exact length depends on which hops
    /// become flyovers — which is what selection decides. Only once the layout is applied to the
    /// actual selection is the real length known, and it is never larger than the bound, so the
    /// accounting stays conservative.
    /// Returns `None` when no hop ended up with a flyover. Such a packet has nothing Hummingbird
    /// to say, and saying it anyway would cost eight bytes of meta header and make every router on
    /// the path parse a wider header to find no reservations — so the caller sends the underlying
    /// standard path instead.
    pub(crate) fn resolve(
        &self,
        frame: PacketFrame,
    ) -> Result<Option<ResolvedHbirdPath<'_>>, PathResolveError> {
        let max_pkt_len = frame.exterior_len as usize + self.max_encoded_len()?;
        let mut session = self
            .tracker
            .as_ref()
            .and_then(|t| t.begin_packet(frame.now));

        let mut decisions: Vec<Option<HopDecision<'_>>> = Vec::with_capacity(self.hops.len());
        for hop in &self.hops {
            decisions.push(self.select(session.as_deref_mut(), hop, frame.now, max_pkt_len)?);
        }

        if decisions.iter().all(Option::is_none) {
            return Ok(None);
        }

        // A hop going out as a standard hop field must not set the bit Hummingbird reads as the
        // flyover discriminator. Checked here rather than at encode time so the failure is a typed
        // resolution error, before any buffer has been sized for it.
        for (index, hop) in self.hops.iter().enumerate() {
            if decisions[index].is_none()
                && hop.hop_field.flags.bits() & HbirdHopFieldFlags::FLYOVER.bits() != 0
            {
                return Err(HbirdEncodeError::FlyoverBitInStandardHopField { hop: index }.into());
            }
        }

        let mut meta = HbirdMetaFields {
            current_info_field: self.current_info_field,
            ..Default::default()
        };
        let encoded_len =
            self.apply_header_layout(&mut meta, |index, _| decisions[index].is_some())?;

        let packet_len = frame.exterior_len as usize + encoded_len;
        if packet_len > u16::MAX as usize {
            return Err(PathResolveError::PacketTooLong(packet_len));
        }
        self.stamp(&mut meta, frame.now);

        // Every MAC is minted before any reservation is charged, so a packet that cannot be
        // encoded costs nothing.
        for (hop, decision) in self.hops.iter().zip(&mut decisions) {
            if let Some(decision) = decision {
                let (mac, res_start_offset) = hop.hop_field.aggregated_flyover_mac(
                    meta,
                    decision.selected.reservation,
                    frame.dst_ia,
                    packet_len as u16,
                )?;
                decision.mac = mac;
                decision.res_start_offset = res_start_offset;
            }
        }

        for decision in decisions.iter().flatten() {
            match session.as_deref_mut() {
                Some(session) => session.commit(&decision.selected, packet_len),
                None => {
                    if let Some(tracker) = self.tracker.as_ref() {
                        tracker.commit(&decision.selected, packet_len);
                    }
                }
            }
        }

        Ok(Some(ResolvedHbirdPath {
            overlay: self,
            decisions,
            meta,
            encoded_len,
        }))
    }

    /// Chooses the reservation `hop` uses for this packet, if any.
    ///
    /// The MAC fields are filled in later, once the packet's exact length is known.
    fn select<'a>(
        &'a self,
        session: Option<&mut (dyn PacketSession + '_)>,
        hop: &'a HbirdHop,
        now: SystemTime,
        max_pkt_len: usize,
    ) -> Result<Option<HopDecision<'a>>, PathResolveError> {
        let selected = match (session, self.tracker.as_ref()) {
            (Some(session), _) => session.select(&hop.reservations, now, max_pkt_len)?,
            (None, Some(tracker)) => tracker.select(&hop.reservations, now, max_pkt_len)?,
            // With no tracker there is no policy to consult, only validity: the first reservation
            // still inside its window carries the hop, and none being valid is the same failure a
            // tracker would report.
            (None, None) => {
                match hop.reservations.first() {
                    None => None,
                    Some(_) => {
                        Some(Selected::untracked(
                            hop.reservations
                                .iter()
                                .find(|reservation| reservation.is_valid_at(now))
                                .ok_or(ReservationTrackerError::ReservationExpired)?,
                        ))
                    }
                }
            }
        };

        Ok(selected.map(|selected| {
            HopDecision {
                selected,
                mac: HopFieldMac::zero(),
                res_start_offset: 0,
            }
        }))
    }

    /// Writes this packet's send time and its duplicate-detection counter into `meta`.
    fn stamp(&self, meta: &mut HbirdMetaFields, now: SystemTime) {
        let since_epoch = now.duration_since(UNIX_EPOCH).unwrap_or_default();

        meta.base_timestamp = since_epoch.as_secs() as u32;
        meta.millis_timestamp = since_epoch.subsec_millis() as u16;
        meta.counter = self.counter.fetch_add(1, Ordering::Relaxed) % COUNTER_MODULUS;
    }

    /// The longest this path's header can encode to: every hop a flyover.
    ///
    /// Selection is offered this bound rather than the exact length, which is not knowable until
    /// selection has answered. It is never smaller than what the packet turns out to be.
    fn max_encoded_len(&self) -> Result<usize, HbirdEncodeError> {
        let mut meta = HbirdMetaFields::default();
        self.apply_header_layout(&mut meta, |_, _| true)
    }

    /// Whether any hop carries a reservation.
    ///
    /// `false` means every send over this path is a plain copy of the standard path's bytes: no
    /// tracker session is opened and no MAC is computed.
    pub(crate) fn has_reservations(&self) -> bool {
        self.hops.iter().any(HbirdHop::has_reservation)
    }
}

/// One hop's outcome for one packet: which reservation carries it, and the two values that
/// depend on both the reservation and the packet.
#[derive(Debug, Clone, Copy)]
struct HopDecision<'a> {
    /// The reservation this packet uses for the hop, and the tracker's handle for it.
    selected: Selected<'a>,
    /// The standard MAC aggregated with the flyover MAC, ready to write.
    mac: HopFieldMac,
    /// Whole seconds from the reservation's start to this packet's base timestamp.
    res_start_offset: u16,
}

/// A Hummingbird path whose shape — and therefore length — is fixed for one packet.
///
/// Holds the decisions resolution took rather than the bytes they imply, so encoding writes
/// straight into the packet's own buffer and the template copy lands where the bytes belong
/// instead of in an intermediate allocation.
///
/// Borrowing the overlay is what stops one resolution being reused for a second packet: it cannot
/// outlive the path it came from, and the path cannot be mutated while it is alive.
#[derive(Debug, Clone)]
pub struct ResolvedHbirdPath<'a> {
    overlay: &'a HbirdOverlay,

    /// Per hop in encode order, `None` for a hop encoded as a plain standard hop field.
    decisions: Vec<Option<HopDecision<'a>>>,

    /// This packet's meta header, with layout and timing fields both final.
    meta: HbirdMetaFields,

    /// The encoded length of this path, frozen here so [`WireEncode::required_size`] cannot
    /// answer differently on two calls.
    encoded_len: usize,
}

impl ResolvedHbirdPath<'_> {
    /// The encoded length of this path, fixed when it was resolved.
    #[inline]
    pub fn encoded_len(&self) -> usize {
        self.encoded_len
    }

    /// Whether the template describes this packet's shape.
    ///
    /// The template encodes the shape in which *every* hop carrying a reservation is a flyover, so
    /// it applies exactly when selection produced one for each of them. A hop can only be selected
    /// if it has reservations, so counting decisions is enough: a hop that had reservations but
    /// was declined leaves the count short, and the layout differs from that hop onward.
    fn template(&self) -> Option<&Template> {
        let template = self.overlay.template.as_ref()?;
        let selected = self.decisions.iter().filter(|d| d.is_some()).count();
        (selected == template.flyover_offsets.len()).then_some(template)
    }

    /// Always `Ok`: the layout, the packet length, every reservation and every hop field were
    /// settled during resolution, which is the whole reason resolution exists.
    pub(crate) fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        Ok(())
    }

    /// Writes this packet's path header into `buf`.
    ///
    /// # Safety
    ///
    /// `buf` must be at least [`encoded_len`](Self::encoded_len) bytes long.
    pub(crate) unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        // SAFETY: the caller guarantees the buffer is long enough for the whole header, and every
        // write below stays inside the length the same layout produced.
        unsafe {
            match self.template() {
                Some(template) => self.encode_from_template(template, buf),
                None => self.encode_from_parts(buf),
            }
        }
        self.encoded_len
    }

    /// Copies the precomputed header and overwrites only what this packet changes.
    ///
    /// # Safety
    ///
    /// As [`encode_unchecked`](Self::encode_unchecked).
    unsafe fn encode_from_template(&self, template: &Template, buf: &mut [u8]) {
        debug_assert_eq!(template.encoded.len(), self.encoded_len);

        // SAFETY: the caller guarantees the buffer is long enough.
        let buf = unsafe { buf.get_unchecked_mut(..self.encoded_len) };
        buf.copy_from_slice(&template.encoded);

        // The template's meta header carries the layout but no timing; this one carries both.
        // SAFETY: the meta header is the first field of a header the buffer already holds.
        unsafe { self.meta.encode_unchecked(buf) };

        let decisions = self.decisions.iter().flatten();
        for (&offset, decision) in template.flyover_offsets.iter().zip(decisions) {
            let field = &mut buf[offset..offset + FlyoverHopFieldLayout::SIZE_BYTES];
            patch_flyover(field.try_into().expect("one flyover hop field"), decision);
        }
    }

    /// Builds the header field by field, for a packet whose shape the template does not describe.
    ///
    /// # Safety
    ///
    /// As [`encode_unchecked`](Self::encode_unchecked).
    unsafe fn encode_from_parts(&self, buf: &mut [u8]) {
        // SAFETY: every offset below comes from the same layout that produced `encoded_len`, which
        // the caller guarantees the buffer covers.
        unsafe {
            let mut at = self.meta.encode_unchecked(buf);
            for info_field in &self.overlay.info_fields {
                at += info_field.encode_unchecked(buf.get_unchecked_mut(at..));
            }

            for (hop, decision) in self.overlay.hops.iter().zip(&self.decisions) {
                match decision {
                    Some(decision) => {
                        let field: &mut [u8; FlyoverHopFieldLayout::SIZE_BYTES] = buf
                            .get_unchecked_mut(at..at + FlyoverHopFieldLayout::SIZE_BYTES)
                            .try_into()
                            .expect("one flyover hop field");
                        FlyoverHopField::encode_template(&hop.hop_field, &mut *field);
                        patch_flyover(field, decision);
                        at += FlyoverHopFieldLayout::SIZE_BYTES;
                    }
                    None => at += hop.hop_field.encode_unchecked(buf.get_unchecked_mut(at..)),
                }
            }

            debug_assert_eq!(at, self.encoded_len, "the layout and the encoder disagree");
        }
    }
}

/// Writes the five fields of a flyover hop field that depend on the packet or on which reservation
/// was chosen for it, over a buffer that already holds the rest.
fn patch_flyover(field: &mut [u8; FlyoverHopFieldLayout::SIZE_BYTES], decision: &HopDecision<'_>) {
    let info = decision.selected.reservation.info();
    FlyoverHopField::patch_per_packet_fields(
        field,
        &decision.mac,
        info.res_id,
        info.bandwidth.encode(),
        decision.res_start_offset,
        info.duration,
    );
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
            resolve::{PathResolveError, ResolvedPath},
            standard::{
                layout::InfoFieldLayout,
                model::{InfoField, Segment, StandardPath},
                types::{HopFieldFlags, HopFieldMac, InfoFieldFlags},
            },
            types::PathType,
            view::{ScionDpPathView, ScionDpPathViewExt},
        },
        header::model::PacketPath,
        hummingbird::{
            Bandwidth, Reservation, ReservationInfo, probabilistic_tracker::ProbabilisticTracker,
            token_bucket_tracker::TokenBucketTracker, tracker::Lenient,
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

    /// Attaches a reservation to each of `hop_indices` that can carry one, and returns the indices
    /// that took it.
    ///
    /// The first hop field after an ordinary crossover refuses, so a test that wants "a
    /// reservation on these hops" has to ask the path which of them that means.
    fn reserve_hops(path: &mut ScionPath, hop_indices: &[usize]) -> Vec<usize> {
        let mut attached = Vec::new();
        for &hop_idx in hop_indices {
            match path.add_reservation_at(hop_idx, reservation(ia(0x110), 0, 1, 600)) {
                Ok(()) => attached.push(hop_idx),
                Err(PathResolveError::HopCannotCarryReservation { .. }) => {}
                Err(err) => panic!("unexpected refusal for hop {hop_idx}: {err}"),
            }
        }
        attached
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
            reserve_hops(&mut path, &hops_with_reservations);

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

    // --- Task 20: per-packet resolution ---------------------------------------------------------

    /// A tracker that keeps no state but records how often a packet session was opened, so the
    /// "no reservations costs nothing" guarantee is observable.
    #[derive(Debug, Default)]
    struct SessionCounter {
        sessions: AtomicU32,
    }

    impl SessionCounter {
        fn sessions_opened(&self) -> u32 {
            self.sessions.load(Ordering::Relaxed)
        }
    }

    impl ReservationTracker for SessionCounter {
        fn begin_packet(&self, _now: SystemTime) -> Option<Box<dyn PacketSession + '_>> {
            self.sessions.fetch_add(1, Ordering::Relaxed);
            None
        }

        fn select<'a>(
            &self,
            reservations: &'a [Reservation],
            _now: SystemTime,
            _max_pkt_len: usize,
        ) -> Result<Option<Selected<'a>>, ReservationTrackerError> {
            Ok(reservations.first().map(Selected::untracked))
        }

        fn commit(&self, _selected: &Selected<'_>, _pkt_len: usize) {}
    }

    fn at(offset: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(START + offset)
    }

    fn frame_at(dst_ia: IsdAsn, exterior_len: u16, now: SystemTime) -> PacketFrame {
        PacketFrame {
            dst_ia,
            exterior_len,
            now,
        }
    }

    fn test_frame() -> PacketFrame {
        frame_at(ia(0x112), 100, at(1))
    }

    /// A one-segment path with a reservation on its middle hop.
    fn path_with_one_reservation() -> ScionPath {
        let mut path = one_segment_path();
        assert!(
            path.try_add_reservation(reservation(ia(0x111), 2, 3, 600))
                .expect("standard path")
        );
        path
    }

    fn encode_resolved(path: &ScionPath, frame: PacketFrame) -> Vec<u8> {
        let resolved = path.resolve(frame).expect("resolves");
        let mut buf = vec![0u8; resolved.required_size()];
        let written = resolved.try_encode(&mut buf).expect("encodes");
        assert_eq!(written, resolved.required_size(), "short write");
        buf
    }

    fn flyover_count(encoded: &[u8]) -> usize {
        let (view, rest): (&HbirdPathView, _) =
            HbirdPathView::try_from_slice(encoded).expect("parses as Hummingbird");
        assert!(rest.is_empty(), "trailing bytes");
        view.hop_fields().filter(|hop| hop.is_flyover()).count()
    }

    #[test]
    fn a_resolved_hummingbird_path_round_trips_through_the_wire() {
        // The whole send side end to end: attach a reservation, resolve for a packet, encode,
        // parse back, and find a flyover where the reservation was attached.
        let path = path_with_one_reservation();
        let encoded = encode_resolved(&path, test_frame());

        assert_eq!(
            PacketPath::path_type(&path.resolve(test_frame()).expect("resolves")),
            PathType::Hummingbird
        );
        assert_eq!(flyover_count(&encoded), 1);
    }

    #[test]
    fn a_path_without_reservations_resolves_to_its_own_bytes() {
        // The overlay exists but carries nothing, so the packet is the standard path verbatim —
        // no Hummingbird header, no MAC, no allocation.
        let mut path = one_segment_path();
        path.set_tracker(Arc::new(ProbabilisticTracker::new()))
            .expect("standard path");

        let resolved = path.resolve(test_frame()).expect("resolves");

        assert_eq!(PacketPath::path_type(&resolved), PathType::Scion);
        assert_eq!(
            encode_resolved(&path, test_frame()),
            path.dp_path().as_slice()
        );
    }

    #[test]
    fn a_path_without_reservations_never_opens_a_session() {
        // What lets a tracker be attached when a path is handed out, before anyone knows whether
        // it will carry reservations.
        let counter = Arc::new(SessionCounter::default());
        let mut path = one_segment_path();
        path.set_tracker(counter.clone()).expect("standard path");

        path.resolve(test_frame()).expect("resolves");
        assert_eq!(counter.sessions_opened(), 0);

        path.try_add_reservation(reservation(ia(0x111), 2, 3, 600))
            .expect("standard path");
        path.resolve(test_frame()).expect("resolves");
        assert_eq!(counter.sessions_opened(), 1);
    }

    #[test]
    fn the_template_and_the_full_encoder_agree_byte_for_byte() {
        // A packet's validity must not depend on which encoder ran. Exercised across shapes,
        // because the template only applies when every reserved hop was selected.
        for reserved in [vec![0], vec![1, 2], vec![0, 1, 2, 3]] {
            let mut path = two_segment_path();
            let reserved = reserve_hops(&mut path, &reserved);
            assert!(
                !reserved.is_empty(),
                "the shape must keep at least one flyover"
            );

            // Cloned before either resolution so both start from the same duplicate-detection
            // counter; without that the two would legitimately differ.
            let with_template = path.hbird_overlay().expect("overlay").clone();
            let mut without_template = with_template.clone();
            without_template.template = None;

            let encode = |overlay: &HbirdOverlay| {
                let resolved = overlay
                    .resolve(test_frame())
                    .expect("resolves")
                    .expect("a hop was selected");
                let mut buf = vec![0u8; resolved.encoded_len()];
                unsafe { resolved.encode_unchecked(&mut buf) };
                buf
            };

            assert_eq!(
                encode(&with_template),
                encode(&without_template),
                "reservations on {reserved:?}"
            );
        }
    }

    #[test]
    fn a_strict_tracker_reports_why_it_refused() {
        // The typed variants are the point: a caller can tell "renew the reservation" from "buy
        // more bandwidth" without parsing a message.
        let mut path = one_segment_path();
        path.try_add_reservation(reservation(ia(0x111), 2, 3, 600))
            .expect("standard path");
        path.set_tracker(Arc::new(TokenBucketTracker::new()))
            .expect("standard path");

        // Long after the reservation's window closed.
        let frame = frame_at(ia(0x112), 100, at(10_000));

        assert_eq!(
            path.resolve(frame)
                .expect_err("the reservation has expired"),
            PathResolveError::ReservationExpired
        );
    }

    #[test]
    fn a_lenient_tracker_demotes_instead_of_failing() {
        // Nothing degrades silently unless asked to: the same path and the same expired
        // reservation succeed once the tracker is wrapped. With its only flyover gone the packet
        // carries the underlying standard path, not an empty Hummingbird one.
        let mut path = one_segment_path();
        path.try_add_reservation(reservation(ia(0x111), 2, 3, 600))
            .expect("standard path");
        path.set_tracker(Arc::new(Lenient(TokenBucketTracker::new())))
            .expect("standard path");

        let frame = frame_at(ia(0x112), 100, at(10_000));

        assert_eq!(
            PacketPath::path_type(&path.resolve(frame).expect("demotes")),
            PathType::Scion
        );
        assert_eq!(encode_resolved(&path, frame), path.dp_path().as_slice());
    }

    #[test]
    fn required_size_is_stable_even_when_a_tracker_demotes() {
        // `required_size` takes &self, receives no context and is called twice per encode; an
        // answer that shrank in between is documented undefined behaviour. A demotion is the one
        // case where the length genuinely could have changed, so this is the case the whole
        // resolution seam exists for.
        let mut path = one_segment_path();
        path.try_add_reservation(reservation(ia(0x111), 2, 3, 600))
            .expect("standard path");
        path.set_tracker(Arc::new(Lenient(TokenBucketTracker::new())))
            .expect("standard path");

        let frame = frame_at(ia(0x112), 100, at(10_000));
        let resolved = path
            .resolve(frame)
            .expect("Lenient demotes rather than failing");

        let first = resolved.required_size();
        assert_eq!(first, resolved.required_size());
        assert_eq!(first, resolved.required_size());

        // And the frozen length is the demoted one, not the optimistic all-flyover one.
        assert_eq!(
            first,
            path.dp_path().as_slice().len(),
            "a fully demoted path is the standard path's own length"
        );
    }

    #[test]
    fn the_flyover_mac_covers_the_whole_packet_length() {
        // PktLen in the MAC input is the common header, address header, path and payload together.
        // Two packets differing only in payload size must produce different MACs, or the MAC would
        // be replayable across packet sizes.
        let path = path_with_one_reservation();
        let now = at(1);

        assert_ne!(
            encode_resolved(&path, frame_at(ia(0x112), 100, now)),
            encode_resolved(&path, frame_at(ia(0x112), 200, now)),
        );
    }

    #[test]
    fn the_flyover_mac_covers_the_destination_as() {
        // The other MAC input no caller ever names. A reservation minted for one destination must
        // not authenticate a packet to another.
        let path = path_with_one_reservation();
        let now = at(1);

        assert_ne!(
            encode_resolved(&path, frame_at(ia(0x112), 100, now)),
            encode_resolved(&path, frame_at(ia(0x113), 100, now)),
        );
    }

    #[test]
    fn two_packets_in_the_same_millisecond_differ_by_their_counter() {
        // The duplicate-detection counter is the only thing separating them, and the flyover MAC
        // covers it — so without it a router would see one packet twice.
        let path = path_with_one_reservation();
        let frame = test_frame();

        assert_ne!(encode_resolved(&path, frame), encode_resolved(&path, frame));
    }

    #[test]
    fn resolution_stamps_the_packets_send_time() {
        let path = path_with_one_reservation();
        let now = UNIX_EPOCH + Duration::from_millis((START + 1) * 1000 + 250);

        let resolved = path
            .resolve(frame_at(ia(0x112), 100, now))
            .expect("resolves");
        let ResolvedPath::Hummingbird(hbird) = &resolved else {
            panic!("a path with reservations resolves as Hummingbird");
        };

        assert_eq!(hbird.meta.base_timestamp, (START + 1) as u32);
        assert_eq!(hbird.meta.millis_timestamp, 250);
    }

    #[test]
    fn a_packet_too_long_to_encode_does_not_resolve() {
        // Caught before any reservation is charged, so an oversized packet costs no bandwidth.
        let path = path_with_one_reservation();

        assert!(matches!(
            path.resolve(frame_at(ia(0x112), u16::MAX, at(1))),
            Err(PathResolveError::PacketTooLong(_))
        ));
    }

    #[test]
    fn a_demoted_hop_shrinks_the_packet_the_macs_cover() {
        // The exact length is settled after selection, not before: a hop that loses its flyover
        // takes eight bytes off the packet, and every remaining MAC must cover the shorter figure.
        let mut path = two_segment_path();
        path.add_reservation_at(0, reservation(ia(0x110), 0, 1, 600))
            .expect("standard path");
        path.add_reservation_at(1, reservation(ia(0x111), 2, 0, 600))
            .expect("standard path");

        let all = encode_resolved(&path, test_frame());
        assert_eq!(flyover_count(&all), 2);

        // Expiring the second hop's reservation leaves one flyover and a shorter path.
        path.set_tracker(Arc::new(Lenient(TokenBucketTracker::new())))
            .expect("standard path");
        path.remove_expired_reservations(at(10_000));
        path.add_reservation_at(0, reservation(ia(0x110), 0, 1, 600))
            .expect("standard path");

        let one = encode_resolved(&path, test_frame());
        assert_eq!(flyover_count(&one), 1);
        assert_eq!(all.len() - one.len(), 8);
    }

    /// Resolution over arbitrary path shapes and arbitrary sets of reserved hops.
    ///
    /// Proptest found two genuine wire-format bugs earlier in this port, and this is the same
    /// class of code: a layout computed one way and read back another.
    #[test]
    fn any_path_resolves_to_something_that_parses_back() {
        use proptest::{prelude::*, test_runner::Config};

        use crate::dataplane_path::standard::model::ptest::ArbitraryPathContext;

        proptest!(
            Config::with_cases(200),
            |(
                path in StandardPath::arbitrary_with(ArbitraryPathContext {
                    // Twenty-five flyovers fill a segment's 508-byte line count, so staying under
                    // that keeps every generated shape encodeable and the interesting failures
                    // reachable.
                    hops_per_segment: 1..=8,
                    ..Default::default()
                }),
                reserved_mask: u32,
                exterior_len: u16,
                offset: u16,
            )| {
                resolves_and_parses(path, reserved_mask, exterior_len, offset)?;
            }
        );

        fn resolves_and_parses(
            path: StandardPath,
            reserved_mask: u32,
            exterior_len: u16,
            offset: u16,
        ) -> Result<(), proptest::test_runner::TestCaseError> {
            let hop_count = path.hop_field_count();
            let standard = path.try_encode_to_owned_view()?;
            let mut scion_path = ScionPath::new(
                ia(0x110),
                ia(0x112),
                ScionDpPathView::Standard(standard),
                None,
                None,
            );

            let asked: Vec<usize> = (0..hop_count)
                .filter(|index| reserved_mask & (1 << (index % 32)) != 0)
                .collect();
            let mut reserved = Vec::new();
            for &index in &asked {
                match scion_path.add_reservation_at(index, reservation(ia(0x110), 0, 1, u16::MAX)) {
                    Ok(()) => reserved.push(index),
                    // The first hop field after an ordinary crossover carries no flyover of its
                    // own; the crossover's reservation lives on the hop before it.
                    Err(PathResolveError::HopCannotCarryReservation { .. }) => {}
                    Err(err) => {
                        return Err(proptest::test_runner::TestCaseError::fail(format!(
                            "unexpected refusal for hop {index}: {err}"
                        )));
                    }
                }
            }

            let frame = frame_at(ia(0x112), exterior_len, at(u64::from(offset)));
            let resolved = match scion_path.resolve(frame) {
                Ok(resolved) => resolved,
                // The only failures a well-formed path may produce, both of them about this
                // packet rather than about the path.
                Err(PathResolveError::PacketTooLong(_) | PathResolveError::Encode(_)) => {
                    return Ok(());
                }
                Err(other) => {
                    return Err(proptest::test_runner::TestCaseError::fail(format!(
                        "unexpected resolution failure: {other}"
                    )));
                }
            };

            let mut buf = vec![0u8; resolved.required_size()];
            let written = resolved.try_encode(&mut buf)?;
            prop_assert_eq!(written, resolved.required_size(), "short write");

            if reserved.is_empty() {
                prop_assert_eq!(&buf, scion_path.dp_path().as_slice());
                return Ok(());
            }

            let (view, rest): (&HbirdPathView, _) = HbirdPathView::try_from_slice(&buf)?;
            prop_assert!(rest.is_empty(), "trailing bytes after the path");
            prop_assert_eq!(view.hop_fields().count(), hop_count);
            prop_assert_eq!(
                view.hop_fields().filter(|hop| hop.is_flyover()).count(),
                reserved.len()
            );
            prop_assert_eq!(
                HummingbirdPath::from_view(view).current_hop_field_index(),
                path.current_hop_field as usize,
                "the current hop field moved to another hop"
            );

            Ok(())
        }
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
    fn the_hop_after_an_ordinary_crossover_cannot_carry_a_reservation() {
        // The crossover AS owns both hop fields but reserves the pair once, on the earlier one.
        // A border router de-aggregates that hop field, steps to this one and verifies its plain
        // SCION MAC without de-aggregating again — so a flyover here is dropped at the router.
        let mut path = two_segment_path();

        assert_eq!(
            path.add_reservation_at(2, reservation(ia(0x111), 0, 3, 600))
                .expect_err("the hop after a crossover refuses"),
            PathResolveError::HopCannotCarryReservation { index: 2 }
        );

        let overlay = overlay_of(&path);
        let reservable: Vec<bool> = overlay.hops.iter().map(HbirdHop::is_reservable).collect();
        assert_eq!(reservable, [true, true, false, true]);
    }

    #[test]
    fn a_reservation_for_the_hop_after_a_crossover_attaches_nowhere() {
        // Its interface pair belongs to the crossover, whose reservation the hop before it already
        // matches. Attaching here as well would mean two reservations for one pair.
        let mut path = two_segment_path();

        assert!(
            !path
                .try_add_reservation(reservation(ia(0x111), 0, 3, 600))
                .expect("standard path"),
            "the crossover's own pair is (2, 3), not (0, 3)"
        );
        assert!(!path.has_reservations());
    }

    #[test]
    fn a_peering_crossover_leaves_both_of_its_hops_reservable() {
        // A peering link joins an AS to its *peer*, so the two hop fields belong to different ASes
        // and each carries its own reservation. The router skips its crossover handling here for
        // the same reason.
        let path = peering_path();
        let overlay = overlay_of(&path);

        assert!(
            overlay.hops.iter().all(HbirdHop::is_reservable),
            "a peering boundary reserves like any other link"
        );
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
    fn a_reversed_hummingbird_path_resolves_as_a_standard_path() {
        // What an SCMP handler replies over. Reservations are directional, so the return path has
        // none of its own, and reversal drops the overlay — leaving a standard path whose bytes
        // are already final. This is why the reply handlers need no resolution: `Static` is not an
        // oversight there, it is the only outcome available.
        let mut path = received_hbird_path();
        path.try_reverse().expect("a Hummingbird path reverses");

        assert!(matches!(path.dp_path(), ScionDpPathView::Standard(_)));
        assert!(!path.has_reservations());
        assert!(matches!(
            path.resolve(test_frame()).expect("resolves"),
            ResolvedPath::Static(_)
        ));
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
        let asked: Vec<usize> = (0..hop_count)
            .filter(|hop_idx| flyover_mask & (1 << hop_idx) != 0)
            .collect();
        reserve_hops(&mut path, &asked);
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
