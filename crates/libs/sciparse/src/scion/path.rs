// Copyright 2026 Anapaya Systems
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

//! SCION control plane paths and related functionality.
//!
//! These paths are usually obtained from the SCION daemon.
//! They contain the encoded dataplane path and optional metadata about the path, such as expiration
//! time, MTU, and interfaces used by the path.

use std::{
    borrow::Cow, collections::HashMap, fmt::Display, net::SocketAddr, sync::Arc,
    time::SystemTime,
};

use prost_types::Timestamp;
use scion_protobuf::daemon::v1 as rpc;

use crate::{
    core::view::View,
    dataplane_path::{
        resolve::{PacketFrame, PathResolveError, ResolvedPath},
        standard::view::StandardPathView,
        types::PathReverseError,
        view::{ScionDpPathView, ScionDpPathViewExt, ScionDpPathViewExtMut},
    },
    hummingbird::{Reservation, tracker::ReservationTracker},
    identifier::isd_asn::IsdAsn,
    path::{
        fingerprint::data_plane::DpPathFingerprint,
        hbird_overlay::HbirdOverlay,
        metadata::{
            geo::GeoCoordinates,
            link::{LinkMeta, LinkType},
            path_interface::PathInterface,
        },
    },
    rpc::FromRpcError,
};

pub mod combinator;
pub mod fingerprint;
pub mod hbird_overlay;
pub mod metadata;
pub mod policy;

/// A Control Plane Path, which can be of different types (e.g., standard, one-hop).
///
/// This contains a [ScionDpPathView], which is the encoded dataplane path as returned by the
/// SCION daemon, and optional metadata about the path, such as expiration time, MTU, and interfaces
/// used by the path
#[derive(Debug, Clone)]
pub struct ScionPath {
    /// The ISD-AS of the path's source.
    src_ia: IsdAsn,
    /// The ISD-AS of the path's destination.
    dst_ia: IsdAsn,
    /// The encoded dataplane path as returned by the SCION daemon.
    ///
    /// For a Hummingbird path this is the underlying *standard* path; the Hummingbird
    /// part lives in `hbird` as an overlay on top of it.
    dp_path: ScionDpPathView,
    /// Hummingbird overlay: attached reservations and the reservation tracker that chooses
    /// between them. `None` for an ordinary path, and always `None` for a path parsed from a
    /// received Hummingbird packet.
    hbird: Option<HbirdOverlay>,
    /// Metadata about the path
    metadata: Option<metadata::PathMetadata>,
    /// The address of the SCION router which is used to exit the local AS on this path.
    next_hop: Option<SocketAddr>,

    // Computed fields
    /// Computed fingerprint of the path based on control plane data
    _cp_fingerprint: Option<fingerprint::control_plane::PathFingerprint>,
    /// Computed fingerprint of the path based on the dataplane path data
    _fingerprint: fingerprint::data_plane::DpPathFingerprint,
    /// Computed Unix epoch in seconds after which the path is considered expired.
    ///
    /// None if the paths expiration time could not be obtained from the dataplane path (e.g.,
    /// unsupported path types).
    _expiration: Option<u32>,
}
impl ScionPath {
    /// Creates a new [ScionPath] with the given dataplane path and metadata.
    #[inline]
    pub fn new(
        src_ia: IsdAsn,
        dst_ia: IsdAsn,
        dp_path: ScionDpPathView,
        metadata: Option<metadata::PathMetadata>,
        next_hop: Option<SocketAddr>,
    ) -> Self {
        let dp_fingerprint = DpPathFingerprint::from_dp_path(dp_path.as_ref(), src_ia, dst_ia);

        let expiration = dp_path.expiration();

        let mut this = Self {
            dp_path,
            hbird: None,
            metadata,
            src_ia,
            dst_ia,
            next_hop,
            _cp_fingerprint: None,
            _fingerprint: dp_fingerprint,
            _expiration: expiration,
        };

        // Try to set the path fingerprint if possible
        this._cp_fingerprint =
            fingerprint::control_plane::PathFingerprint::try_from_scion_path(&this).ok();
        this
    }

    /// Creates a new [ScionPath] for a local path, sending packets within the same AS.
    ///
    /// Returns None if the AS is a wildcard.
    #[inline]
    pub fn local(local_as: IsdAsn) -> Option<Self> {
        if local_as.is_wildcard() {
            None
        } else {
            Some(Self::new(
                local_as,
                local_as,
                ScionDpPathView::Empty,
                None,
                None,
            ))
        }
    }
}
impl PartialEq for ScionPath {
    /// Two paths are equal when they are the same route, carrying the same metadata, reached
    /// through the same next hop.
    fn eq(&self, other: &Self) -> bool {
        self.src_ia == other.src_ia
            && self.dst_ia == other.dst_ia
            && self.dp_path == other.dp_path
            && self.metadata == other.metadata
            && self.next_hop == other.next_hop
    }
}

// utility
impl ScionPath {
    /// Returns the egress interface of the first hop of the path.
    #[inline]
    pub fn first_egress_interface(&self) -> Option<PathInterface> {
        // Try from dataplane path first
        if let Some(if_id) = self.dp_path.first_egress_interface() {
            return Some(PathInterface {
                isd_asn: self.src_ia,
                id: if_id,
            });
        }

        // Then try from metadata
        if let Some(meta_if) = self
            .metadata
            .as_ref()
            .as_ref()
            .and_then(|m| m.interfaces.as_ref())
            .and_then(|interfaces| interfaces.first())
            .map(|meta| meta.interface)
        {
            return Some(meta_if);
        }

        None
    }

    /// Returns the ingress interface of the last hop of the path, if metadata is available.
    #[inline]
    pub fn last_ingress_interface(&self) -> Option<PathInterface> {
        // Try from dataplane path first
        if let Some(if_id) = self.dp_path.last_ingress_interface() {
            return Some(PathInterface {
                isd_asn: self.dst_ia,
                id: if_id,
            });
        }

        // Then try from metadata
        if let Some(meta_if) = self
            .metadata
            .as_ref()
            .as_ref()
            .and_then(|m| m.interfaces.as_ref())
            .and_then(|interfaces| interfaces.last())
            .map(|meta| meta.interface)
        {
            return Some(meta_if);
        }

        None
    }

    /// Attempts to reverse the path by reversing the dataplane path and swapping the source and
    /// destination ISD-AS.
    ///
    /// If EPIC authentication information is present in the path metadata, it will be lost, as it
    /// is not possible to derive the reverse secret.
    ///
    /// If the dataplane path type does not support reversal, returns an error.
    #[inline]
    pub fn try_reverse(&mut self) -> Result<(), PathReverseError> {
        self.dp_path.try_reverse()?;
        std::mem::swap(&mut self.src_ia, &mut self.dst_ia);

        // Next hop is not valid after reversal.
        self.next_hop = None;

        // Flyover reservations are directional.
        self.hbird = None;

        if let Some(metadata) = self.metadata.as_mut() {
            metadata.reverse();

            self._cp_fingerprint =
                fingerprint::control_plane::PathFingerprint::try_from_scion_path(self).ok();
        }

        self._fingerprint = fingerprint::data_plane::DpPathFingerprint::from_dp_path(
            self.dp_path.as_ref(),
            self.src_ia,
            self.dst_ia,
        );

        Ok(())
    }

    /// Resolves this path for exactly one packet.
    ///
    /// A path's encoding can depend on the packet carrying it — a Hummingbird flyover MAC covers
    /// the destination AS, the packet length and the send time — and so, therefore, can its
    /// length. Resolution takes those decisions once and hands back a
    /// [`ResolvedPath`] whose length is fixed, which is the only form an encoder accepts.
    ///
    /// For paths whose bytes do not vary per packet this is close to free: the frame is consulted
    /// only to check that the resulting packet is short enough to encode.
    #[inline]
    pub fn resolve(&self, frame: PacketFrame) -> Result<ResolvedPath<'_>, PathResolveError> {
        match self.hbird.as_ref() {
            // An overlay only ever exists over a standard path, so it knows the hops it is layered
            // on. One carrying no reservations takes the static arm and stays a plain memcpy,
            // which is what makes attaching a tracker at path-handout time free.
            Some(overlay) if overlay.has_reservations() => {
                match overlay.resolve(frame)? {
                    Some(resolved) => Ok(ResolvedPath::Hummingbird(resolved)),
                    // No hop kept a flyover, so there is nothing Hummingbird to say.
                    None => ResolvedPath::resolve_static(self.dp_path.as_ref(), frame),
                }
            }
            _ => ResolvedPath::resolve_static(self.dp_path.as_ref(), frame),
        }
    }

    /// Attempts to reverse the path by reversing the dataplane path and swapping the source and
    /// destination ISD-AS.
    ///
    /// If EPIC authentication information is present in the path metadata, it will be lost, as it
    /// is not possible to derive the reverse secret.
    ///
    /// If the dataplane path type does not support reversal, returns an error.
    #[allow(clippy::result_large_err)]
    #[inline]
    pub fn try_into_reversed(mut self) -> Result<Self, (Self, PathReverseError)> {
        match self.try_reverse() {
            Ok(()) => Ok(self),
            Err(e) => Err((self, e)),
        }
    }

    /// Returns true if the path is expired.
    ///
    /// First checks the expiration time from the dataplane path, if available. If not, checks the
    /// expiration time from the control plane metadata.
    ///
    /// If neither is available, the function returns None.
    #[inline]
    pub fn is_expired(&self, timestamp: u32) -> Option<bool> {
        let expiration = self.expiration()?;
        Some(timestamp >= expiration)
    }
}

/// Hummingbird send-side operations.
///
/// All of these need an overlay, and an overlay is only meaningful on a standard path: a path
/// parsed from a received Hummingbird packet is a snapshot of one packet rather than a generator
/// of encodings, and the remaining path types have no hops to attach reservations to. Those cases
/// return [`PathResolveError::ReservationsUnsupported`].
impl ScionPath {
    /// The overlay for this path, created if it does not have one yet.
    fn overlay_mut(&mut self) -> Result<&mut HbirdOverlay, PathResolveError> {
        if self.hbird.is_none() {
            let ScionDpPathView::Standard(view) = &self.dp_path else {
                return Err(PathResolveError::ReservationsUnsupported);
            };

            self.hbird = Some(HbirdOverlay::new(view, self.src_ia, self.metadata.as_ref()));
        }

        Ok(self
            .hbird
            .as_mut()
            .expect("the overlay was just created if it was missing"))
    }

    /// Attaches `reservation` to whichever of this path's hops it covers, matching by AS and
    /// interface pair.
    ///
    /// Returns whether any hop matched.
    ///
    /// A hop's AS comes from the path's metadata. A path without metadata can therefore match
    /// nothing; use [`add_reservation_at`](Self::add_reservation_at) for those.
    pub fn try_add_reservation(
        &mut self,
        reservation: Reservation,
    ) -> Result<bool, PathResolveError> {
        Ok(self.overlay_mut()?.try_add_reservation(reservation))
    }

    /// Attaches `reservation` to the hop at flat index `hop_idx`, counting hops across all
    /// segments in order, without matching it against that hop's interfaces.
    ///
    /// Fails if the index names no hop, or names the first hop field after an ordinary crossover,
    /// which cannot carry a flyover.
    ///
    /// See also [`try_add_reservation`](Self::try_add_reservation).
    pub fn add_reservation_at(
        &mut self,
        hop_idx: usize,
        reservation: Reservation,
    ) -> Result<(), PathResolveError> {
        self.overlay_mut()?.add_reservation_at(hop_idx, reservation)
    }

    /// Drops every attached reservation whose validity window has passed by `now`.
    pub fn remove_expired_reservations(&mut self, now: SystemTime) {
        if let Some(overlay) = self.hbird.as_mut() {
            overlay.remove_expired_reservations(now);
        }
    }

    /// Attaches or replaces the reservation tracker that decides which of a hop's reservations
    /// each packet uses.
    ///
    /// The same tracker can be attached to multiple paths, e.g., to monitor the usage
    /// of a reservation by multiple paths against the same bandwidth allowance.
    pub fn set_tracker(
        &mut self,
        tracker: Arc<dyn ReservationTracker>,
    ) -> Result<(), PathResolveError> {
        self.overlay_mut()?.set_tracker(tracker);
        Ok(())
    }

    /// The hops of this path that could carry a flyover reservation, each with the AS that owns
    /// it and the interfaces it is entered and left by.
    ///
    /// The tuple is `(hop_index, isd_asn, ingress, egress)`, where `hop_index` counts hops across
    /// all segments in order — the same index [`add_reservation_at`](Self::add_reservation_at)
    /// takes. Use it to ask each AS on a path for a reservation before attaching the results.
    ///
    /// Answers without disturbing the path: an overlay is built and discarded rather than
    /// attached, so a path that carries no reservations still carries none afterwards.
    ///
    /// Returns `None` if this path cannot carry reservations at all — its dataplane path is not a
    /// standard one. A hop whose AS the path's metadata does not identify is skipped, since there
    /// is nobody to ask; a path with no metadata therefore yields an empty vector.
    pub fn reservable_hops(&self) -> Option<Vec<(u8, IsdAsn, u16, u16)>> {
        let ScionDpPathView::Standard(view) = &self.dp_path else {
            return None;
        };

        let overlay = match self.hbird.as_ref() {
            Some(overlay) => Cow::Borrowed(overlay),
            None => Cow::Owned(HbirdOverlay::new(view, self.src_ia, self.metadata.as_ref())),
        };

        Some(
            overlay
                .hops()
                .iter()
                .enumerate()
                .filter(|(_, hop)| hop.is_reservable())
                .filter_map(|(idx, hop)| {
                    Some((u8::try_from(idx).ok()?, hop.isd_asn()?, hop.ingress(), hop.egress()))
                })
                .collect(),
        )
    }

    /// The Hummingbird overlay attached to this path, if one has been created.
    ///
    /// An overlay appears the first time a reservation or a tracker is attached; before that
    /// this is `None`.
    pub fn hbird_overlay(&self) -> Option<&HbirdOverlay> {
        self.hbird.as_ref()
    }

    /// Whether any hop of this path carries a reservation.
    ///
    /// `false` means every send over this path is a plain copy of the standard path's bytes.
    pub fn has_reservations(&self) -> bool {
        self.hbird
            .as_ref()
            .is_some_and(HbirdOverlay::has_reservations)
    }
}
// accessors
impl ScionPath {
    /// Returns the encoded dataplane path as returned by the SCION daemon.
    #[inline]
    pub const fn dp_path(&self) -> &ScionDpPathView {
        &self.dp_path
    }
    /// Returns metadata about the path, if available.
    #[inline]
    pub const fn metadata(&self) -> Option<&metadata::PathMetadata> {
        self.metadata.as_ref()
    }

    /// Returns the ISD-AS of the path's source.
    #[inline]
    pub const fn src_ia(&self) -> IsdAsn {
        self.src_ia
    }

    /// Returns the ISD-AS of the path's destination.
    #[inline]
    pub const fn dst_ia(&self) -> IsdAsn {
        self.dst_ia
    }

    /// Returns the address of the SCION router which is used to exit the local AS on this path, if
    /// available.
    #[inline]
    pub const fn next_hop(&self) -> Option<SocketAddr> {
        self.next_hop
    }

    /// Sets the address of the SCION router which is used to exit the local AS on this path.
    #[inline]
    pub fn set_next_hop(&mut self, next_hop: Option<SocketAddr>) {
        self.next_hop = next_hop;
    }

    /// Returns a fingerprint for this path, uniquely identifying the route taken by the path.
    ///
    /// Usually [Self::fingerprint] is preferable, this method is only useful if the control plane
    /// fingerprint is needed.
    ///
    /// See [PathFingerprint](fingerprint::control_plane::PathFingerprint) for details.
    #[inline]
    pub const fn cp_fingerprint(&self) -> Option<fingerprint::control_plane::PathFingerprint> {
        self._cp_fingerprint
    }

    /// Returns the fingerprint for this path based on the dataplane path data, uniquely identifying
    /// the route taken by the path.
    ///
    /// See [DpPathFingerprint](fingerprint::data_plane::DpPathFingerprint) for details.
    #[inline]
    pub const fn fingerprint(&self) -> fingerprint::data_plane::DpPathFingerprint {
        self._fingerprint
    }

    /// Returns the expiration time of the path in seconds since the UNIX epoch, if available.
    ///
    /// This is obtained from the dataplane path if possible, and falls back to the control plane
    /// metadata if not.
    ///
    /// Returns None if the expiration time could not be obtained from either source.
    #[inline]
    pub fn expiration(&self) -> Option<u32> {
        self._expiration.or_else(|| {
            self.metadata
                .as_ref()
                .map(|metadata| metadata.expiration as u32)
        })
    }
}
// rpc
impl ScionPath {
    /// Creates a new [ScionPath] from the given RPC path.
    ///
    /// ### Parameters
    /// - `rpc_path`: The RPC path as returned by the SCION daemon.
    /// - `src_ia`: The ISD-AS of the path's source.
    /// - `dst_ia`: The ISD-AS of the path's destination.
    pub fn try_from_rpc(
        rpc_path: rpc::Path,
        src_ia: IsdAsn,
        dst_ia: IsdAsn,
    ) -> Result<Self, FromRpcError> {
        if rpc_path.raw.is_empty() {
            if src_ia.is_wildcard() && dst_ia.is_wildcard() {
                // Todo(ake): Scion Proto creates a `empty` path here. Does this make sense?
                return Err(
                    "cannot create empty path with wildcard source and destination IA".into(),
                );
            } else if src_ia == dst_ia {
                // Local path, create an empty dataplane path
                return Ok(Self::local(src_ia).expect("check above ensures src_ia is not wildcard"));
            } else {
                return Err("RPC payload had an empty path".into());
            }
        }

        // Parse the path
        let (view, rest) = StandardPathView::try_from_slice(&rpc_path.raw).map_err(|err| {
            FromRpcError::new(format!("failed to parse standard path from RPC: {err}"))
        })?;

        if !rest.is_empty() {
            return Err("RPC payload had extra data after parsing standard path".into());
        }

        let next_hop = rpc_path
            .interface
            .and_then(|intf| intf.address)
            .map(|addr| addr.address.parse())
            .transpose()
            .map_err(|err| {
                FromRpcError::new(format!("failed to parse next hop address from RPC: {err}"))
            })?;

        let path_meta = {
            let interface_count = rpc_path.interfaces.len();
            if interface_count == 0 || !interface_count.is_multiple_of(2) {
                return Err(format!(
                    "RPC payload had invalid number of interfaces: expected an even number greater than 0, got {interface_count}"
                ).into());
            }

            let mut interface_meta = rpc_path
                .interfaces
                .into_iter()
                .map(|intf| {
                    Ok(metadata::InterfaceMetadata {
                        interface: intf.try_into()?,
                        geo_info: None,
                        latency: None,
                        bandwidth: None,
                        link: None,
                    })
                })
                .collect::<Result<Vec<_>, FromRpcError>>()?;

            let expected_count_ases = interface_count / 2 + 1;
            let expected_count_links = interface_count - 1;
            let expected_count_links_intra = interface_count / 2 - 1;
            let expected_count_links_inter = interface_count / 2;

            let expiration: u64 = rpc_path
                .expiration
                .map(|ts| ts.seconds)
                .ok_or("RPC payload missing expiration timestamp")?
                as u64;

            let mtu: u16 = rpc_path
                .mtu
                .try_into()
                .map_err(|_| "RPC MTU does not fit in u16")?;

            // Collect latencies if available, one per link (total_interfaces - 1) leaving out the
            // last interface which is the destination
            if rpc_path.latency.len() == expected_count_links {
                for (meta, latency) in interface_meta.iter_mut().zip(rpc_path.latency.into_iter()) {
                    // A negative latency indicates that no latency is supplied, so we treat it as
                    // None
                    meta.latency = latency.try_into().ok();
                }
            }

            // Collect bandwidths if available, one per link (total_interfaces - 1) leaving out the
            // last interface which is the destination
            if rpc_path.bandwidth.len() == expected_count_links {
                for (meta, bandwidth) in interface_meta
                    .iter_mut()
                    .zip(rpc_path.bandwidth.into_iter())
                {
                    // Bandwith of 0 indicates that no bandwidth is supplied
                    meta.bandwidth = (bandwidth > 0).then_some(bandwidth);
                }
            }

            // Collect geo info if available, one per interface
            if rpc_path.geo.len() == interface_count {
                for (meta, geo_info) in interface_meta.iter_mut().zip(rpc_path.geo.into_iter()) {
                    meta.geo_info = GeoCoordinates::try_from_rpc(geo_info);
                }
            }

            // Link Types
            // The path switches between intra-AS and inter-AS links every interface.
            // The first is always a inter-AS link, the second an intra-AS link, and so on.
            // We need to weave the rpc_path.link_type and rpc_path.interfaces together to assign
            // the correct link type to each interface.

            {
                // Inter-AS links are at the even indices (0, 2, 4, ...) of the interfaces
                let egress_iter = interface_meta.iter_mut().step_by(2);
                if rpc_path.link_type.len() == expected_count_links_inter {
                    for (egress_meta, link_type) in egress_iter.zip(rpc_path.link_type.into_iter())
                    {
                        egress_meta.link = Some(LinkMeta::Egress(link_type.into()));
                    }
                }
            }

            {
                // Intra-AS links are at the odd indices (1, 3, 5, ...) of the interfaces
                let ingress_iter = interface_meta.iter_mut().skip(1).step_by(2);
                if rpc_path.internal_hops.len() == expected_count_links_intra {
                    for (ingress_meta, internal_hops) in
                        ingress_iter.zip(rpc_path.internal_hops.into_iter())
                    {
                        ingress_meta.link = Some(LinkMeta::Ingress {
                            internal_hop_count: internal_hops,
                        });
                    }
                }
            }

            // collect notes if available, one per AS (total_interfaces / 2 + 1) leaving out the
            // links
            let notes = if rpc_path.notes.len() == expected_count_ases {
                Some(rpc_path.notes)
            } else {
                None
            };

            metadata::PathMetadata {
                expiration,
                mtu,
                interfaces: Some(interface_meta),
                epic_auth: None,
                notes,
            }
        };

        Ok(Self::new(
            src_ia,
            dst_ia,
            view.to_boxed().into(),
            Some(path_meta),
            next_hop,
        ))
    }

    /// Converts the [ScionPath] into an RPC path.
    pub fn to_rpc(&self) -> rpc::Path {
        // Creating a new rpc::Path struct first for simplicity, then copying the fields over to a
        // new struct to ensure all fields are set.
        let mut rpc_path = rpc::Path {
            ..Default::default()
        };

        rpc_path.raw = self.dp_path.as_slice().to_vec();
        rpc_path.interface = self.next_hop.map(|addr| {
            rpc::Interface {
                address: Some(rpc::Underlay {
                    address: addr.to_string(),
                }),
            }
        });

        if let Some(meta) = &self.metadata {
            rpc_path.mtu = meta.mtu as u32;
            rpc_path.expiration = Some(Timestamp {
                //XXX(ake): Let's see if we are still using unix epoch at ~292 billion CE
                seconds: meta.expiration.try_into().unwrap_or(i64::MAX),
                nanos: 0,
            });
            rpc_path.epic_auths = meta.epic_auth.clone().map(|auth| auth.to_rpc());

            if let Some(if_meta) = &meta.interfaces {
                rpc_path.interfaces = if_meta
                    .iter()
                    .map(|meta| {
                        rpc::PathInterface {
                            isd_as: meta.interface.isd_asn.to_u64(),
                            id: meta.interface.id as u64,
                        }
                    })
                    .collect();

                rpc_path.latency = if_meta
                    .iter()
                    .map(|latency| {
                        match latency.latency {
                            Some(latency) => {
                                prost_types::Duration {
                                    // XXX(ake): I hope most links won't have multiple hundered
                                    // years of latency.
                                    seconds: latency.as_secs().try_into().unwrap_or(i64::MAX),
                                    nanos: latency.subsec_nanos().try_into().unwrap_or(i32::MAX),
                                }
                            }
                            // XXX(ake): a negative value indicates that no latency is supplied
                            None => {
                                prost_types::Duration {
                                    seconds: -1,
                                    nanos: 0,
                                }
                            }
                        }
                    })
                    .collect();

                rpc_path.bandwidth = if_meta
                    .iter()
                    .map(|meta| meta.bandwidth.unwrap_or(0))
                    .collect();

                rpc_path.geo = if_meta
                    .iter()
                    .map(|meta| {
                        meta.geo_info
                            .as_ref()
                            .map(|geo| geo.to_rpc())
                            .unwrap_or_default()
                    })
                    .collect();

                rpc_path.link_type = if_meta
                    .iter()
                    .map(|meta| {
                        match &meta.link {
                            Some(LinkMeta::Egress(link_type)) => link_type.to_i32(),
                            _ => LinkType::Unset.to_i32(),
                        }
                    })
                    .collect();

                // collect notes if available, must be one per AS (total_interfaces / 2 + 1)
                let expected_count_ases = if_meta.len() / 2 + 1;
                if let Some(notes) = &meta.notes {
                    // XXX(ake): don't really have a good idea to validate the notes or pad them to
                    // the expected length
                    if notes.len() == expected_count_ases {
                        rpc_path.notes = notes.clone();
                    }
                }
            }
        }

        // XXX(ake): Doing this to catch any new fields added to the rpc::Path struct in the future,
        // so we don't forget to set them here. Compiler should easily optimize this away.
        rpc::Path {
            raw: rpc_path.raw,
            interface: rpc_path.interface,
            interfaces: rpc_path.interfaces,
            mtu: rpc_path.mtu,
            expiration: rpc_path.expiration,
            latency: rpc_path.latency,
            bandwidth: rpc_path.bandwidth,
            geo: rpc_path.geo,
            link_type: rpc_path.link_type,
            internal_hops: rpc_path.internal_hops,
            notes: rpc_path.notes,
            epic_auths: rpc_path.epic_auths,
            discovery_information: HashMap::default(), // TODO: add support for discovery info
        }
    }
}
// formating
impl ScionPath {
    /// Formats the interfaces of the path for human consumption
    ///
    /// Example: `"1-ff00:0:111 2>2 1-ff00:0:110 5>10 1-ff00:0:200"`
    ///
    /// If no interface metadata is available, the dataplane path is used to format the interfaces
    /// instead.
    pub fn format_interfaces(&self, writer: &mut dyn std::fmt::Write) -> std::fmt::Result {
        match self
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.interfaces.as_ref())
        {
            Some(interfaces) => {
                if interfaces.is_empty() {
                    write!(writer, "<empty interfaces>")?;
                    return Ok(());
                }

                if interfaces.len() != 1 && interfaces.len() % 2 != 0 {
                    // This is not a valid path, but we handle it anyway.
                    write!(writer, "<invalid path> ")?;
                }

                // first interface
                let first = &interfaces[0]; // Safety: we know there is at least one interface
                write!(writer, "{} {}", first.interface.isd_asn, first.interface.id)?;

                if interfaces.len() <= 1 {
                    // in case there is only one interface we are done
                    return Ok(());
                }

                write!(writer, ">")?;

                let mut had_final = false;
                // following interfaces
                for chunk in interfaces[1..interfaces.len()].chunks(2) {
                    match chunk {
                        [trav_in, trav_out] => {
                            match trav_in.interface.isd_asn == trav_out.interface.isd_asn {
                                true => {
                                    write!(
                                        writer,
                                        "{} {} {}>",
                                        trav_in.interface.id,
                                        trav_in.interface.isd_asn,
                                        trav_out.interface.id
                                    )?
                                }
                                false => {
                                    write!(
                                        writer,
                                        "{} <invalid hop> ({}/{}) {}>",
                                        trav_in.interface.id,
                                        trav_in.interface.isd_asn,
                                        trav_out.interface.isd_asn,
                                        trav_out.interface.id
                                    )?;
                                }
                            }
                        }
                        [final_if] => {
                            write!(
                                writer,
                                "{} {}",
                                final_if.interface.id, final_if.interface.isd_asn
                            )?;
                            had_final = true;
                        }
                        _ => {}
                    }
                }

                if !had_final {
                    writer.write_str(" missing final hop")?;
                }

                Ok(())
            }
            None => {
                write!(writer, "{}", self.dp_path)
            }
        }
    }
}
impl Display for ScionPath {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "src: {} dst: {} next_hop: {} fp: {} path: ",
            self.src_ia,
            self.dst_ia,
            self.next_hop
                .map_or("none".to_string(), |addr| addr.to_string()),
            self._fingerprint,
        )?;

        self.format_interfaces(f)
    }
}
