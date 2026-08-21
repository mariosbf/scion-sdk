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

//! Per-packet resolution of dataplane paths.
//!
//! Most path types encode to the same bytes for every packet, so a path can be handed straight to
//! an encoder. Hummingbird paths cannot: a flyover MAC binds the destination AS, the packet
//! length and the send time, so each packet needs a fresh encoding — and its *length* depends on
//! decisions taken per packet, since a hop that ends up without a usable reservation is encoded as
//! a 12-byte standard hop field rather than a 20-byte flyover.
//!
//! That is a problem for [`WireEncode::required_size`], which takes `&self`, receives no packet
//! context, is called more than once per encode, and documents an undersized answer as undefined
//! behaviour. Resolution takes those decisions once and records the result in a [`ResolvedPath`],
//! whose length is fixed at construction. Because only the resolved form implements
//! [`WireEncode`], an unresolved path cannot reach an encoder at all: the hazard is removed by the
//! type system rather than by a convention encoders have to remember.

use std::time::SystemTime;

use crate::{
    core::encode::{InvalidStructureError, WireEncode},
    dataplane_path::{
        hbird::model::HbirdEncodeError,
        types::PathType,
        view::{ScionDpPathViewExt, ScionDpPathViewRef},
    },
    header::{
        layout::CommonHeaderLayout,
        model::{AddressHeader, PacketPath},
    },
    hummingbird::tracker::ReservationTrackerError,
    identifier::isd_asn::IsdAsn,
    path::hbird_overlay::ResolvedHbirdPath,
};

/// What a dataplane path needs to know about the packet around it in order to encode itself.
///
/// Only one length is carried, rather than a payload length and a header length, because a path
/// is the one part of the packet whose length the caller cannot know: it is what resolution
/// decides. The path adds its own encoded length to [`exterior_len`](Self::exterior_len) to obtain
/// the packet length its MACs cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketFrame {
    /// Destination AS. Covered by the Hummingbird flyover MAC.
    pub dst_ia: IsdAsn,
    /// Every byte of the packet that is not the path: common header, address header, payload.
    pub exterior_len: u16,
    /// The instant this packet is emitted, stamped into the Hummingbird meta header.
    pub now: SystemTime,
}

impl PacketFrame {
    /// Builds a frame from the packet parts that are known before a path is attached.
    #[inline]
    pub fn new(address: &AddressHeader, payload_size: u16, now: SystemTime) -> Self {
        Self {
            dst_ia: address.dst_ia,
            exterior_len: CommonHeaderLayout::SIZE_BYTES as u16
                + address.required_size() as u16
                + payload_size,
            now,
        }
    }
}

/// A dataplane path whose encoded form is fully determined for one packet.
///
/// Only this type implements [`WireEncode`] among the path representations, which is what makes
/// [`WireEncode::required_size`] safe to leave context-free: by the time an encoder can see a
/// path, every per-packet decision has already been taken.
#[derive(Debug, Clone)]
pub enum ResolvedPath<'a> {
    /// A path whose bytes are already final and are written out verbatim.
    ///
    /// This covers every path type whose encoding does not vary per packet, and also a Hummingbird
    /// path that arrived in a received packet: its bytes are fixed and it is not something that
    /// gets sent onward without being reversed first.
    Static(ScionDpPathViewRef<'a>),

    /// A standard path carrying flyover reservations, whose shape and MACs were fixed for this
    /// one packet.
    Hummingbird(ResolvedHbirdPath<'a>),
}

/// Why a path could not be resolved for a packet.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathResolveError {
    /// The resulting packet would be longer than the length field can express.
    #[error("packet length {0} exceeds the maximum encodeable value")]
    PacketTooLong(usize),
    /// This path cannot carry flyover reservations, because reservations are layered over a
    /// *standard* path and this path's dataplane path is not one.
    #[error("flyover reservations are only supported on standard paths")]
    ReservationsUnsupported,
    /// The hop index named no hop on this path.
    #[error("hop index {index} is out of range for a path with {hop_count} hops")]
    HopIndexOutOfRange {
        /// The index that was asked for.
        index: usize,
        /// The number of hops the path actually has.
        hop_count: usize,
    },
    /// Every reservation on some hop was outside its validity window.
    ///
    /// The path itself is unharmed; renewing the reservation makes it sendable again. Wrap the
    /// tracker in [`Lenient`](crate::hummingbird::tracker::Lenient) to send the packet without a
    /// flyover on that hop instead of failing.
    #[error("no reservation on one of the path's hops is still valid")]
    ReservationExpired,
    /// Some hop had valid reservations, but none with bandwidth left for this packet.
    ///
    /// Distinct from [`ReservationExpired`](Self::ReservationExpired) because the remedy is
    /// different: wait, send less, or obtain a larger reservation.
    #[error("no reservation on one of the path's hops has bandwidth left for this packet")]
    BandwidthExceeded,
    /// The path could not be laid out for this packet, or a selected reservation could not be
    /// encoded against its timestamp.
    #[error(transparent)]
    Encode(#[from] HbirdEncodeError),
}

impl From<ReservationTrackerError> for PathResolveError {
    fn from(error: ReservationTrackerError) -> Self {
        match error {
            ReservationTrackerError::ReservationExpired => Self::ReservationExpired,
            ReservationTrackerError::BandwidthExceeded => Self::BandwidthExceeded,
        }
    }
}

impl<'a> ResolvedPath<'a> {
    /// Resolves a path whose encoding does not depend on the packet.
    ///
    /// The frame is still consulted, because a path that is fine in isolation can still make the
    /// packet around it too long to encode.
    #[inline]
    pub fn resolve_static(
        view: ScionDpPathViewRef<'a>,
        frame: PacketFrame,
    ) -> Result<Self, PathResolveError> {
        let packet_len = frame.exterior_len as usize + view.as_slice().len();
        if packet_len > u16::MAX as usize {
            return Err(PathResolveError::PacketTooLong(packet_len));
        }

        Ok(ResolvedPath::Static(view))
    }

    /// The total packet length this resolution implies, in bytes.
    ///
    /// This is the value a Hummingbird flyover MAC covers, and it is only knowable once the path
    /// has been resolved.
    #[inline]
    pub fn packet_len(&self, frame: PacketFrame) -> u16 {
        frame.exterior_len + self.required_size() as u16
    }
}

impl PacketPath for ResolvedPath<'_> {
    #[inline]
    fn path_type(&self) -> PathType {
        match self {
            ResolvedPath::Static(view) => {
                match view {
                    ScionDpPathViewRef::Empty => PathType::Empty,
                    ScionDpPathViewRef::Standard(_) => PathType::Scion,
                    ScionDpPathViewRef::OneHop(_) => PathType::OneHop,
                    ScionDpPathViewRef::Hummingbird(_) => PathType::Hummingbird,
                    ScionDpPathViewRef::Unsupported { path_type, .. } => *path_type,
                }
            }
            // The overlay's own path is standard; what goes on the wire is Hummingbird.
            ResolvedPath::Hummingbird(_) => PathType::Hummingbird,
        }
    }
}

impl WireEncode for ResolvedPath<'_> {
    #[inline]
    fn required_size(&self) -> usize {
        match self {
            ResolvedPath::Static(view) => view.as_slice().len(),
            ResolvedPath::Hummingbird(path) => path.encoded_len(),
        }
    }

    #[inline]
    fn wire_valid(&self) -> Result<(), InvalidStructureError> {
        match self {
            // The bytes came from a view, which cannot exist over an invalid encoding.
            ResolvedPath::Static(_) => Ok(()),
            ResolvedPath::Hummingbird(path) => path.wire_valid(),
        }
    }

    #[inline]
    unsafe fn encode_unchecked(&self, buf: &mut [u8]) -> usize {
        match self {
            ResolvedPath::Static(view) => {
                let bytes = view.as_slice();
                // SAFETY: the caller guarantees buf.len() >= required_size(), which is bytes.len()
                unsafe { buf.get_unchecked_mut(..bytes.len()) }.copy_from_slice(bytes);
                bytes.len()
            }
            // SAFETY: the caller guarantees buf.len() >= required_size(), which is encoded_len()
            ResolvedPath::Hummingbird(path) => unsafe { path.encode_unchecked(buf) },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        address::{addr::ScionAddr, ip_addr::ScionIpAddr},
        core::model::Model,
        dataplane_path::{
            model::DpPath,
            standard::{
                model::{HopField, InfoField, Segment, StandardPath},
                types::{HopFieldMac, InfoFieldFlags},
            },
            view::ScionDpPathView,
        },
    };

    fn standard_view() -> ScionDpPathView {
        let path = StandardPath {
            current_info_field: 0,
            current_hop_field: 0,
            segments: [Segment {
                info_field: InfoField {
                    flags: InfoFieldFlags::CONS_DIR,
                    segment_id: 1,
                    timestamp: 1_700_000_000,
                },
                hop_fields: [
                    HopField {
                        flags: Default::default(),
                        expiration_units: 63,
                        cons_ingress: 0,
                        cons_egress: 1,
                        mac: HopFieldMac::zero(),
                    },
                    HopField {
                        flags: Default::default(),
                        expiration_units: 63,
                        cons_ingress: 2,
                        cons_egress: 0,
                        mac: HopFieldMac::zero(),
                    },
                ]
                .into_iter()
                .collect(),
            }]
            .into_iter()
            .collect(),
        };
        ScionDpPathView::Standard(path.try_encode_to_owned_view().expect("encodes"))
    }

    fn frame(exterior_len: u16) -> PacketFrame {
        PacketFrame {
            dst_ia: IsdAsn::WILDCARD,
            exterior_len,
            now: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn resolving_a_standard_path_borrows_its_bytes() {
        let view = standard_view();
        let resolved =
            ResolvedPath::resolve_static(view.as_ref(), frame(100)).expect("standard resolves");

        assert_eq!(resolved.required_size(), view.as_slice().len());
    }

    #[test]
    fn required_size_is_stable_across_calls() {
        // The property the whole seam exists for: an encoder sizes a buffer with one call and
        // fills it after another, and an answer that shrank in between is documented UB.
        let view = standard_view();
        let resolved =
            ResolvedPath::resolve_static(view.as_ref(), frame(100)).expect("standard resolves");

        let first = resolved.required_size();
        assert_eq!(first, resolved.required_size());
        assert_eq!(first, resolved.required_size());
    }

    #[test]
    fn a_resolved_path_encodes_to_the_original_bytes() {
        let view = standard_view();
        let resolved =
            ResolvedPath::resolve_static(view.as_ref(), frame(100)).expect("standard resolves");

        let mut buf = vec![0u8; resolved.required_size()];
        let written = resolved.try_encode(&mut buf).expect("encodes");

        assert_eq!(written, view.as_slice().len());
        assert_eq!(buf, view.as_slice());
    }

    #[test]
    fn packet_len_adds_the_path_to_the_exterior() {
        let view = standard_view();
        let f = frame(100);
        let resolved = ResolvedPath::resolve_static(view.as_ref(), f).expect("standard resolves");

        assert_eq!(
            resolved.packet_len(f) as usize,
            100 + view.as_slice().len(),
            "the packet length a MAC covers is the exterior plus the resolved path"
        );
    }

    #[test]
    fn a_packet_too_long_to_encode_is_rejected() {
        // The path alone is fine; it is the packet around it that cannot be expressed. Catching
        // this at resolution keeps it out of the encoder, where the length field would silently
        // wrap.
        let view = standard_view();
        let err = ResolvedPath::resolve_static(view.as_ref(), frame(u16::MAX))
            .expect_err("an oversized packet must not resolve");

        assert!(matches!(err, PathResolveError::PacketTooLong(_)));
    }

    #[test]
    fn resolution_reports_the_path_type_it_resolved() {
        let view = standard_view();
        let resolved =
            ResolvedPath::resolve_static(view.as_ref(), frame(100)).expect("standard resolves");

        assert_eq!(PacketPath::path_type(&resolved), PathType::Scion);
        assert_eq!(
            PacketPath::path_type(&ResolvedPath::Static(ScionDpPathViewRef::Empty)),
            PathType::Empty
        );
    }

    #[test]
    fn a_received_hummingbird_path_resolves_as_static() {
        // Its bytes came off the wire and are already fixed; resolution is the identity. A
        // *sendable* Hummingbird path is a different thing — a standard path plus an overlay —
        // and resolves through a different arm once the overlay exists.
        let hbird = DpPath::Hummingbird(crate::dataplane_path::hbird::model::HummingbirdPath {
            current_info_field: 0,
            current_hop_field: 0,
            segments: vec![crate::dataplane_path::hbird::model::HbirdSegment {
                info_field: InfoField {
                    flags: InfoFieldFlags::CONS_DIR,
                    segment_id: 1,
                    timestamp: 1_700_000_000,
                },
                hop_fields: [crate::dataplane_path::hbird::model::HbirdHopField::Flyover(
                    crate::dataplane_path::hbird::model::FlyoverHopField {
                        flags: Default::default(),
                        expiration_units: 63,
                        cons_ingress: 0,
                        cons_egress: 1,
                        mac: HopFieldMac::zero(),
                        res_id: 5,
                        bw: 10,
                        res_start_offset: 0,
                        res_duration: 60,
                    },
                )]
                .into_iter()
                .collect(),
            }],
            base_timestamp: 1_700_000_000,
            millis_timestamp: 0,
            counter: 0,
        });
        let view = hbird.try_encode_to_owned_view().expect("encodes");

        let resolved = ResolvedPath::resolve_static(view.as_ref(), frame(100)).expect("resolves");

        assert_eq!(PacketPath::path_type(&resolved), PathType::Hummingbird);
        assert_eq!(resolved.required_size(), view.as_slice().len());
        assert_eq!(resolved.required_size(), resolved.required_size());
    }

    #[test]
    fn build_produces_the_same_bytes_as_constructing_the_packet_directly() {
        // The seam must be a pure refactor for paths that do not vary per packet: whatever the
        // socket produced before, `build` must produce byte for byte.
        use crate::{
            address::socket_addr::ScionSocketAddr, packet::model::ScionUdpPacket, path::ScionPath,
        };

        let src = ScionSocketAddr::V4(crate::address::socket_addr::ScionSocketAddrV4 {
            isd_asn: IsdAsn::WILDCARD,
            host: "127.0.0.1".parse().unwrap(),
            port: 1000,
        });
        let dst = ScionSocketAddr::V4(crate::address::socket_addr::ScionSocketAddrV4 {
            isd_asn: IsdAsn::WILDCARD,
            host: "127.0.0.2".parse().unwrap(),
            port: 2000,
        });
        let payload = b"hello hummingbird".to_vec();

        let view = standard_view();
        let scion_path = ScionPath::new(
            IsdAsn::WILDCARD,
            IsdAsn::WILDCARD,
            standard_view(),
            None,
            None,
        );

        let direct = ScionUdpPacket::new(src, dst, view.to_model(), payload.clone());
        let mut expected = vec![0u8; direct.required_size()];
        direct.try_encode(&mut expected).expect("encodes");

        let built = ScionUdpPacket::build(src, dst, &scion_path, payload, SystemTime::UNIX_EPOCH)
            .expect("resolves");
        let actual = built.try_encode_to_raw().expect("encodes");

        assert_eq!(actual, expected);
    }

    #[test]
    fn a_frame_measures_everything_but_the_path() {
        let address = AddressHeader::new(
            ScionAddr::from(ScionIpAddr::new(
                IsdAsn::WILDCARD,
                "127.0.0.1".parse().unwrap(),
            )),
            ScionAddr::from(ScionIpAddr::new(
                IsdAsn::WILDCARD,
                "127.0.0.2".parse().unwrap(),
            )),
        );
        let f = PacketFrame::new(&address, 42, SystemTime::UNIX_EPOCH);

        assert_eq!(
            f.exterior_len as usize,
            CommonHeaderLayout::SIZE_BYTES + address.required_size() + 42
        );
        assert_eq!(f.dst_ia, address.dst_ia);
    }
}
