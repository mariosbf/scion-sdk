// Copyright 2025 Mysten Labs
// Copyright 2025 Anapaya Systems
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

//! SCION path types.
//!
//! This module contains types for SCION paths and metadata as well as encoding and decoding
//! functions.
//!
//! # Organisation
//!
//! - [`Path`] is the primary path type used with SCION sockets and applications. It encapsulates a
//!   [datplane path][DataPlanePath] along with optional metadata about that path, such as its
//!   source and destination ASes, next hop on the SCION underlay, expiry time, and interface hops.
//!
//! - [`Metadata`] is metadata about a SCION [`Path`] that is communicated during beaconing or
//!   parsed from the path.
//!
//! - [`DataPlanePath`] represents the various SCION paths that be placed within a SCION packet, and
//!   sent on the network. Currently, only the empty and standard SCION datplane path types are
//!   supported (see [`standard`]).
//!
//! - [`StandardPath`] is a structure representation of a SCION path that can be used to create or
//!   modify SCION paths.

use std::{net::SocketAddr, ops::Deref};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use scion_protobuf::daemon::v1 as daemon_grpc;
use tracing::warn;

use crate::{
    address::IsdAsn,
    hummingbird::Reservation,
    packet::{ByEndpoint, DecodeError, NonEncodeError, NonScmpEncodeError},
    path::hummingbird::{HummingbirdPath, HummingbirdPathError},
    wire_encoding::WireDecode,
};

mod error;
pub use error::{DataPlanePathErrorKind, PathParseError, PathParseErrorKind};

mod data_plane;
pub use data_plane::{DataPlanePath, PathType, UnsupportedPathType};

pub mod standard;
pub use standard::*;

pub mod segment;
pub use segment::*;

pub mod encoded;
pub use encoded::*;

pub mod convert;

pub mod epic;
pub use epic::EpicAuths;

pub mod combinator;
pub mod policy;

mod fingerprint;
pub use fingerprint::{FingerprintError, PathFingerprint};

mod dataplane_fingerprint;
pub use dataplane_fingerprint::DataPlanePathFingerprint;

mod metadata;
pub use metadata::{GeoCoordinates, LinkType, Metadata, PathInterface};

mod meta_header;
pub use meta_header::{HopFieldIndex, InfoFieldIndex, MetaHeader, MetaReserved, SegmentLength};

pub mod crypto;
pub mod test_builder;

/// Signed-message helpers for authenticated payloads.
pub mod signed_message;

pub mod hummingbird;

/// Minimum MTU along any path or within any AS.
pub const PATH_MIN_MTU: u16 = 1280;

/// A SCION end-to-end path with optional metadata.
///
/// `Path`s are generic over the underlying representation used by the [`DataPlanePath`]. By
/// default, this is a [`Bytes`] object which allows relatively cheap copying of the overall path
/// as the Path data can then be shared across several `Path` instances.
#[derive(Clone)]
pub struct Path<T = Bytes> {
    /// The raw bytes to be added as the path header to SCION data plane packets.
    pub data_plane_path: DataPlanePath<T>,
    /// The underlay address (IP + port) of the next hop; i.e., the local border router.
    pub underlay_next_hop: Option<SocketAddr>,
    /// The ISD-ASN where the path starts and ends.
    pub isd_asn: ByEndpoint<IsdAsn>,
    /// Path metadata.
    pub metadata: Option<Metadata>,
}

impl<T> std::fmt::Debug for Path<T>
where
    T: Deref<Target = [u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.data_plane_path {
            DataPlanePath::EmptyPath => {
                write!(
                    f,
                    "EmptyPath: {} -> {}",
                    self.isd_asn.source, self.isd_asn.destination
                )
            }
            DataPlanePath::Unsupported { .. } => {
                write!(
                    f,
                    "UnsupportedPath: {} -> {}",
                    self.isd_asn.source, self.isd_asn.destination
                )
            }
            DataPlanePath::Standard(_) => {
                if let Some(metadata) = &self.metadata {
                    write!(f, "StandardPath Hops: ")?;
                    metadata.format_interfaces(f)?;
                    write!(f, " MTU: {}", metadata.mtu)
                } else {
                    write!(
                        f,
                        "StandardPath: {} -> {} (no metadata)",
                        self.isd_asn.source, self.isd_asn.destination
                    )
                }
            }
            DataPlanePath::Hummingbird(_) => {
                // TODO: Potentially replace with something more useful.
                if let Some(metadata) = &self.metadata {
                    write!(f, "HummingbirdPath Hops: ")?;
                    metadata.format_interfaces(f)?;
                    write!(f, " MTU: {}", metadata.mtu)
                } else {
                    write!(
                        f,
                        "HummingbirdPath: {} -> {} (no metadata)",
                        self.isd_asn.source, self.isd_asn.destination
                    )
                }
            }
        }
    }
}

impl<T> Path<T>
where
    T: Deref<Target = [u8]>,
{
    /// Creates a new `Path` instance with the provided data plane path, its endpoints, and the
    /// next hop in the network underlay, but with no metadata.
    pub fn new(
        data_plane_path: DataPlanePath<T>,
        isd_asn: ByEndpoint<IsdAsn>,
        underlay_next_hop: Option<SocketAddr>,
    ) -> Self {
        Self {
            data_plane_path,
            underlay_next_hop,
            isd_asn,
            metadata: None,
        }
    }

    /// Returns a path for sending packets within the specified AS.
    ///
    /// # Panics
    ///
    /// Panics if the AS is a wildcard AS.
    pub fn local(isd_asn: IsdAsn) -> Self {
        assert!(!isd_asn.is_wildcard(), "no local path for wildcard AS");

        Self {
            data_plane_path: DataPlanePath::EmptyPath,
            underlay_next_hop: None,
            isd_asn: ByEndpoint::with_cloned(isd_asn),
            metadata: Some(Metadata {
                expiration: DateTime::<Utc>::MAX_UTC,
                mtu: PATH_MIN_MTU,
                interfaces: None,
                ..Metadata::default()
            }),
        }
    }

    /// Returns the source of this path.
    pub const fn source(&self) -> IsdAsn {
        self.isd_asn.source
    }

    /// Returns the destination of this path.
    pub const fn destination(&self) -> IsdAsn {
        self.isd_asn.destination
    }

    /// Creates a new empty path with the provided source and destination ASes.
    ///
    /// For creating an empty, AS-local path see [`local()`][Self::local] instead.
    pub fn empty(isd_asn: ByEndpoint<IsdAsn>) -> Self {
        Self {
            data_plane_path: DataPlanePath::EmptyPath,
            underlay_next_hop: None,
            isd_asn,
            metadata: None,
        }
    }

    /// Returns true iff the data plane path is an empty path.
    pub fn is_empty(&self) -> bool {
        self.data_plane_path.is_empty()
    }

    /// Returns a fingerprint of the path.
    ///
    /// See [`PathFingerprint`] for more details.
    pub fn fingerprint(&self) -> Result<PathFingerprint, FingerprintError> {
        PathFingerprint::try_from(self)
    }

    /// Returns a fingerprint based on the dataplane path.
    ///
    /// Different from [`PathFingerprint`], this can be computed, even if
    /// no metadata is present.
    ///
    /// See [`DataPlanePathFingerprint`] for more details.
    pub fn data_plane_fingerprint(&self) -> DataPlanePathFingerprint {
        DataPlanePathFingerprint::new(self)
    }

    /// Returns the expiry time of the path if the path hop fields, otherwise None.
    pub fn expiry_time(&self) -> Option<DateTime<Utc>> {
        // First check the metadata, if it exists.
        if let Some(metadata) = &self.metadata {
            return Some(metadata.expiration);
        }
        // If no metadata exists, calculate it from the data plane path.
        match &self.data_plane_path {
            DataPlanePath::EmptyPath => None,
            DataPlanePath::Standard(path) => Some(path.expiry_time()),
            DataPlanePath::Hummingbird(path) => Some(path.expiry_time()),
            DataPlanePath::Unsupported { .. } => None,
        }
    }

    /// Returns true if the path contains an expiry time, and it is after now,
    /// false if the contained expiry time is at or before now, and None if the path
    /// does not contain an expiry time.
    pub fn is_expired(&self, now: DateTime<Utc>) -> Option<bool> {
        self.expiry_time().map(|t| t <= now)
    }

    /// Sets the expiry time of the path.
    pub fn set_expiration(&mut self, expiration: DateTime<Utc>) {
        self.metadata = Some(Metadata {
            expiration,
            ..self.metadata.take().unwrap_or_default()
        });
    }

    /// Returns the number of interfaces traversed by the path, if available. Otherwise None.
    pub fn interface_count(&self) -> Option<usize> {
        self.metadata
            .as_ref()
            .and_then(|i| i.interfaces.as_ref().map(|intfs| intfs.len()))
    }

    /// Returns the first hop egress interface of the path, if available.
    pub fn first_hop_egress_interface(&self) -> Option<PathInterface> {
        match self
            .metadata
            .as_ref()
            .and_then(|m| m.interfaces.as_ref())
            .and_then(|intfs| intfs.first())
        {
            Some(intf) => Some(*intf),
            None => {
                // Extract from data plane path if possible
                match &self.data_plane_path {
                    DataPlanePath::Standard(path) => {
                        let info = path.info_fields().next()?;
                        let hf = path.hop_fields().next()?;
                        Some(PathInterface::new(
                            self.source(),
                            hf.egress_interface(info)?.into(),
                        ))
                    }
                    _ => None,
                }
            }
        }
    }

    /// Returns the last hop ingress interface of the path, if available.
    pub fn last_hop_ingress_interface(&self) -> Option<PathInterface> {
        match self
            .metadata
            .as_ref()
            .and_then(|m| m.interfaces.as_ref())
            .and_then(|intfs| intfs.iter().next_back())
        {
            Some(intf) => Some(*intf),
            None => {
                // Extract from data plane path if possible
                match &self.data_plane_path {
                    DataPlanePath::Standard(path) => {
                        let info = path.info_fields().next_back()?;
                        let hf = path.hop_fields().next_back()?;
                        Some(PathInterface::new(
                            self.destination(),
                            hf.ingress_interface(info)?.into(),
                        ))
                    }
                    _ => None,
                }
            }
        }
    }

    /// Returns the ASes traversed by the path, if available.
    pub fn ases(&self) -> Option<Vec<IsdAsn>> {
        self.metadata.as_ref().and_then(|m| {
            m.interfaces.as_ref().map(|intfs| {
                intfs
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| {
                        // Except for the first and last AS, every AS appears
                        // twice in the interfaces list (once as ingress and once
                        // as egress). Here, we skip the entries corresponding
                        // to egress interfaces.
                        *i == 0 || *i % 2 == 1
                    })
                    .map(|(_, intf)| intf.isd_asn)
                    .collect()
            })
        })
    }

    /// Returns the hops along the path that can be reversed, if necessary
    /// metadata is available.
    pub fn reservable_hops(&self) -> Option<Vec<(u8, IsdAsn, u16, u16)>> {
        // TODO (mariosbf): might be wrong when using peering links
        let mut result = vec![];

        let path = if let DataPlanePath::Standard(p) = &self.data_plane_path {
            p
        } else {
            return None;
        };

        // Iterate over interfaces in pairs of two
        let mut interfaces = vec![PathInterface {
            isd_asn: self.source(),
            id: 0,
        }];

        interfaces.extend(self.metadata.as_ref()?.interfaces.as_ref()?.clone());

        interfaces.push(PathInterface {
            isd_asn: self.destination(),
            id: 0,
        });

        let mut iface_iter = interfaces.chunks(2).peekable();

        for (hop_idx, (info_field, hop)) in path
            .segments()
            .zip(path.info_fields())
            .flat_map(|(s, i)| s.hop_fields().map(move |h| (i, h)))
            .enumerate()
        {
            let Some([ingress, egress]) = iface_iter.peek() else {
                break;
            };

            let hop_egress = hop.egress_interface(info_field).map(u16::from).unwrap_or(0);
            let hop_ingress = hop
                .ingress_interface(info_field)
                .map(u16::from)
                .unwrap_or(0);

            if ingress.id == hop_ingress && egress.id == hop_egress || hop_ingress == 0 {
                iface_iter.next();
            }

            if (ingress.id == hop_ingress && egress.id == hop_egress) || hop_egress == 0 {
                result.push((hop_idx as u8, ingress.isd_asn, ingress.id, egress.id));
            }
        }

        Some(result)
    }

    /// Returns the hop index that `reservation` applies to on this path, if any.
    ///
    /// A reservation applies to a hop when the reservation's ISD-AS, ingress interface, and
    /// egress interface match that hop's, as computed by [`Self::reservable_hops`]. Returns
    /// `None` if no hop matches, or if `reservable_hops` itself returns `None` (e.g. the path is
    /// not a standard path, or metadata is unavailable).
    pub fn reservation_hop_index(&self, reservation: &Reservation) -> Option<u8> {
        self.reservable_hops()?
            .into_iter()
            .find(|&(_, isd_asn, ingress, egress)| {
                isd_asn == reservation.info.isd_as
                    && ingress == reservation.info.ingress_interface
                    && egress == reservation.info.egress_interface
            })
            .map(|(hop_idx, ..)| hop_idx)
    }
}

/// Error returned when applying reservations to a path fails.
#[derive(thiserror::Error, Debug)]
pub enum HummingbirdConversionError {
    /// Path type is not supported for adding reservations.
    #[error("unsupported path type")]
    UnsupportedPathType,
    /// Failed to decode underlying data plan path.
    #[error("failed to decode underlying data plane path")]
    DecodeError(#[from] DecodeError),
    /// Error in path Hummingbird path builder.
    #[error("failed to add reservation to path: {0}")]
    HummingbirdPathBuilderError(#[from] HummingbirdPathError),
}

impl Path<Bytes> {
    /// Apply reservation to path.
    ///
    /// The behaviour of this function depends on the current underlying path
    /// type.
    /// - Empty paths: left unchanged.
    /// - Standard paths: decoded, converted to Hummingbird paths, have the reservations applied,
    ///   and then re-encoded as Hummingbird paths.
    /// - Hummingbird paths: similar to standard paths, but the timestamp and counter
    ///   of the original path are used in the new path to avoid invalidating existing
    ///   flyover MACs.
    ///
    /// Parameters:
    /// - `reservations`: the reservations to apply to the path.
    /// - `payload_len`: the length of the payload contained in the packet
    ///   (number of bytes). Used for flyover MAC calculations.
    /// - `address_header_len`: the length of the address header (number of bytes). Used for
    ///   flyover MAC calculations.
    pub fn with_reservations(
        self,
        reservations: impl IntoIterator<Item = Reservation>,
        payload_len: u16,
        address_header_len: u16,
    ) -> Result<Self, HummingbirdConversionError> {
        let mut hbird_path = self.to_hbird()?;

        for r in reservations {
            hbird_path.try_add_reservation(r);
        }

        let encoded_p =
            hbird_path.to_encoded(self.isd_asn.destination, payload_len, address_header_len)?;
        let data_plane_path = DataPlanePath::Hummingbird(encoded_p);

        Ok(Self {
            data_plane_path,
            underlay_next_hop: self.underlay_next_hop,
            isd_asn: self.isd_asn,
            metadata: self.metadata,
        })
    }

    /// Converts the path to a Hummingbird path.
    ///
    /// If the underlying path is a standard path or an encoded Hummingbird path,
    /// the interface information from the path metadata (see [`Metadata`]
    /// [`PathInterface`]) is used to determine each hop's ISD-AS, if available.
    /// Hops whose ISD-AS cannot be determined are left without one.
    ///
    /// If the underlying path is of type `Unsupported`, then the conversion
    /// will fail.
    pub fn to_hbird(&self) -> Result<HummingbirdPath, HummingbirdConversionError> {
        match &self.data_plane_path {
            DataPlanePath::EmptyPath => Ok(HummingbirdPath::new()),
            DataPlanePath::Standard(p) => {
                let ifaces = self
                    .metadata
                    .as_ref()
                    .and_then(|m| m.interfaces.as_deref())
                    .unwrap_or(&[]);

                let standard_path: StandardPath = p.clone().try_into()?;
                Ok(standard_path.to_hbird(ifaces))
            }
            DataPlanePath::Hummingbird(p) => {
                let ases = self.ases().unwrap_or_default();
                let mut bytes = p.encoded_path.clone();
                Ok(HummingbirdPath::decode(&mut bytes, &ases)?)
            }
            DataPlanePath::Unsupported {
                path_type: _,
                bytes: _,
            } => Err(HummingbirdConversionError::UnsupportedPathType),
        }
    }
}

impl<T> Path<T>
where
    T: Deref<Target = [u8]>,
{
    /// Returns a new `Path` reversing `data_plane_path` and `isd_asn`
    /// using given `buf` as backing storage for the `data_plane_path`
    ///
    /// # Panics
    ///
    /// Panics if `buf` has insufficient length. This can be prevented by ensuring a buffer size
    /// of at least [`DataPlanePath::MAX_LEN`].
    pub fn reverse_to_slice(self, buf: &mut [u8]) -> Path<&mut [u8]> {
        let path_len = self.data_plane_path.raw().len();
        let data_plane_path = self.data_plane_path.reverse_to_slice(&mut buf[..path_len]);

        Path::new(
            data_plane_path,
            self.isd_asn.into_reversed(),
            self.underlay_next_hop,
        )
    }

    /// Returns a new `Path` reversing `data_plane_path`, `isd_asn`, and the `interfaces` list
    /// in the metadata (if present). Other metadata fields are copied as-is.
    pub fn to_reversed(&self) -> Result<Path, UnsupportedPathType> {
        let mut path = Path::new(
            self.data_plane_path.to_reversed()?,
            self.isd_asn.into_reversed(),
            self.underlay_next_hop,
        );
        path.metadata = self.metadata.as_ref().map(|m| Metadata {
            interfaces: m.interfaces.clone().map(|mut v| {
                v.reverse();
                v
            }),
            ..Metadata::default()
        });
        Ok(path)
    }
}

impl Path<Bytes> {
    /// Attempts to parse the GRPC representation of a path into a [`Path`].
    #[tracing::instrument]
    pub fn try_from_grpc(
        mut value: daemon_grpc::Path,
        isd_asn: ByEndpoint<IsdAsn>,
    ) -> Result<Self, PathParseError> {
        let mut data_plane_path = Bytes::from(std::mem::take(&mut value.raw));
        if data_plane_path.is_empty() {
            return if isd_asn.are_equal() && isd_asn.destination.is_wildcard() {
                Ok(Path::empty(isd_asn))
            } else if isd_asn.are_equal() {
                Ok(Path::local(isd_asn.destination))
            } else {
                Err(PathParseErrorKind::EmptyRaw.into())
            };
        };
        let data_plane_path = encoded::EncodedStandardPath::decode(&mut data_plane_path)
            .map_err(|_| PathParseError::from(PathParseErrorKind::InvalidRaw))?
            .into();

        let underlay_next_hop = match &value.interface {
            Some(daemon_grpc::Interface {
                address: Some(daemon_grpc::Underlay { address }),
            }) => address
                .parse()
                .map_err(|_| PathParseError::from(PathParseErrorKind::InvalidInterface))?,
            // TODO: Determine if the daemon returns paths that are strictly on the host.
            // If so, this is only an error if the path is non-empty
            _ => return Err(PathParseErrorKind::NoInterface.into()),
        };
        let underlay_next_hop = Some(underlay_next_hop);

        let metadata = Metadata::try_from(value)
            .map_err(|e| {
                tracing::warn!("{}", e);
                e
            })
            .ok();

        Ok(Self {
            data_plane_path,
            underlay_next_hop,
            isd_asn,
            metadata,
        })
    }

    /// Creates a new Path using the given path's bytes as backing storage
    pub fn to_slice_path(&self) -> Path<&[u8]> {
        Path {
            data_plane_path: self.data_plane_path.to_slice_path(),
            underlay_next_hop: self.underlay_next_hop,
            isd_asn: self.isd_asn,
            metadata: self.metadata.clone(),
        }
    }
}

impl<T: AsRef<[u8]>> Path<T> {
    /// Transforms the path to be backed by [`Bytes`].
    pub fn to_bytes_path(&self) -> Path<Bytes> {
        Path {
            data_plane_path: self.data_plane_path.to_bytes_path(),
            underlay_next_hop: self.underlay_next_hop,
            isd_asn: self.isd_asn,
            metadata: self.metadata.clone(),
        }
    }
}

impl<T> PartialEq for Path<T>
where
    T: Deref<Target = [u8]>,
{
    fn eq(&self, other: &Self) -> bool {
        self.data_plane_path == other.data_plane_path
            && self.underlay_next_hop == other.underlay_next_hop
            && self.isd_asn == other.isd_asn
            && self.metadata == other.metadata
    }
}

impl<T> std::fmt::Display for Path<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "src:{}, dst:{}, next hop: {}, MTU: {}, path: ",
            self.isd_asn.source,
            self.isd_asn.destination,
            self.underlay_next_hop
                .map_or_else(|| "none".to_string(), |a| a.to_string()),
            self.metadata
                .as_ref()
                .map_or_else(|| "none".to_string(), |m| m.mtu.to_string()),
        )?;

        match self.metadata.as_ref() {
            Some(meta) => meta.format_interfaces(f)?,
            None => write!(f, "<no metadata>")?,
        };

        Ok(())
    }
}

/// Builds a [`Path`] for use in a SCION packet, potentially applying a reservation.
pub trait PathProvider {
    /// Error type returned when building the path fails.
    type Error: NonEncodeError + NonScmpEncodeError + Send;

    /// Builds a Path instance.
    fn build(
        &self,
        isd_asn: ByEndpoint<IsdAsn>,
        payload_len: u16,
        address_header_len: u16,
    ) -> Result<Path, Self::Error>;
}

impl<T: AsRef<[u8]>> PathProvider for Path<T> {
    type Error = std::convert::Infallible;

    fn build(
        &self,
        _isd_asn: ByEndpoint<IsdAsn>,
        _payload_len: u16,
        _address_header_len: u16,
    ) -> Result<Path, Self::Error> {
        Ok(self.to_bytes_path())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::path::metadata::{PathInterface, test_utils::*};

    #[test]
    fn successful_empty_path() {
        let path = Path::try_from_grpc(
            daemon_grpc::Path {
                raw: vec![],
                ..minimal_grpc_path()
            },
            ByEndpoint {
                source: IsdAsn::WILDCARD,
                destination: IsdAsn::WILDCARD,
            },
        )
        .expect("conversion should succeed");
        assert!(path.underlay_next_hop.is_none());
        assert!(path.metadata.is_none());
        assert!(path.data_plane_path.is_empty());
        assert_eq!(
            path.isd_asn,
            ByEndpoint {
                source: IsdAsn::WILDCARD,
                destination: IsdAsn::WILDCARD,
            }
        );
    }

    #[test]
    fn successful_conversion() {
        let path = Path::try_from_grpc(
            minimal_grpc_path(),
            ByEndpoint {
                source: IsdAsn::WILDCARD,
                destination: IsdAsn::WILDCARD,
            },
        )
        .expect("conversion should succeed");
        assert_eq!(
            path.underlay_next_hop.unwrap(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 42)
        );
        assert_eq!(
            path.isd_asn,
            ByEndpoint {
                source: IsdAsn::WILDCARD,
                destination: IsdAsn::WILDCARD,
            }
        );
        assert_eq!(
            path.metadata,
            Some(Metadata {
                interfaces: Some(vec![
                    PathInterface {
                        isd_asn: IsdAsn::WILDCARD,
                        id: 0,
                    };
                    2
                ]),
                internal_hops: Some(vec![]),
                ..Default::default()
            })
        );
    }

    macro_rules! test_conversion_failure {
        ($name:ident; $($field:ident : $value:expr),* ; $error:expr) => {
            #[test]
            fn $name() {
                assert_eq!(
                    Path::try_from_grpc(
                        daemon_grpc::Path {
                            $($field : $value,)*
                            ..minimal_grpc_path()
                        },
                        ByEndpoint {
                            source: "1-1".parse().unwrap(),
                            destination: "1-2".parse().unwrap(),
                        },
                    ),
                    Err($error)
                )
            }
        };
    }

    test_conversion_failure!(
        empty_raw_path_different_ases;
        raw: vec![];
        PathParseErrorKind::EmptyRaw.into()
    );
    test_conversion_failure!(no_interface; interface: None; PathParseErrorKind::NoInterface.into());
    test_conversion_failure!(
        invalid_interface;
        interface: Some(daemon_grpc::Interface {
            address: Some(daemon_grpc::Underlay {
                address: "invalid address".into(),
            }),
        });
        PathParseErrorKind::InvalidInterface.into()
    );

    #[test]
    fn reservable_hops_only_down_segment() {
        use crate::address::{Asn, EndhostAddr, Isd, IsdAsn};
        use crate::path::test_builder::TestPathBuilder;

        let src = EndhostAddr::new(IsdAsn::new(Isd(1), Asn(110)), [127, 0, 0, 1].into());
        let dst = EndhostAddr::new(IsdAsn::new(Isd(1), Asn(114)), [127, 0, 0, 1].into());

        let ctx = TestPathBuilder::new(src.into(), dst.into())
            .down()
            .with_asn(110)
            .add_hop(0, 1)
            .with_asn(111)
            .add_hop(1, 2)
            .with_asn(114)
            .add_hop(1, 0)
            .build(1000);

        let path = ctx.path();

        let hops = path
            .reservable_hops()
            .expect("path should expose reservable hops");

        let asn = |n: u64| IsdAsn::new(Isd(1), Asn(n));

        assert_eq!(
            hops,
            vec![
                (0, asn(110), 0, 1), // server: first hop of the return trip
                (1, asn(111), 1, 2), // transit AS, same on both directions
                (2, asn(114), 1, 0), // client: last hop of the return trip
            ]
        );
    }

    #[test]
    fn reservable_hops_only_up_segment() {
        use crate::address::{Asn, EndhostAddr, Isd, IsdAsn};
        use crate::path::test_builder::TestPathBuilder;

        let src = EndhostAddr::new(IsdAsn::new(Isd(1), Asn(114)), [127, 0, 0, 1].into());
        let dst = EndhostAddr::new(IsdAsn::new(Isd(1), Asn(110)), [127, 0, 0, 1].into());

        let ctx = TestPathBuilder::new(src.into(), dst.into())
            .up()
            .with_asn(114)
            .add_hop(0, 1)
            .with_asn(111)
            .add_hop(2, 1)
            .with_asn(110)
            .add_hop(1, 0)
            .build(1000);

        let path = ctx.path();

        let hops = path
            .reservable_hops()
            .expect("path should expose reservable hops");

        let asn = |n: u64| IsdAsn::new(Isd(1), Asn(n));

        assert_eq!(
            hops,
            vec![
                (0, asn(114), 0, 1),
                (1, asn(111), 2, 1),
                (2, asn(110), 1, 0),
            ]
        );
    }

    #[test]
    fn reservable_hops_up_and_down_segment() {
        use crate::address::{Asn, EndhostAddr, Isd, IsdAsn};
        use crate::path::test_builder::TestPathBuilder;

        let src = EndhostAddr::new(IsdAsn::new(Isd(1), Asn(110)), [127, 0, 0, 1].into());
        let dst = EndhostAddr::new(IsdAsn::new(Isd(1), Asn(112)), [127, 0, 0, 1].into());

        let ctx = TestPathBuilder::new(src.into(), dst.into())
            .using_info_timestamp(42)
            .up()
            .with_asn(110)
            .add_hop(0, 1)
            .with_asn(111)
            .add_hop(1, 0)
            .down()
            .with_asn(111)
            .add_hop(0, 2)
            .with_asn(112)
            .add_hop(1, 0)
            .build(1000);

        let path = ctx.path();

        let hops = path
            .reservable_hops()
            .expect("path should expose reservable hops");

        let asn = |n: u64| IsdAsn::new(Isd(1), Asn(n));

        assert_eq!(
            hops,
            vec![
                (0, asn(110), 0, 1),
                (1, asn(111), 1, 2),
                (3, asn(112), 1, 0),
            ]
        );
    }

    fn reservation_for(
        isd_as: IsdAsn,
        ingress_interface: u16,
        egress_interface: u16,
    ) -> Reservation {
        use crate::{
            hummingbird::{Bandwidth, ReservationInfo},
            path::hummingbird::HbirdAuthKey,
        };

        Reservation {
            info: ReservationInfo {
                isd_as,
                ingress_interface,
                egress_interface,
                res_id: 42,
                bandwidth: Bandwidth::from_bytes_per_sec(64).unwrap(),
                start: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                duration: 600,
            },
            reservation_key: HbirdAuthKey::from([0xABu8; 16]),
        }
    }

    #[test]
    fn reservation_hop_index_matches_hop() {
        use crate::address::{Asn, EndhostAddr, Isd, IsdAsn};
        use crate::path::test_builder::TestPathBuilder;

        let src = EndhostAddr::new(IsdAsn::new(Isd(1), Asn(110)), [127, 0, 0, 1].into());
        let dst = EndhostAddr::new(IsdAsn::new(Isd(1), Asn(112)), [127, 0, 0, 1].into());

        let ctx = TestPathBuilder::new(src.into(), dst.into())
            .using_info_timestamp(42)
            .up()
            .with_asn(110)
            .add_hop(0, 1)
            .with_asn(111)
            .add_hop(1, 0)
            .down()
            .with_asn(111)
            .add_hop(0, 2)
            .with_asn(112)
            .add_hop(1, 0)
            .build(1000);

        let path = ctx.path();

        let asn = |n: u64| IsdAsn::new(Isd(1), Asn(n));

        // Matches the transit hop: (1, asn(111), 1, 2).
        let reservation = reservation_for(asn(111), 1, 2);
        assert_eq!(path.reservation_hop_index(&reservation), Some(1));

        // Matches the last hop: (3, asn(112), 1, 0).
        let reservation = reservation_for(asn(112), 1, 0);
        assert_eq!(path.reservation_hop_index(&reservation), Some(3));
    }

    #[test]
    fn reservation_hop_index_no_match() {
        use crate::address::{Asn, EndhostAddr, Isd, IsdAsn};
        use crate::path::test_builder::TestPathBuilder;

        let src = EndhostAddr::new(IsdAsn::new(Isd(1), Asn(110)), [127, 0, 0, 1].into());
        let dst = EndhostAddr::new(IsdAsn::new(Isd(1), Asn(112)), [127, 0, 0, 1].into());

        let ctx = TestPathBuilder::new(src.into(), dst.into())
            .using_info_timestamp(42)
            .up()
            .with_asn(110)
            .add_hop(0, 1)
            .with_asn(111)
            .add_hop(1, 0)
            .down()
            .with_asn(111)
            .add_hop(0, 2)
            .with_asn(112)
            .add_hop(1, 0)
            .build(1000);

        let path = ctx.path();

        let asn = |n: u64| IsdAsn::new(Isd(1), Asn(n));

        // Right AS, wrong interfaces.
        let reservation = reservation_for(asn(111), 9, 9);
        assert_eq!(path.reservation_hop_index(&reservation), None);

        // AS not on the path at all.
        let reservation = reservation_for(asn(999), 1, 2);
        assert_eq!(path.reservation_hop_index(&reservation), None);
    }
}
