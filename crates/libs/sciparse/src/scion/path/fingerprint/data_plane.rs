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

//! SCION path fingerprinting based on the dataplane path.
//!
//! This module provides the [DpPathFingerprint] type, which uniquely identifies a SCION path based
//! on the sequence of interfaces traversed.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::{
    dataplane_path::{
        types::PathType,
        view::{ScionDpPathViewExt, ScionDpPathViewRef},
    },
    identifier::isd_asn::IsdAsn,
    path::ScionPath,
};

/// A fingerprint for a SCION path, derived from the dataplane path.
///
/// Different from [`PathFingerprint`](super::control_plane::PathFingerprint), this fingerprint is
/// computed solely based on data available on the dataplane path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DpPathFingerprint([u8; DpPathFingerprint::LENGTH]);
impl DpPathFingerprint {
    const LENGTH: usize = 32;
    const DISPLAYED_BYTES: usize = 8;

    /// Returns a unique fingerprint for the provided path.
    ///
    /// Fields like expiration time, or MACs are not included in the fingerprint. Allowing these
    /// fields to differ without affecting the fingerprint.
    ///
    /// The fingerprint is computed by hashing the path type, src and dst AS and the sequence of hop
    /// field interfaces. As the sequence of interfaces is unique for each path, the resulting
    /// fingerprint is also unique for each path.
    ///
    /// For unsupported path types, the fingerprint is computed by hashing the path type, src and
    /// dst AS and the raw path data.
    #[inline]
    pub fn from_scion_path(path: &ScionPath) -> DpPathFingerprint {
        Self::from_dp_path(path.dp_path.as_ref(), path.src_ia, path.dst_ia)
    }

    /// Returns a unique fingerprint for the provided path.
    ///
    /// Fields like expiration time, or MACs are not included in the fingerprint. Allowing these
    /// fields to differ without affecting the fingerprint.
    ///
    /// The fingerprint is computed by hashing the path type, src and dst AS and the sequence of hop
    /// field interfaces. As the sequence of interfaces is unique for each path, the resulting
    /// fingerprint is also unique for each path.
    ///
    /// For unsupported path types, the fingerprint is computed by hashing the path type, src and
    /// dst AS and the raw path data.
    pub fn from_dp_path(
        dp_path: ScionDpPathViewRef<'_>,
        src_ia: IsdAsn,
        dst_ia: IsdAsn,
    ) -> DpPathFingerprint {
        let mut hasher = Sha256::new();
        match dp_path {
            ScionDpPathViewRef::Empty => {
                hasher.update([u8::from(PathType::Empty)]);
                hasher.update(src_ia.to_be_bytes());
                hasher.update(dst_ia.to_be_bytes());
            }
            ScionDpPathViewRef::Standard(standard_path) => {
                hasher.update([u8::from(PathType::Scion)]);
                hasher.update(src_ia.to_be_bytes());
                hasher.update(dst_ia.to_be_bytes());
                standard_path.hop_fields().iter().for_each(|hf| {
                    hasher.update(hf.cons_ingress().to_be_bytes());
                    hasher.update(hf.cons_egress().to_be_bytes());
                });
            }
            ScionDpPathViewRef::Hummingbird(hbird_path) => {
                // Hashed exactly like a standard path but under its own path type: reservations
                // are credentials rather than route properties, so two Hummingbird paths over the
                // same interfaces fingerprint alike.
                hasher.update([u8::from(PathType::Hummingbird)]);
                hasher.update(src_ia.to_be_bytes());
                hasher.update(dst_ia.to_be_bytes());
                hbird_path.hop_fields().for_each(|hf| {
                    hasher.update(hf.cons_ingress().to_be_bytes());
                    hasher.update(hf.cons_egress().to_be_bytes());
                });
            }
            ScionDpPathViewRef::Unsupported { path_type, data } => {
                hasher.update([u8::from(path_type)]);
                hasher.update(src_ia.to_be_bytes());
                hasher.update(dst_ia.to_be_bytes());
                hasher.update(data.as_ref());
            }
            ScionDpPathViewRef::OneHop(onehop) => {
                hasher.update([u8::from(PathType::OneHop)]);
                hasher.update(src_ia.to_be_bytes());
                hasher.update(dst_ia.to_be_bytes());
                onehop.hop_fields().iter().for_each(|hf| {
                    hasher.update(hf.cons_ingress().to_be_bytes());
                    hasher.update(hf.cons_egress().to_be_bytes());
                });
            }
        }

        DpPathFingerprint(hasher.finalize().into())
    }

    /// Writes the fingerprint as lower or upper case hex, without the leading 0x.
    ///
    /// The argument n_displayed controls how many characters are written.
    #[inline]
    fn format(&self, f: &mut fmt::Formatter<'_>, n_displayed: usize, lower: bool) -> fmt::Result {
        for byte in &self.0[..n_displayed] {
            if lower {
                write!(f, "{byte:02x}")?;
            } else {
                write!(f, "{byte:02X}")?;
            }
        }

        Ok(())
    }
}
impl From<&ScionPath> for DpPathFingerprint {
    #[inline]
    fn from(path: &ScionPath) -> Self {
        Self::from_scion_path(path)
    }
}
impl AsRef<[u8]> for DpPathFingerprint {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl TryFrom<&[u8]> for DpPathFingerprint {
    type Error = std::array::TryFromSliceError;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}
impl From<[u8; 32]> for DpPathFingerprint {
    #[inline]
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}
impl fmt::Display for DpPathFingerprint {
    /// Formats the first 8 bytes of the fingerprint as a lower-case hex.
    ///
    /// The alternate flag formats the entire 32-bytes of the fingerprint.
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            self.format(f, Self::LENGTH, true)
        } else {
            self.format(f, Self::DISPLAYED_BYTES, true)
        }
    }
}
impl fmt::LowerHex for DpPathFingerprint {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        self.format(f, Self::DISPLAYED_BYTES, true)
    }
}
impl fmt::UpperHex for DpPathFingerprint {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        self.format(f, Self::DISPLAYED_BYTES, false)
    }
}

#[cfg(test)]
mod hbird_tests {
    use std::str::FromStr;

    use super::*;
    use crate::{
        core::model::Model,
        dataplane_path::{
            hbird::model::{FlyoverHopField, HbirdHopField, HbirdSegment, HummingbirdPath},
            standard::{
                model::HopField,
                types::{HopFieldMac, InfoFieldFlags},
            },
            view::ScionDpPathView,
        },
    };

    fn src() -> IsdAsn {
        IsdAsn::from_str("1-ff00:0:110").expect("valid ISD-AS")
    }

    fn dst() -> IsdAsn {
        IsdAsn::from_str("1-ff00:0:112").expect("valid ISD-AS")
    }

    /// A two-hop Hummingbird path whose first hop carries a reservation with the given id.
    fn hbird_path(interfaces: &[(u16, u16)], res_id: u32) -> HummingbirdPath {
        let hop_fields = interfaces
            .iter()
            .enumerate()
            .map(|(index, &(cons_ingress, cons_egress))| {
                if index == 0 {
                    HbirdHopField::Flyover(FlyoverHopField {
                        flags: Default::default(),
                        expiration_units: 63,
                        cons_ingress,
                        cons_egress,
                        mac: HopFieldMac::zero(),
                        res_id,
                        bw: 10,
                        res_start_offset: 0,
                        res_duration: 60,
                    })
                } else {
                    HbirdHopField::Standard(HopField {
                        flags: Default::default(),
                        expiration_units: 63,
                        cons_ingress,
                        cons_egress,
                        mac: HopFieldMac::zero(),
                    })
                }
            })
            .collect();

        HummingbirdPath {
            current_info_field: 0,
            current_hop_field: 0,
            segments: vec![HbirdSegment {
                info_field: crate::dataplane_path::standard::model::InfoField {
                    flags: InfoFieldFlags::CONS_DIR,
                    segment_id: 7,
                    timestamp: 1_700_000_000,
                },
                hop_fields,
            }],
            base_timestamp: 1_700_000_000,
            millis_timestamp: 0,
            counter: 0,
        }
    }

    fn fingerprint(view: &ScionDpPathView) -> DpPathFingerprint {
        DpPathFingerprint::from_dp_path(view.as_ref(), src(), dst())
    }

    fn hbird_view(path: HummingbirdPath) -> ScionDpPathView {
        ScionDpPathView::Hummingbird(path.try_encode_to_owned_view().expect("encodes"))
    }

    #[test]
    fn hummingbird_and_standard_paths_over_the_same_hops_fingerprint_differently() {
        // They route identically but are different path types on the wire and reverse differently,
        // so the path set must not treat them as one path.
        let path = hbird_path(&[(0, 1), (2, 0)], 5);
        let standard = ScionDpPathView::Standard(
            path.to_standard_path()
                .try_encode_to_owned_view()
                .expect("encodes"),
        );

        assert_ne!(fingerprint(&hbird_view(path)), fingerprint(&standard));
    }

    #[test]
    fn renewing_a_reservation_does_not_change_the_fingerprint() {
        // This is the property that makes the fingerprint usable for dedup: reservations are
        // credentials with their own lifetimes, and renewing one must not churn the path set.
        let interfaces = [(0, 1), (2, 0)];

        assert_eq!(
            fingerprint(&hbird_view(hbird_path(&interfaces, 5))),
            fingerprint(&hbird_view(hbird_path(&interfaces, 99_999))),
        );
    }

    #[test]
    fn a_different_route_fingerprints_differently() {
        // Guards against the above being vacuous: the interfaces must actually reach the hash.
        assert_ne!(
            fingerprint(&hbird_view(hbird_path(&[(0, 1), (2, 0)], 5))),
            fingerprint(&hbird_view(hbird_path(&[(0, 3), (4, 0)], 5))),
        );
    }

    #[test]
    fn the_endpoints_are_part_of_the_fingerprint() {
        let view = hbird_view(hbird_path(&[(0, 1), (2, 0)], 5));

        assert_ne!(
            DpPathFingerprint::from_dp_path(view.as_ref(), src(), dst()),
            DpPathFingerprint::from_dp_path(view.as_ref(), dst(), src()),
        );
    }
}
