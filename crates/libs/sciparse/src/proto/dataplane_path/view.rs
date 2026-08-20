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

//! SCION dataplane path views

use std::fmt::Display;

use crate::{
    core::{macros::impl_from, view::View},
    dataplane_path::{
        hbird::view::HbirdPathView,
        model::DpPath,
        onehop::view::OneHopPathView,
        standard::view::StandardPathView,
        types::{PathReverseError, PathType},
    },
};

/// View over a SCION dataplane path, which can be of different types (e.g., standard, one-hop).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScionDpPathViewRef<'a> {
    /// View over a standard SCION path
    Standard(&'a StandardPathView),
    /// View over a one-hop SCION path
    OneHop(&'a OneHopPathView),
    /// View over a Hummingbird SCION path
    Hummingbird(&'a HbirdPathView),
    /// View over an unsupported path type
    Unsupported {
        /// The unsupported path type
        path_type: PathType,
        /// Raw path data
        data: &'a [u8],
    },
    /// Empty path type
    Empty,
}
impl ScionDpPathViewExt for ScionDpPathViewRef<'_> {
    /// Returns an immutable view over the same path data.
    #[inline]
    fn as_ref(&self) -> ScionDpPathViewRef<'_> {
        *self
    }
}
impl<'a> From<&'a StandardPathView> for ScionDpPathViewRef<'a> {
    #[inline]
    fn from(value: &'a StandardPathView) -> Self {
        ScionDpPathViewRef::Standard(value)
    }
}
impl<'a> From<&'a OneHopPathView> for ScionDpPathViewRef<'a> {
    #[inline]
    fn from(value: &'a OneHopPathView) -> Self {
        ScionDpPathViewRef::OneHop(value)
    }
}
impl Display for ScionDpPathViewRef<'_> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.display(f)
    }
}

/// Mutable view over different path types
#[derive(Debug, PartialEq, Eq)]
pub enum ScionDpPathViewRefMut<'a> {
    /// Mutable view over a standard SCION path
    Standard(&'a mut StandardPathView),
    /// Mutable view over a one-hop SCION path
    OneHop(&'a mut OneHopPathView),
    /// Mutable view over a Hummingbird SCION path
    Hummingbird(&'a mut HbirdPathView),
    /// Mutable view over an unsupported path type
    Unsupported {
        /// The unsupported path type
        path_type: PathType,
        /// Raw path data
        buf: &'a mut [u8],
    },
    /// Empty path type
    Empty,
}
impl ScionDpPathViewExt for ScionDpPathViewRefMut<'_> {
    /// Returns an immutable view over the same path data.
    #[inline]
    fn as_ref(&self) -> ScionDpPathViewRef<'_> {
        match self {
            ScionDpPathViewRefMut::Standard(standard_path_view) => {
                ScionDpPathViewRef::Standard(standard_path_view)
            }
            ScionDpPathViewRefMut::Hummingbird(hbird_path_view) => {
                ScionDpPathViewRef::Hummingbird(hbird_path_view)
            }
            ScionDpPathViewRefMut::OneHop(one_hop_path_view) => {
                ScionDpPathViewRef::OneHop(one_hop_path_view)
            }
            ScionDpPathViewRefMut::Unsupported { path_type, buf } => {
                ScionDpPathViewRef::Unsupported {
                    path_type: *path_type,
                    data: buf,
                }
            }
            ScionDpPathViewRefMut::Empty => ScionDpPathViewRef::Empty,
        }
    }
}
impl ScionDpPathViewExtMut for ScionDpPathViewRefMut<'_> {
    #[inline]
    fn as_mut(&mut self) -> ScionDpPathViewRefMut<'_> {
        // XXX(ake): looks a bit weird, but this allows reborrowing the mutable reference while
        // preserving the lifetime.
        match self {
            ScionDpPathViewRefMut::Standard(v) => ScionDpPathViewRefMut::Standard(v),
            ScionDpPathViewRefMut::Hummingbird(v) => ScionDpPathViewRefMut::Hummingbird(v),
            ScionDpPathViewRefMut::OneHop(v) => ScionDpPathViewRefMut::OneHop(v),
            ScionDpPathViewRefMut::Unsupported { path_type, buf } => {
                ScionDpPathViewRefMut::Unsupported {
                    path_type: *path_type,
                    buf,
                }
            }
            ScionDpPathViewRefMut::Empty => ScionDpPathViewRefMut::Empty,
        }
    }
}
impl<'a> From<&'a mut StandardPathView> for ScionDpPathViewRef<'a> {
    #[inline]
    fn from(value: &'a mut StandardPathView) -> Self {
        ScionDpPathViewRef::Standard(value)
    }
}
impl<'a> From<&'a mut OneHopPathView> for ScionDpPathViewRef<'a> {
    #[inline]
    fn from(value: &'a mut OneHopPathView) -> Self {
        ScionDpPathViewRef::OneHop(value)
    }
}
impl Display for ScionDpPathViewRefMut<'_> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.display(f)
    }
}

/// Owned view over different path types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScionDpPathView {
    /// Owned view over a standard SCION path
    Standard(Box<StandardPathView>),
    /// Owned view over a one-hop SCION path
    OneHop(OneHopPathView),
    /// Owned view over a Hummingbird SCION path
    Hummingbird(Box<HbirdPathView>),
    /// Owned view over an unsupported path type
    Unsupported {
        /// The unsupported path type
        path_type: PathType,
        /// Raw path data
        data: Box<[u8]>,
    },
    /// Empty path type
    Empty,
}
impl ScionDpPathViewExt for ScionDpPathView {
    /// Returns an immutable view over the same path data.
    #[inline]
    fn as_ref(&self) -> ScionDpPathViewRef<'_> {
        match self {
            ScionDpPathView::Standard(standard_path_view) => {
                ScionDpPathViewRef::Standard(standard_path_view.as_ref())
            }
            ScionDpPathView::Hummingbird(hbird_path_view) => {
                ScionDpPathViewRef::Hummingbird(hbird_path_view.as_ref())
            }
            ScionDpPathView::OneHop(one_hop_path_view) => {
                ScionDpPathViewRef::OneHop(one_hop_path_view)
            }
            ScionDpPathView::Unsupported { path_type, data } => {
                ScionDpPathViewRef::Unsupported {
                    path_type: *path_type,
                    data: data.as_ref(),
                }
            }
            ScionDpPathView::Empty => ScionDpPathViewRef::Empty,
        }
    }
}
impl ScionDpPathViewExtMut for ScionDpPathView {
    /// Reverses the path, replacing a Hummingbird path with the standard path over the same hops.
    ///
    /// Flyover reservations are valid only in the direction they were bought, so reversal drops
    /// them. That changes both the path's type and its length, which is why this is overridden
    /// here rather than handled by the borrowed default.
    #[inline]
    fn try_reverse(&mut self) -> Result<&mut Self, PathReverseError> {
        if matches!(self, ScionDpPathView::Hummingbird(_)) {
            let mut model = self.to_model();
            model.try_reverse()?;
            *self = model.try_encode_to_owned_view().map_err(|e| {
                PathReverseError::new(format!("re-encoding the reversed path failed: {e}"))
            })?;
            return Ok(self);
        }

        match self.as_mut() {
            ScionDpPathViewRefMut::Standard(standard_path_view) => {
                standard_path_view.try_reverse()?;
            }
            ScionDpPathViewRefMut::OneHop(one_hop_path_view) => {
                one_hop_path_view.try_reverse()?;
            }
            ScionDpPathViewRefMut::Empty => {}
            ScionDpPathViewRefMut::Hummingbird(_) => {
                unreachable!("the Hummingbird variant is handled above")
            }
            ScionDpPathViewRefMut::Unsupported { .. } => {
                return Err(PathReverseError::new(
                    "Cannot reverse unsupported path type",
                ));
            }
        }

        Ok(self)
    }

    #[inline]
    fn as_mut(&mut self) -> ScionDpPathViewRefMut<'_> {
        match self {
            ScionDpPathView::Standard(standard_path_view) => {
                ScionDpPathViewRefMut::Standard(standard_path_view.as_mut())
            }
            ScionDpPathView::Hummingbird(hbird_path_view) => {
                ScionDpPathViewRefMut::Hummingbird(hbird_path_view.as_mut())
            }
            ScionDpPathView::OneHop(one_hop_path_view) => {
                ScionDpPathViewRefMut::OneHop(one_hop_path_view)
            }
            ScionDpPathView::Unsupported { path_type, data } => {
                ScionDpPathViewRefMut::Unsupported {
                    path_type: *path_type,
                    buf: data.as_mut(),
                }
            }
            ScionDpPathView::Empty => ScionDpPathViewRefMut::Empty,
        }
    }
}
impl_from!(Box<StandardPathView>, ScionDpPathView, |v| {
    ScionDpPathView::Standard(v)
});
impl_from!(OneHopPathView, ScionDpPathView, |v| {
    ScionDpPathView::OneHop(v)
});
impl_from!(Box<HbirdPathView>, ScionDpPathView, |v| {
    ScionDpPathView::Hummingbird(v)
});
impl<'a> From<&'a HbirdPathView> for ScionDpPathViewRef<'a> {
    #[inline]
    fn from(value: &'a HbirdPathView) -> Self {
        ScionDpPathViewRef::Hummingbird(value)
    }
}
impl<'a> From<&'a mut HbirdPathView> for ScionDpPathViewRefMut<'a> {
    #[inline]
    fn from(value: &'a mut HbirdPathView) -> Self {
        ScionDpPathViewRefMut::Hummingbird(value)
    }
}
impl Display for ScionDpPathView {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.display(f)
    }
}

/// Helper trait for working with [`ScionDpPathView`] and its references, providing common
/// functionality across different path types.
pub trait ScionDpPathViewExt {
    /// Returns an immutable view over the path data.
    fn as_ref(&self) -> ScionDpPathViewRef<'_>;

    /// Clones the path data into an owned view.
    #[inline]
    fn to_owned_view(&self) -> ScionDpPathView {
        match self.as_ref() {
            ScionDpPathViewRef::Standard(standard_path_view) => {
                ScionDpPathView::Standard(standard_path_view.to_boxed())
            }
            ScionDpPathViewRef::Hummingbird(hbird_path_view) => {
                ScionDpPathView::Hummingbird(hbird_path_view.to_boxed())
            }
            ScionDpPathViewRef::OneHop(one_hop_path_view) => {
                ScionDpPathView::OneHop(one_hop_path_view.clone())
            }
            ScionDpPathViewRef::Unsupported { path_type, data } => {
                ScionDpPathView::Unsupported {
                    path_type,
                    data: Box::from(data),
                }
            }
            ScionDpPathViewRef::Empty => ScionDpPathView::Empty,
        }
    }

    /// Returns the raw bytes of the path data as a slice.
    #[inline]
    fn as_slice(&self) -> &[u8] {
        match self.as_ref() {
            ScionDpPathViewRef::Standard(standard_path_view) => standard_path_view.as_slice(),
            ScionDpPathViewRef::Hummingbird(hbird_path_view) => hbird_path_view.as_slice(),
            ScionDpPathViewRef::OneHop(one_hop_path_view) => one_hop_path_view.as_slice(),
            ScionDpPathViewRef::Unsupported { data, .. } => data,
            ScionDpPathViewRef::Empty => &[],
        }
    }

    /// Returns the expiration time of the path in seconds since the UNIX epoch.
    ///
    /// Returns `None` if the expiration time cannot be determined (e.g., for unsupported path
    /// types).
    #[inline]
    fn expiration(&self) -> Option<u32> {
        match self.as_ref() {
            ScionDpPathViewRef::Standard(standard_path_view) => {
                Some(standard_path_view.expiration())
            }
            ScionDpPathViewRef::Hummingbird(hbird_path_view) => Some(hbird_path_view.expiration()),
            ScionDpPathViewRef::OneHop(one_hop_path_view) => Some(one_hop_path_view.expiration()),
            ScionDpPathViewRef::Empty => Some(u32::MAX),
            ScionDpPathViewRef::Unsupported { .. } => None,
        }
    }

    /// Returns the normalized first egress interface of the path if available.
    #[inline]
    fn first_egress_interface(&self) -> Option<u16> {
        match self.as_ref() {
            ScionDpPathViewRef::Standard(standard_path_view) => {
                let info_field = standard_path_view.info_fields().first()?;
                let hop_field = standard_path_view.hop_fields().first()?;
                Some(hop_field.egress_interface(info_field))
            }
            ScionDpPathViewRef::Hummingbird(hbird_path_view) => {
                let info_field = hbird_path_view.info_fields().first()?;
                let hop_field = hbird_path_view.hop_fields().next()?;
                Some(hop_field.egress_interface(info_field))
            }
            ScionDpPathViewRef::OneHop(one_hop_path_view) => {
                let info_field = one_hop_path_view.info_field();
                let [hop_field, _] = one_hop_path_view.hop_fields();
                Some(hop_field.egress_interface(info_field))
            }
            ScionDpPathViewRef::Empty => None,
            ScionDpPathViewRef::Unsupported { .. } => None,
        }
    }

    /// Returns the normalized current egress interface of the path if available.
    ///
    /// If the path is a one-hop path, the current egress interface is the egress interface of the
    /// first hop field.
    #[inline]
    fn current_egress_interface(&self) -> Option<u16> {
        match self.as_ref() {
            ScionDpPathViewRef::Standard(standard_path_view) => {
                let info_field = standard_path_view.curr_info_field()?;
                Some(
                    standard_path_view
                        .curr_hop_field()?
                        .egress_interface(info_field),
                )
            }
            ScionDpPathViewRef::Hummingbird(hbird_path_view) => {
                let info_field = hbird_path_view.curr_info_field()?;
                Some(
                    hbird_path_view
                        .curr_hop_field()?
                        .egress_interface(info_field),
                )
            }
            ScionDpPathViewRef::OneHop(one_hop_path_view) => {
                let info_field = one_hop_path_view.info_field();
                let [hop_field, _] = one_hop_path_view.hop_fields();
                Some(hop_field.egress_interface(info_field))
            }
            ScionDpPathViewRef::Empty => None,
            ScionDpPathViewRef::Unsupported { .. } => None,
        }
    }

    /// Returns the normalized last ingress interface of the path if available.
    #[inline]
    fn last_ingress_interface(&self) -> Option<u16> {
        match self.as_ref() {
            ScionDpPathViewRef::Standard(standard_path_view) => {
                let info_field = standard_path_view.info_fields().last()?;
                Some(
                    standard_path_view
                        .hop_fields()
                        .last()?
                        .ingress_interface(info_field),
                )
            }
            ScionDpPathViewRef::Hummingbird(hbird_path_view) => {
                let info_field = hbird_path_view.info_fields().last()?;
                Some(
                    hbird_path_view
                        .hop_fields()
                        .last()?
                        .ingress_interface(info_field),
                )
            }
            ScionDpPathViewRef::OneHop(one_hop_path_view) => {
                Some(
                    one_hop_path_view
                        .hop_fields()
                        .last()?
                        .ingress_interface(one_hop_path_view.info_field()),
                )
            }
            ScionDpPathViewRef::Empty => None,
            ScionDpPathViewRef::Unsupported { .. } => None,
        }
    }

    /// Returns the normalized current ingress interface of the path if available.
    ///
    /// If the path is a one-hop path, the current ingress interface is the ingress interface of the
    /// last hop field.
    #[inline]
    fn current_ingress_interface(&self) -> Option<u16> {
        match self.as_ref() {
            ScionDpPathViewRef::Standard(standard_path_view) => {
                let info_field = standard_path_view.curr_info_field()?;
                Some(
                    standard_path_view
                        .curr_hop_field()?
                        .ingress_interface(info_field),
                )
            }
            ScionDpPathViewRef::Hummingbird(hbird_path_view) => {
                let info_field = hbird_path_view.curr_info_field()?;
                Some(
                    hbird_path_view
                        .curr_hop_field()?
                        .ingress_interface(info_field),
                )
            }
            ScionDpPathViewRef::OneHop(one_hop_path_view) => {
                let info_field = one_hop_path_view.info_field();
                let [_, hop_field] = one_hop_path_view.hop_fields();
                Some(hop_field.ingress_interface(info_field))
            }
            ScionDpPathViewRef::Empty => None,
            ScionDpPathViewRef::Unsupported { .. } => None,
        }
    }

    /// Converts the view into a `DpPath` model.
    #[inline]
    fn to_model(&self) -> DpPath {
        DpPath::from_view(&self.as_ref())
    }

    /// Displays the path view in a human-readable format.
    #[inline]
    fn display(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.as_ref() {
            ScionDpPathViewRef::Standard(standard_path_view) => write!(f, "{}", standard_path_view),
            ScionDpPathViewRef::Hummingbird(hbird_path_view) => write!(f, "{}", hbird_path_view),
            ScionDpPathViewRef::OneHop(one_hop_path_view) => write!(f, "{}", one_hop_path_view),
            ScionDpPathViewRef::Unsupported { path_type, .. } => {
                write!(f, "[unsupported] {:?}", path_type)
            }
            ScionDpPathViewRef::Empty => write!(f, "[empty]"),
        }
    }
}
impl<T: ScionDpPathViewExt> ScionDpPathViewExt for &T {
    #[inline]
    fn as_ref(&self) -> ScionDpPathViewRef<'_> {
        (*self).as_ref()
    }
}

/// Helper trait for working with mutable references to [`ScionDpPathView`], providing common
/// functionality across different path types.
pub trait ScionDpPathViewExtMut: ScionDpPathViewExt {
    /// Returns a mutable view over the path data.
    fn as_mut(&mut self) -> ScionDpPathViewRefMut<'_>;

    /// Attempts to reverse the path in place if supported by the path type.
    ///
    /// Returns an error if the path type does not support reversal.
    #[inline]
    fn try_reverse(&mut self) -> Result<&mut Self, PathReverseError>
    where
        Self: Sized,
    {
        let mut_self = self.as_mut();

        match mut_self {
            ScionDpPathViewRefMut::Standard(standard_path_view) => {
                standard_path_view.try_reverse()?;
                Ok(self)
            }
            // Reversal drops the flyover reservations, which makes the path shorter and changes
            // its type. Neither is expressible through a borrowed view of fixed length, so only
            // the owned `ScionDpPathView` can do it.
            ScionDpPathViewRefMut::Hummingbird(_) => {
                Err(PathReverseError::new(
                    "Cannot reverse a Hummingbird path in place: reversal yields a standard path \
                     of a different length; reverse the owned ScionDpPathView instead",
                ))
            }
            ScionDpPathViewRefMut::OneHop(one_hop_path_view) => {
                one_hop_path_view.try_reverse()?;
                Ok(self)
            }
            ScionDpPathViewRefMut::Empty => Ok(self),
            ScionDpPathViewRefMut::Unsupported { .. } => {
                Err(PathReverseError::new(
                    "Cannot reverse unsupported path type",
                ))
            }
        }
    }

    /// Converts the path into a reversed view if supported by the path type.
    ///
    /// Returns an error if the path type does not support reversal.
    #[inline]
    fn try_into_reversed(mut self) -> Result<Self, (Self, PathReverseError)>
    where
        Self: Sized,
    {
        match self.try_reverse() {
            Ok(_) => Ok(self),
            Err(e) => Err((self, e)),
        }
    }
}

#[cfg(test)]
mod hbird_reversal_tests {
    use super::*;
    use crate::{
        core::model::Model,
        dataplane_path::{
            hbird::model::HummingbirdPath,
            standard::{
                model::{HopField, InfoField},
                types::{HopFieldMac, InfoFieldFlags},
            },
        },
    };

    fn hbird_view() -> ScionDpPathView {
        let path = HummingbirdPath {
            current_info_field: 0,
            current_hop_field: 0,
            segments: vec![crate::dataplane_path::hbird::model::HbirdSegment {
                info_field: InfoField {
                    flags: InfoFieldFlags::CONS_DIR,
                    segment_id: 1,
                    timestamp: 1_700_000_000,
                },
                hop_fields: [
                    crate::dataplane_path::hbird::model::HbirdHopField::Flyover(
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
                    ),
                    crate::dataplane_path::hbird::model::HbirdHopField::Standard(HopField {
                        flags: Default::default(),
                        expiration_units: 63,
                        cons_ingress: 2,
                        cons_egress: 0,
                        mac: HopFieldMac::zero(),
                    }),
                ]
                .into_iter()
                .collect(),
            }],
            base_timestamp: 1_700_000_000,
            millis_timestamp: 0,
            counter: 0,
        };
        ScionDpPathView::Hummingbird(path.try_encode_to_owned_view().expect("must encode"))
    }

    #[test]
    fn an_owned_hummingbird_view_reverses_into_a_standard_view() {
        let mut view = hbird_view();
        let before = view.as_slice().len();

        view.try_reverse().expect("owned view should reverse");

        assert!(matches!(view, ScionDpPathView::Standard(_)));
        assert!(
            view.as_slice().len() < before,
            "dropping the flyover must shorten the path"
        );
        assert!(matches!(
            DpPath::from_view(&view.as_ref()),
            DpPath::Standard(_)
        ));
    }

    #[test]
    fn a_borrowed_hummingbird_view_refuses_to_reverse() {
        // A borrowed view is fixed-length, so it cannot express the shorter standard path that
        // reversal produces. The error must say so rather than silently doing nothing.
        let mut view = hbird_view();
        let mut borrowed = view.as_mut();

        let err = borrowed
            .try_reverse()
            .expect_err("a borrowed Hummingbird view must not reverse");
        assert!(
            err.to_string().contains("owned"),
            "error should point at the owned view: {err}"
        );
    }

    #[test]
    fn reversing_twice_returns_a_standard_path_over_the_original_route() {
        // The second reversal goes through the standard path, so the route must come back.
        let mut view = hbird_view();
        view.try_reverse().expect("first reversal");
        let once = view.as_slice().to_vec();

        view.try_reverse().expect("second reversal");
        view.try_reverse().expect("third reversal");

        assert_eq!(view.as_slice(), once.as_slice());
    }
}
