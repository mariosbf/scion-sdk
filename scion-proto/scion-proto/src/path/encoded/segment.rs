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
//! Encoded SCION path segments.

use std::{iter::FusedIterator, ops::Range};

use chrono::{DateTime, Utc};

use crate::path::EncodedHopField;

use super::{EncodedInfoField, HopFields};

/// A segment of a SCION [`EncodedStandardPath`][super::EncodedStandardPath].
///
/// Allows retrieving the info and hop fields associated with the path segment,
/// as well as the overall expiry time of the segment.
#[derive(Debug, Clone)]
pub struct EncodedSegment<'a> {
    info_field: &'a EncodedInfoField,
    hop_fields: HopFields<'a>,
}

impl<'a> EncodedSegment<'a> {
    /// Creates a new view of a non-empty segment.
    ///
    /// # Panics
    ///
    /// If hop_fields is empty.
    pub(super) fn new(info_field: &'a EncodedInfoField, hop_fields: HopFields<'a>) -> Self {
        assert_ne!(hop_fields.len(), 0);
        Self {
            info_field,
            hop_fields,
        }
    }

    /// Returns the [`EncodedInfoField`] associated with this path segment.
    pub fn info_field(&self) -> &EncodedInfoField {
        self.info_field
    }

    /// Returns an iterator over the [`EncodedHopField`][super::EncodedHopField]s associated with
    /// this segment.
    pub fn hop_fields(&self) -> HopFields<'a> {
        self.hop_fields.clone()
    }

    /// Returns the expiry time of the segment as the minimum expiry time of all of its hop fields.
    pub fn expiry_time(&self) -> DateTime<Utc> {
        self.hop_fields()
            .map(|hop_field| hop_field.expiry_time(self.info_field()))
            .min()
            .expect("always at least 1 hop field")
    }
}

/// An iterator over the [`EncodedSegment`]s in a SCION
/// [`EncodedStandardPath`][super::EncodedStandardPath].
///
/// This `struct` is created by the [`segments`][super::EncodedStandardPath::segments] method on
/// [`EncodedStandardPath`][super::EncodedStandardPath]. See its documentation for more information.
pub struct EncodedSegments<'a> {
    inner: [Option<EncodedSegment<'a>>; 3],
    valid_range: Range<usize>,
}

impl<'a> EncodedSegments<'a> {
    pub(super) fn new(segments: [Option<EncodedSegment<'a>>; 3]) -> Self {
        let end = segments.iter().position(Option::is_none).unwrap_or(3);
        Self {
            inner: segments,
            valid_range: 0..end,
        }
    }
}

impl<'a> Iterator for EncodedSegments<'a> {
    type Item = EncodedSegment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.valid_range.next().map(|idx| {
            self.inner[idx]
                .clone()
                .expect("segment in iterated position is not None")
        })
    }
}

impl DoubleEndedIterator for EncodedSegments<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.valid_range.next_back().map(|idx| {
            self.inner[idx]
                .clone()
                .expect("segment in iterated position is not None")
        })
    }
}

impl ExactSizeIterator for EncodedSegments<'_> {
    fn len(&self) -> usize {
        self.valid_range.len()
    }
}

impl FusedIterator for EncodedSegments<'_> {}
