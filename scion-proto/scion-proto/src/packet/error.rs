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

//! Errors raised when encoding or decoding SCION packets.

use super::Version;
use crate::path::DataPlanePathErrorKind;

/// Errors raised when failing to decode a [`ScionPacketRaw`][super::ScionPacketRaw] or
/// [`ScionPacketUdp`][super::ScionPacketUdp] or its constituents.
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum DecodeError {
    #[error("cannot decode packet with unsupported header version {0:?}")]
    UnsupportedVersion(Version),
    #[error("header length factor is inconsistent with the SCION specification: {0}")]
    InvalidHeaderLength(u8),
    #[error("the provided bytes did not include the full packet")]
    PacketEmptyOrTruncated,
    #[error("the path type and length do not correspond")]
    InconsistentPathLength,
    #[error("attempted to decode the empty path type")]
    EmptyPath,
    #[error("invalid path header: {0}")]
    InvalidPath(DataPlanePathErrorKind),
}

impl From<DataPlanePathErrorKind> for DecodeError {
    fn from(value: DataPlanePathErrorKind) -> Self {
        Self::InvalidPath(value)
    }
}

/// Errors raised when failing to encode a [`ScionPacketRaw`][super::ScionPacketRaw],
/// [`super::ScionPacketScmp`], or [`ScionPacketUdp`][super::ScionPacketUdp].
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum EncodeError {
    /// The payload is too large to be properly encoded in a SCION packet.
    #[error("packet payload is too large")]
    PayloadTooLarge,
    /// The overall header is too large.
    ///
    /// This is most likely due to a too long path.
    #[error("packet header is too large")]
    HeaderTooLarge,
}

/// Marker trait for error types that are not [EncodeError].
///
/// This prevents [PathProviderEncodeError<EncodeError>], which would
/// create conflicting `From` implementations.
pub trait NonEncodeError: std::error::Error {}

impl NonEncodeError for std::convert::Infallible {}

/// Errors raised when encoding a SCION UDP packet with a path provider.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum PathProviderEncodeError<E: NonEncodeError> {
    /// A general [`EncodeError`] occurred.
    #[error("error during packet encoding")]
    EncodeError(#[from] EncodeError),
    /// An error occurred in the path provider.
    #[error("error in the path provider")]
    PathProviderError(#[from] E),
}

/// Errors raised when creating a [`ScionPacketScmp`][super::ScionPacketScmp].
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum ScmpEncodeError {
    /// Some SCMP messages (notably the
    /// [`ScmpTracerouteRequest`][crate::scmp::ScmpTracerouteRequest]) require a specific path
    /// type.
    #[error("the provided path type is not appropriate for this type of packet")]
    InappropriatePathType,
    /// A provided parameter is out of range.
    #[error("a provided parameter is out of range")]
    ParameterOutOfRange,
    /// A general [`EncodeError`] occurred.
    #[error("encoding error")]
    GeneralEncodeError(#[from] EncodeError),
}

/// Errors raised when encoding a SCION SCMP packet with a path provider.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
pub enum PathProviderScmpEncodeError<E: NonScmpEncodeError> {
    /// A [`ScmpEncodeError`] occurred.
    #[error("error during SCMP packet encoding")]
    ScmpEncodeError(#[from] ScmpEncodeError),
    /// An error occurred in the path provider.
    #[error("error in the path provider")]
    PathProviderError(#[from] E),
}

/// Marker trait for error types that are not [ScmpEncodeError].
///
/// This prevents [PathProviderScmpEncodeError<ScmpEncodeError>], which would
/// create conflicting `From` implementations.
pub trait NonScmpEncodeError: std::error::Error {}

impl NonScmpEncodeError for std::convert::Infallible {}

/// Raised if the buffer does not have sufficient capacity for encoding the SCION headers.
///
/// As the headers can be a maximum of 1020 bytes in length, it is advisable to have at
/// least that amount of remaining space for encoding a [`ScionPacketRaw`][super::ScionPacketRaw] or
/// [`ScionPacketUdp`][super::ScionPacketUdp] (the payload is not written to the buffer).
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy, Default)]
#[error("the provided buffer did not have sufficient size")]
pub struct InadequateBufferSize;
