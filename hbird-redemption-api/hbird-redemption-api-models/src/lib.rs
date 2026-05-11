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
//! Hummingbird redemption API models library.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use scion_proto::hummingbird::{Bandwidth, Reservation};
use scion_stack::scionstack::ScionSocketBindError;
use thiserror::Error;

/// Information about a desired Hummingbird flyover reservation.
///
/// This is the pre-redemption specification sent to the Hummingbird service.
/// After a successful redemption, the returned [`Reservation`] includes the
/// assigned reservation ID and authentication key.
#[derive(Debug, Clone)]
pub struct RedemptionInfo {
    /// Ingress interface ID.
    pub ingress: u16,
    /// Egress interface ID.
    pub egress: u16,
    /// Requested bandwidth.
    pub bandwidth: Bandwidth,
    /// Reservation start time.
    pub start_time: DateTime<Utc>,
    /// Reservation duration in seconds.
    pub duration: u16,
}

/// A single Hummingbird flyover redemption request.
#[derive(Debug, Clone)]
pub struct RedemptionRequest {
    /// Reservation parameters.
    pub info: RedemptionInfo,
    /// Asset redemption token for the ingress reservation. 16 bytes.
    pub ingress_token: IngressToken,
    /// Asset redemption token for the egress reservation. 16 bytes.
    pub egress_token: EgressToken,
}

/// Opaque ingress-side redemption token. 16 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressToken(pub [u8; 16]);

/// Opaque egress-side redemption token. 16 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressToken(pub [u8; 16]);

/// Client private key used for decrypting the auth_key in redemption responses.
pub type ClientPrivateKey = rsa::RsaPrivateKey;

/// Client public key used for encrypting the auth_key in redemption responses.
pub type ClientPublicKey = rsa::RsaPublicKey;

/// Status information returned by the Hummingbird service.
#[derive(Debug, Clone)]
pub struct StatusInfo {
    /// Version of the Hummingbird service.
    pub version: u32,
}

/// Errors returned by [`HbirdRedemptionService`] methods.
#[derive(Debug, Error)]
pub enum HbirdRedemptionError {
    /// Transport or RPC error.
    #[error("transport error: {0}")]
    Transport(String),
    /// Server returned an empty response for a single-item request.
    #[error("empty response from server")]
    EmptyResponse,
    /// Server returned a different number of reservations than requested.
    #[error("server returned {got} reservations for {expected} requests")]
    ResponseMismatch {
        /// Number of requests sent.
        expected: usize,
        /// Number of reservations received.
        got: usize,
    },
    /// Reservation data from the server is malformed.
    #[error("invalid reservation data: {0}")]
    InvalidReservation(String),

    /// Decryption error.
    #[error("decryption error: {0}")]
    FailedDecryption(#[from] rsa::errors::Error),

    /// Error making service resolution request
    #[error("service resolution error: {0}")]
    ServiceResolution(#[from] svc_resolution_models::SvcResolutionError),

    /// Error parsing PKCS#1 keys
    #[error("PKCS#1 error: {0}")]
    Pkcs1(#[from] rsa::pkcs1::Error),
}

impl From<scion_sdk_reqwest_connect_rpc::client::CrpcClientError> for HbirdRedemptionError {
    fn from(err: scion_sdk_reqwest_connect_rpc::client::CrpcClientError) -> Self {
        HbirdRedemptionError::Transport(err.to_string())
    }
}

impl From<scion_sdk_scion_connect_rpc::client::RequestError> for HbirdRedemptionError {
    fn from(err: scion_sdk_scion_connect_rpc::client::RequestError) -> Self {
        HbirdRedemptionError::Transport(err.to_string())
    }
}

impl From<ScionSocketBindError> for HbirdRedemptionError {
    fn from(err: ScionSocketBindError) -> Self {
        HbirdRedemptionError::Transport(err.to_string())
    }
}

/// Hummingbird redemption service trait.
///
/// Implementors provide the server-side ability to redeem Hummingbird flyover reservations.
/// The client's public key is used to encrypt the returned auth keys.
#[async_trait]
pub trait HbirdRedemptionService: Send + Sync {
    /// Redeems a batch of flyover reservations.
    ///
    /// The returned [`Reservation`]s are in the same order as `requests`.
    async fn redeem(
        &self,
        requests: Vec<RedemptionRequest>,
        client_key: ClientPublicKey,
    ) -> Result<Vec<Reservation>, HbirdRedemptionError>;

    /// Redeems a single flyover reservation.
    ///
    /// Convenience wrapper around [`redeem`](Self::redeem).
    async fn redeem_single(
        &self,
        request: RedemptionRequest,
        client_key: ClientPublicKey,
    ) -> Result<Reservation, HbirdRedemptionError> {
        self.redeem(vec![request], client_key)
            .await?
            .into_iter()
            .next()
            .ok_or(HbirdRedemptionError::EmptyResponse)
    }

    /// Returns the status of the Hummingbird service.
    async fn status(&self) -> Result<StatusInfo, HbirdRedemptionError>;
}
