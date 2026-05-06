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

//! Service resolution models and client trait.

use async_trait::async_trait;
use scion_proto::address::SocketAddrSvc;
use thiserror::Error;

/// Resolved service endpoint information.
#[derive(Debug, Clone, Copy)]
pub struct SvcResolutionResponse {
    /// The QUIC address at which the service can be reached.
    pub quic_address: std::net::SocketAddr,
}

/// Errors returned by [`ServiceResolver`].
#[derive(Debug, Error)]
pub enum SvcResolutionError {
    /// SCION send failed.
    #[error("send error: {0}")]
    Send(String),
    /// SCION receive failed.
    #[error("receive error: {0}")]
    Receive(String),
    /// Timed out waiting for a response.
    #[error("timeout waiting for response")]
    Timeout,
    /// Response protobuf could not be decoded.
    #[error("failed to decode response: {0}")]
    Decode(String),
    /// QUIC transport address string is not a valid socket address.
    #[error("invalid transport address: {0}")]
    InvalidAddress(String),
    /// Response contains no QUIC transport entry.
    #[error("response contains no QUIC transport")]
    NoQuicTransport,
}

/// Service resolution trait.
#[async_trait]
pub trait ServiceResolver: Send + Sync {
    /// Resolves the QUIC transport address for the given SCION service socket address.
    async fn resolve(
        &self,
        dst: SocketAddrSvc,
    ) -> Result<SvcResolutionResponse, SvcResolutionError>;
}

impl TryFrom<scion_protobuf::control_plane::v1::ServiceResolutionResponse>
    for SvcResolutionResponse
{
    type Error = SvcResolutionError;

    fn try_from(
        proto: scion_protobuf::control_plane::v1::ServiceResolutionResponse,
    ) -> Result<Self, Self::Error> {
        let quic_address = proto
            .transports
            .get("QUIC")
            .ok_or(SvcResolutionError::NoQuicTransport)?
            .address
            .parse::<std::net::SocketAddr>()
            .map_err(|e| SvcResolutionError::InvalidAddress(e.to_string()))?;

        Ok(SvcResolutionResponse { quic_address })
    }
}

#[cfg(test)]
mod tests {
    use scion_protobuf::control_plane::v1::{
        ServiceResolutionResponse as ProtoResponse, Transport,
    };

    use super::*;

    #[test]
    fn quic_transport_extracted() {
        let proto = ProtoResponse {
            transports: [(
                "QUIC".to_string(),
                Transport {
                    address: "192.168.1.1:8080".to_string(),
                },
            )]
            .into(),
        };
        let response = SvcResolutionResponse::try_from(proto).unwrap();
        assert_eq!(
            response.quic_address,
            "192.168.1.1:8080".parse().unwrap()
        );
    }

    #[test]
    fn missing_quic_returns_no_quic_transport() {
        let proto = ProtoResponse {
            transports: [(
                "TCP".to_string(),
                Transport {
                    address: "192.168.1.1:8080".to_string(),
                },
            )]
            .into(),
        };
        assert!(matches!(
            SvcResolutionResponse::try_from(proto),
            Err(SvcResolutionError::NoQuicTransport)
        ));
    }

    #[test]
    fn unknown_transports_ignored() {
        let proto = ProtoResponse {
            transports: [
                (
                    "QUIC".to_string(),
                    Transport {
                        address: "10.0.0.1:443".to_string(),
                    },
                ),
                (
                    "UNKNOWN".to_string(),
                    Transport {
                        address: "10.0.0.2:443".to_string(),
                    },
                ),
            ]
            .into(),
        };
        let response = SvcResolutionResponse::try_from(proto).unwrap();
        assert_eq!(response.quic_address, "10.0.0.1:443".parse().unwrap());
    }

    #[test]
    fn invalid_quic_address_returns_invalid_address() {
        let proto = ProtoResponse {
            transports: [(
                "QUIC".to_string(),
                Transport {
                    address: "not-an-address".to_string(),
                },
            )]
            .into(),
        };
        assert!(matches!(
            SvcResolutionResponse::try_from(proto),
            Err(SvcResolutionError::InvalidAddress(_))
        ));
    }

    #[test]
    fn empty_transports_returns_no_quic_transport() {
        let proto = ProtoResponse {
            transports: [].into(),
        };
        assert!(matches!(
            SvcResolutionResponse::try_from(proto),
            Err(SvcResolutionError::NoQuicTransport)
        ));
    }
}
