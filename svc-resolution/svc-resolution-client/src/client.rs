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

//! # Service Resolution Client
//!
//! A [`UdpScionServiceResolutionClient`] sends a `ServiceResolutionRequest` over SCION UDP
//! to a service anycast address and returns the QUIC transport address from the response.
//!
//! ## Example
//!
//! ```no_run
//! use std::str::FromStr;
//! use std::time::Duration;
//!
//! use scion_proto::address::{IsdAsn, ServiceAddr, ScionAddrSvc, SocketAddrSvc};
//! use svc_resolution_client::UdpScionServiceResolutionClient;
//! use svc_resolution_models::ServiceResolver;
//!
//! # async fn example(socket: scion_stack::scionstack::UdpScionSocket) -> anyhow::Result<()> {
//! let client = UdpScionServiceResolutionClient::new(socket, Some(Duration::from_secs(5)));
//!
//! let dst = SocketAddrSvc::new(
//!     ScionAddrSvc::new(IsdAsn::from_str("1-ff00:0:110")?, ServiceAddr::CONTROL),
//!     0,
//! );
//! let response = client.resolve(dst).await?;
//! println!("Control service QUIC address: {}", response.quic_address);
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

use async_trait::async_trait;
use prost::Message;
use scion_proto::address::{SocketAddr, SocketAddrSvc};
use scion_protobuf::control_plane::v1::{ServiceResolutionRequest, ServiceResolutionResponse};
use scion_stack::scionstack::UdpScionSocket;
use svc_resolution_models::{ServiceResolver, SvcResolutionError, SvcResolutionResponse};

const RECV_BUF_SIZE: usize = 65535;

/// SCION UDP service resolution client.
pub struct UdpScionServiceResolutionClient {
    socket: UdpScionSocket,
    timeout: Option<Duration>,
}

impl UdpScionServiceResolutionClient {
    /// Creates a new service resolution client.
    ///
    /// `timeout` — if `Some`, each [`resolve`](ServiceResolver::resolve) call is bounded by
    /// this duration; if `None`, calls wait indefinitely for a response.
    pub fn new(socket: UdpScionSocket, timeout: Option<Duration>) -> Self {
        Self { socket, timeout }
    }

    async fn do_resolve(
        &self,
        dst: SocketAddrSvc,
    ) -> Result<SvcResolutionResponse, SvcResolutionError> {
        let buf = ServiceResolutionRequest {}.encode_to_vec();

        self.socket
            .send_to(&buf, SocketAddr::Svc(dst))
            .await
            .map_err(|e| SvcResolutionError::Send(e.to_string()))?;

        let mut recv_buf = vec![0u8; RECV_BUF_SIZE];
        let (len, sender) = self
            .socket
            .recv_from(&mut recv_buf)
            .await
            .map_err(|e| SvcResolutionError::Receive(e.to_string()))?;
        tracing::trace!(%sender, "received service resolution response");
        // Sender validation is intentionally omitted: the socket is purpose-built for this
        // single request/response exchange, and service resolution is typically called once
        // at startup against a well-known anycast address.

        let proto_resp = ServiceResolutionResponse::decode(&recv_buf[..len])
            .map_err(|e| SvcResolutionError::Decode(e.to_string()))?;

        SvcResolutionResponse::try_from(proto_resp)
    }
}

#[async_trait]
impl ServiceResolver for UdpScionServiceResolutionClient {
    async fn resolve(
        &self,
        dst: SocketAddrSvc,
    ) -> Result<SvcResolutionResponse, SvcResolutionError> {
        let fut = self.do_resolve(dst);
        match self.timeout {
            Some(timeout) => tokio::time::timeout(timeout, fut)
                .await
                .map_err(|_| SvcResolutionError::Timeout)?,
            None => fut.await,
        }
    }
}
