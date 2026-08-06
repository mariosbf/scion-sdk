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
//! Connect RPC client for the Hummingbird redemption API.

use std::{collections::HashMap, sync::Arc};

use hbird_redemption_api::routes::{HBIRD_API_V1, HBIRD_SERVICE, REDEEM};
use hbird_redemption_api_models::{
    EgressToken, HbirdRedemptionError, IngressToken, RedemptionInfo, RedemptionRequest,
};
use hbird_redemption_api_protobuf::{
    convert::{from_proto_responses, to_proto_requests},
    hbird::v1::RedemptionResponses,
};
use http::Method;
use rsa::pkcs1::EncodeRsaPublicKey;
use scion_proto::{
    address::{IsdAsn, ScionAddr, ScionAddrSvc, ServiceAddr, SocketAddr, SocketAddrSvc},
    hummingbird::Reservation,
};
use scion_sdk_quic_scion::quic::config::QuicConfig;
use scion_sdk_reqwest_connect_rpc::client::CrpcClient as ReqwestCrpcClient;
use scion_sdk_scion_connect_rpc::client::{ConnectRpcClient, CrpcClient as ScionCrpcClient};
use scion_stack::scionstack::ScionStack;
use svc_resolution_client::UdpScionServiceResolutionClient;
use svc_resolution_models::ServiceResolver;

/// Port on which the Hummingbird redemption service listens on the control service host.
const HBIRD_PORT: u16 = 30258;

/// Connect RPC client for the Hummingbird redemption service.
pub struct CrpcHbirdRedemptionClient {
    /// SCION stack used for remote AS communication.
    scion_stack: Arc<ScionStack>,

    /// Base URL for the Hummingbird service in the local AS.
    local_hbird_service_url: url::Url,

    /// Local SCION address to bind to for remote AS communication.
    local_addr: ScionAddr,

    /// SCION service resolution client.
    svc_resolution_client: UdpScionServiceResolutionClient,

    /// RSA private key used to decrypt redemption responses.
    sk: rsa::RsaPrivateKey,

    /// DER-encoded RSA public key sent with redemption requests.
    pk_der: Vec<u8>,

    /// QUIC configuration used for remote AS communication.
    quic_config: QuicConfig,
}

/// A single Hummingbird flyover redemption request.
#[derive(Debug, Clone)]
pub struct RedemptionRequestWithIsdAsn {
    /// IsdAsn
    pub isd_asn: IsdAsn,

    /// Reservation parameters.
    pub info: RedemptionInfo,

    /// Asset redemption token for the ingress reservation. 16 bytes.
    pub ingress_token: IngressToken,

    /// Asset redemption token for the egress reservation. 16 bytes.
    pub egress_token: EgressToken,
}

impl From<RedemptionRequestWithIsdAsn> for RedemptionRequest {
    fn from(req: RedemptionRequestWithIsdAsn) -> Self {
        RedemptionRequest {
            info: req.info,
            ingress_token: req.ingress_token,
            egress_token: req.egress_token,
        }
    }
}

impl CrpcHbirdRedemptionClient {
    /// Creates a new Hummingbird redemption client.
    ///
    /// Parameters:
    /// - `scion_stack`: SCION stack used for remote AS communication.
    /// - `local_hbird_service_url`: Base URL for the Hummingbird service in
    ///   the local AS.
    /// - `local_addr`: Local SCION address to bind to for remote AS communication.
    pub async fn new(
        scion_stack: Arc<ScionStack>,
        local_hbird_service_url: url::Url,
        local_addr: ScionAddr,
    ) -> Result<Self, HbirdRedemptionError> {
        Self::with_quic_config(
            scion_stack,
            local_hbird_service_url,
            local_addr,
            QuicConfig::default(),
        )
        .await
    }

    /// Creates a new Hummingbird redemption client with a custom QUIC configuration.
    ///
    /// Use this to reach a Hummingbird service that does not speak squiche's SCION QUIC version,
    /// or whose certificate is issued by the SCION control-plane PKI rather than the web PKI:
    ///
    /// ```no_run
    /// # use scion_sdk_quic_scion::quic::config::{QuicConfig, PROTOCOL_VERSION};
    /// let quic_config = QuicConfig::builder()
    ///     .protocol_version(PROTOCOL_VERSION)
    ///     .ca_certs_dir("/path/to/gen/certs")
    ///     .verify_server_name(false)
    ///     .build();
    /// ```
    ///
    /// Parameters are as for [`Self::new`], plus:
    /// - `quic_config`: QUIC configuration for remote AS communication.
    pub async fn with_quic_config(
        scion_stack: Arc<ScionStack>,
        local_hbird_service_url: url::Url,
        local_addr: ScionAddr,
        quic_config: QuicConfig,
    ) -> Result<Self, HbirdRedemptionError> {
        let svc_resolution_socket = scion_stack
            .bind(Some(SocketAddr::new(local_addr, 0)))
            .await?;

        let svc_resolution_client =
            UdpScionServiceResolutionClient::new(svc_resolution_socket, None);

        let sk = tokio::task::spawn_blocking(|| {
            rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048)
        })
        .await
        .map_err(|e| HbirdRedemptionError::InvalidReservation(e.to_string()))??;

        let pk_der = sk
            .to_public_key()
            .to_pkcs1_der()
            .map_err(|e| HbirdRedemptionError::InvalidReservation(e.to_string()))?
            .to_vec();

        Ok(CrpcHbirdRedemptionClient {
            local_addr,
            scion_stack,
            local_hbird_service_url,
            svc_resolution_client,
            sk,
            pk_der,
            quic_config,
        })
    }
}

impl CrpcHbirdRedemptionClient {
    /// Redeems a batch of flyover reservations.
    pub async fn redeem(
        &self,
        requests: Vec<RedemptionRequestWithIsdAsn>,
    ) -> Result<Vec<Reservation>, HbirdRedemptionError> {
        let mut reservations = Vec::with_capacity(requests.len());

        for (target_isd_as, requests) in requests_by_as(requests) {
            let proto_request = to_proto_requests(requests.clone(), self.pk_der.clone());

            let proto_response = if self.local_addr.isd_asn() == target_isd_as {
                // Note: Service address resolution does not work currently for
                // the local AS.
                // Note: Cannot currenlty use service addresses for communication
                // within the local AS with the scion-sdk.
                let client = ReqwestCrpcClient::new(&self.local_hbird_service_url)
                    .map_err(|e| HbirdRedemptionError::Transport(e.to_string()))?;

                client
                    .unary_request::<_, RedemptionResponses>(
                        &format!("{HBIRD_API_V1}.{HBIRD_SERVICE}{REDEEM}"),
                        proto_request,
                    )
                    .await?
            } else {
                let cs_addr = self
                    .svc_resolution_client
                    .resolve(SocketAddrSvc::new(
                        ScionAddrSvc::new(target_isd_as, ServiceAddr::CONTROL),
                        HBIRD_PORT,
                    ))
                    .await?
                    .quic_address;
                let mut hbird_local_addr = cs_addr;
                hbird_local_addr.set_port(HBIRD_PORT);

                let hbird_addr = SocketAddr::new(
                    ScionAddr::new(target_isd_as, hbird_local_addr.ip().into()),
                    HBIRD_PORT,
                );

                let socket_addr = SocketAddr::new(self.local_addr, 0);
                let socket = self.scion_stack.bind(Some(socket_addr)).await?;
                let socket = Arc::new(socket);

                let server_name = target_isd_as.to_string();

                let client = ScionCrpcClient::with_quic_config(
                    hbird_addr,
                    socket,
                    Some(server_name),
                    None,
                    self.quic_config.clone(),
                )
                .await
                .map_err(|e| {
                    HbirdRedemptionError::Transport(format!("failed to create SCION client: {e}"))
                })?;

                client
                    .unary_request::<_, RedemptionResponses>(
                        Method::POST,
                        hbird_method_url(REDEEM)?,
                        proto_request,
                    )
                    .await?
            };

            tracing::trace!(target_isd_as = %target_isd_as, "received redemption response from Hummingbird service");
            reservations.extend(from_proto_responses(proto_response, &requests, &self.sk)?);
        }
        Ok(reservations)
    }

    /// Redeems a single flyover reservation.
    pub async fn redeem_single(
        &self,
        request: RedemptionRequestWithIsdAsn,
    ) -> Result<Reservation, HbirdRedemptionError> {
        self.redeem(vec![request])
            .await?
            .into_iter()
            .next()
            .ok_or(HbirdRedemptionError::EmptyResponse)
    }
}

/// Groups redemption requests by their target ISD-AS.
fn requests_by_as(
    requests: Vec<RedemptionRequestWithIsdAsn>,
) -> HashMap<IsdAsn, Vec<RedemptionRequest>> {
    requests.iter().fold(HashMap::new(), |mut map, request| {
        map.entry(request.isd_asn)
            .or_default()
            .push(request.clone().into());
        map
    })
}

/// Builds a full URL for a Hummingbird service method.
/// Parameters:
/// - `method`: Method name, e.g., "Redeem".
fn hbird_method_url(method: &str) -> Result<url::Url, HbirdRedemptionError> {
    url::Url::parse(&format!(
        "https://hbird/{}.{}{}",
        HBIRD_API_V1, HBIRD_SERVICE, method
    ))
    .map_err(|e| HbirdRedemptionError::Transport(format!("failed to construct method URL: {e}")))
}
