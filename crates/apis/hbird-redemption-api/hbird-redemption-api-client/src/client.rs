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
use reqwest_connect_rpc::client::CrpcClient as ReqwestCrpcClient;
use rsa::pkcs1::EncodeRsaPublicKey;
use scion_connect_rpc::client::{ConnectRpcClient, CrpcClient as ScionCrpcClient, RemoteEndpoint};
use scion_quic::quic::config::QuicConfig;
use scion_stack::ScionStack;
use sciparse::{
    address::{
        host_addr::ServiceAddr, ip_addr::ScionIpAddr, ip_socket_addr::ScionSocketIpAddr,
        socket_addr::ScionSocketAddrSvc,
    },
    hummingbird::Reservation,
    identifier::isd_asn::IsdAsn,
};
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
    local_addr: ScionIpAddr,

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
    /// # Panics
    ///
    /// Redeeming from the *local* AS goes over plain HTTP through `reqwest`, which is built
    /// without a default TLS backend. If no rustls crypto provider has been installed for the
    /// process, that call panics rather than returning an error. Install one at startup, e.g.
    /// with `scion_sdk_utils::rustls::select_ring_crypto_provider()`.
    ///
    /// Parameters:
    /// - `scion_stack`: SCION stack used for remote AS communication.
    /// - `local_hbird_service_url`: Base URL for the Hummingbird service in the local AS.
    /// - `local_addr`: Local SCION address to bind to for remote AS communication.
    pub async fn new(
        scion_stack: Arc<ScionStack>,
        local_hbird_service_url: url::Url,
        local_addr: ScionIpAddr,
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
    /// # use scion_quic::quic::config::{QuicConfig, PROTOCOL_VERSION};
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
        local_addr: ScionIpAddr,
        quic_config: QuicConfig,
    ) -> Result<Self, HbirdRedemptionError> {
        let svc_resolution_socket = scion_stack
            .bind(Some(ScionSocketIpAddr::new(
                local_addr.isd_asn(),
                local_addr.ip(),
                0,
            )))
            .await?;

        let svc_resolution_client =
            UdpScionServiceResolutionClient::new(svc_resolution_socket, None);

        let sk =
            tokio::task::spawn_blocking(|| rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048))
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
    ///
    /// The returned reservations are in the same order as `requests`. Requests are grouped by
    /// target AS and each group redeemed in one round trip, so responses arrive grouped; a
    /// [`Reservation`] carries nothing that would let a caller re-associate it with its request,
    /// so the original order is restored before returning.
    pub async fn redeem(
        &self,
        requests: Vec<RedemptionRequestWithIsdAsn>,
    ) -> Result<Vec<Reservation>, HbirdRedemptionError> {
        let mut reservations: Vec<Option<Reservation>> = vec![None; requests.len()];

        for (target_isd_as, group) in requests_by_as(requests) {
            let (positions, requests): (Vec<usize>, Vec<RedemptionRequest>) =
                group.into_iter().unzip();
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
                        &proto_request,
                    )
                    .await?
            } else {
                // The redemption service shares a host with the control service but listens on
                // its own port, so resolution supplies the host and HBIRD_PORT the port.
                let cs_addr = self
                    .svc_resolution_client
                    .resolve(ScionSocketAddrSvc::new(
                        target_isd_as,
                        ServiceAddr::CONTROL,
                        HBIRD_PORT,
                    ))
                    .await?
                    .quic_address;

                let hbird_addr = ScionSocketIpAddr::new(target_isd_as, cs_addr.ip(), HBIRD_PORT);

                let socket = self
                    .scion_stack
                    .bind(Some(ScionSocketIpAddr::new(
                        self.local_addr.isd_asn(),
                        self.local_addr.ip(),
                        0,
                    )))
                    .await?;

                let client = ScionCrpcClient::with_config(
                    RemoteEndpoint::new(hbird_addr, Arc::new(socket)),
                    Some(target_isd_as.to_string()),
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
                        &proto_request,
                    )
                    .await?
            };

            tracing::trace!(target_isd_as = %target_isd_as, "received redemption response from Hummingbird service");

            // `from_proto_responses` rejects a count mismatch, so this fills exactly the
            // positions this group came from.
            for (position, reservation) in positions.into_iter().zip(from_proto_responses(
                proto_response,
                &requests,
                &self.sk,
            )?) {
                reservations[position] = Some(reservation);
            }
        }

        Ok(reservations
            .into_iter()
            .map(|reservation| {
                reservation.expect("every position is filled by the group it was grouped into")
            })
            .collect())
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

/// Groups redemption requests by their target ISD-AS, keeping each request's position in the
/// original batch so the results can be put back in order.
fn requests_by_as(
    requests: Vec<RedemptionRequestWithIsdAsn>,
) -> HashMap<IsdAsn, Vec<(usize, RedemptionRequest)>> {
    requests
        .into_iter()
        .enumerate()
        .fold(HashMap::new(), |mut map, (position, request)| {
            map.entry(request.isd_asn)
                .or_default()
                .push((position, request.into()));
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

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::SystemTime};

    use sciparse::hummingbird::Bandwidth;

    use super::*;

    fn request(isd_asn: &str) -> RedemptionRequestWithIsdAsn {
        RedemptionRequestWithIsdAsn {
            isd_asn: IsdAsn::from_str(isd_asn).unwrap(),
            info: RedemptionInfo {
                ingress: 1,
                egress: 2,
                bandwidth: Bandwidth::from_bytes_per_sec(1024).unwrap(),
                start_time: SystemTime::UNIX_EPOCH,
                duration: 60,
            },
            ingress_token: IngressToken([0u8; 16]),
            egress_token: EgressToken([0u8; 16]),
        }
    }

    #[test]
    fn grouping_by_as_records_each_request_position() {
        // A batch that interleaves two ASes: grouping reorders it, so every request has to carry
        // the position it must be restored to.
        let batch = vec![
            request("1-ff00:0:110"),
            request("1-ff00:0:111"),
            request("1-ff00:0:110"),
        ];
        let grouped = requests_by_as(batch);

        assert_eq!(grouped.len(), 2);
        assert_eq!(
            grouped[&IsdAsn::from_str("1-ff00:0:110").unwrap()]
                .iter()
                .map(|(position, _)| *position)
                .collect::<Vec<_>>(),
            vec![0, 2]
        );
        assert_eq!(
            grouped[&IsdAsn::from_str("1-ff00:0:111").unwrap()]
                .iter()
                .map(|(position, _)| *position)
                .collect::<Vec<_>>(),
            vec![1]
        );
    }

    #[test]
    fn grouping_covers_every_position_exactly_once() {
        // `redeem` indexes into a pre-sized Vec and unwraps every slot, so a position that is
        // dropped or duplicated by grouping would panic rather than merely misorder.
        let batch: Vec<_> = ["1-ff00:0:110", "1-ff00:0:111", "1-ff00:0:112"]
            .iter()
            .cycle()
            .take(7)
            .map(|isd_asn| request(isd_asn))
            .collect();
        let total = batch.len();

        let mut positions: Vec<usize> = requests_by_as(batch)
            .into_values()
            .flatten()
            .map(|(position, _)| position)
            .collect();
        positions.sort_unstable();

        assert_eq!(positions, (0..total).collect::<Vec<_>>());
    }
}
