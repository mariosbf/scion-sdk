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

use std::{ops::Deref, sync::Arc};

use async_trait::async_trait;
use hbird_redemption_api::routes::{HBIRD_API_V1, HBIRD_SERVICE, REDEEM, STATUS};
use hbird_redemption_api_models::{
    ClientKey, HbirdRedemptionError, HbirdRedemptionService, RedemptionRequest, StatusInfo,
};
use hbird_redemption_api_protobuf::{
    convert::{from_proto_responses, to_proto_requests},
    hbird::v1::{RedemptionResponses, StatusResponse},
};
use scion_proto::hummingbird::Reservation;
use scion_sdk_reqwest_connect_rpc::{
    client::{CrpcClient, CrpcClientError},
    token_source::TokenSource,
};

/// Connect RPC client for the Hummingbird redemption service.
pub struct CrpcHbirdRedemptionClient {
    client: CrpcClient,
}

impl Deref for CrpcHbirdRedemptionClient {
    type Target = CrpcClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl CrpcHbirdRedemptionClient {
    /// Creates a new Hummingbird redemption client from the given base URL.
    pub fn new(base_url: &url::Url) -> anyhow::Result<Self> {
        Ok(CrpcHbirdRedemptionClient {
            client: CrpcClient::new(base_url)?,
        })
    }

    /// Creates a new Hummingbird redemption client from the given base URL and [`reqwest::Client`].
    pub fn new_with_client(base_url: &url::Url, client: reqwest::Client) -> anyhow::Result<Self> {
        Ok(CrpcHbirdRedemptionClient {
            client: CrpcClient::new_with_client(base_url, client)?,
        })
    }

    /// Uses the provided token source for authentication.
    pub fn use_token_source(&mut self, token_source: Arc<dyn TokenSource>) -> &mut Self {
        self.client.use_token_source(token_source);
        self
    }
}

#[async_trait]
impl HbirdRedemptionService for CrpcHbirdRedemptionClient {
    async fn redeem(
        &self,
        requests: Vec<RedemptionRequest>,
        client_key: ClientKey,
    ) -> Result<Vec<Reservation>, HbirdRedemptionError> {
        let proto_request = to_proto_requests(requests.clone(), client_key);

        let proto_response = self
            .client
            .unary_request::<_, RedemptionResponses>(
                &format!("{HBIRD_API_V1}.{HBIRD_SERVICE}{REDEEM}"),
                proto_request,
            )
            .await
            .map_err(crpc_to_hbird_error)?;

        let reservations = from_proto_responses(proto_response, &requests)?;
        tracing::debug!("Redeemed {} flyover reservation(s)", reservations.len());
        Ok(reservations)
    }

    async fn status(&self) -> Result<StatusInfo, HbirdRedemptionError> {
        let resp = self
            .client
            .unary_request::<_, StatusResponse>(
                &format!("{HBIRD_API_V1}.{HBIRD_SERVICE}{STATUS}"),
                (),
            )
            .await
            .map_err(crpc_to_hbird_error)?;
        tracing::debug!(version = resp.version, "Hummingbird service status");
        Ok(resp.into())
    }
}

fn crpc_to_hbird_error(e: CrpcClientError) -> HbirdRedemptionError {
    HbirdRedemptionError::Transport(e.to_string())
}
