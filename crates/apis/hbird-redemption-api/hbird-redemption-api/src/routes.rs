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

//! Hummingbird redemption API endpoint definitions and handlers.

use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::post};
use axum_connect_rpc::extractor::ConnectRpc;
use hbird_redemption_api_models::{HbirdRedemptionError, HbirdRedemptionService};
use hbird_redemption_api_protobuf::{
    convert::from_proto_requests,
    hbird::v1::{RedemptionRequests, RedemptionResponses, StatusResponse},
};

/// Hummingbird API package path.
pub const HBIRD_API_V1: &str = "proto.hbird.v1";

/// Hummingbird service name.
pub const HBIRD_SERVICE: &str = "HBirdService";

/// Redeem endpoint.
pub const REDEEM: &str = "/Redeem";

/// Status endpoint.
pub const STATUS: &str = "/Status";

/// Nests the Hummingbird redemption API routes into the provided `base_router`.
pub fn nest_hbird_redemption_api(
    base_router: axum::Router,
    service: Arc<dyn HbirdRedemptionService>,
) -> axum::Router {
    let hbird_router = axum::Router::new()
        .route(REDEEM, post(redeem_handler))
        .route(STATUS, post(status_handler))
        .with_state(service);
    base_router.nest(&service_path(HBIRD_API_V1, HBIRD_SERVICE), hbird_router)
}

async fn redeem_handler(
    State(service): State<Arc<dyn HbirdRedemptionService>>,
    ConnectRpc(request): ConnectRpc<RedemptionRequests>,
) -> Result<ConnectRpc<RedemptionResponses>, axum::response::Response> {
    let (requests, client_key) = from_proto_requests(request)
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()).into_response())?;

    let reservations = service.redeem(requests, client_key).await.map_err(|e| {
        match e {
            HbirdRedemptionError::Transport(msg) => {
                (axum::http::StatusCode::INTERNAL_SERVER_ERROR, msg).into_response()
            }
            other => {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    other.to_string(),
                )
                    .into_response()
            }
        }
    })?;

    Ok(ConnectRpc(reservations.into()))
}

async fn status_handler(
    State(service): State<Arc<dyn HbirdRedemptionService>>,
    ConnectRpc(_request): ConnectRpc<()>,
) -> Result<ConnectRpc<StatusResponse>, axum::response::Response> {
    service
        .status()
        .await
        .map(|info| {
            ConnectRpc(StatusResponse {
                version: info.version,
            })
        })
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
}

fn service_path(api: &str, service: &str) -> String {
    format!("/{api}.{service}")
}
