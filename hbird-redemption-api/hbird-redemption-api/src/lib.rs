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
//! # Hummingbird Redemption API
//!
//! Connect RPC API endpoint handlers and utilities to embed the Hummingbird
//! redemption API into an existing [`axum::Router`].
//!
//! ## Basic Usage
//!
//! ```no_run
//! use std::{net::SocketAddr, sync::Arc};
//!
//! use async_trait::async_trait;
//! use hbird_redemption_api::routes::nest_hbird_redemption_api;
//! use hbird_redemption_api_models::{
//!     ClientPublicKey, HbirdRedemptionError, HbirdRedemptionService, RedemptionRequest, StatusInfo,
//! };
//! use scion_proto::hummingbird::Reservation;
//! use tokio::net::TcpListener;
//!
//! struct MyRedemptionService;
//!
//! #[async_trait]
//! impl HbirdRedemptionService for MyRedemptionService {
//!     async fn redeem(
//!         &self,
//!         _requests: Vec<RedemptionRequest>,
//!         _client_key: ClientPublicKey,
//!     ) -> Result<Vec<Reservation>, HbirdRedemptionError> {
//!         todo!()
//!     }
//!
//!     async fn status(&self) -> Result<StatusInfo, HbirdRedemptionError> {
//!         todo!()
//!     }
//! }
//!
//! # async {
//! let base_router = axum::Router::<()>::new();
//! let router = nest_hbird_redemption_api(base_router, Arc::new(MyRedemptionService));
//!
//! let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
//!     .await
//!     .unwrap();
//! axum::serve(listener, router.into_make_service())
//!     .await
//!     .unwrap();
//! # };
//! ```

pub mod routes;
