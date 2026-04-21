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
//! # Hummingbird Redemption API client
//!
//! A [`CrpcHbirdRedemptionClient`] wraps the Hummingbird redemption connectRPC
//! service (`HBirdService`) and implements [`HbirdRedemptionService`].
//!
//! ## Example Usage
//!
//! ```no_run
//! use hbird_redemption_api_client::client::CrpcHbirdRedemptionClient;
//! use hbird_redemption_api_models::HbirdRedemptionService;
//!
//! pub async fn get_status() -> anyhow::Result<()> {
//!     let client = CrpcHbirdRedemptionClient::new(
//!         &url::Url::parse("http://10.0.100.20:10131/").unwrap(),
//!     )?;
//!
//!     let status = client.status().await?;
//!     println!("Hummingbird service version: {}", status.version);
//!     Ok(())
//! }
//! ```

pub mod client;
