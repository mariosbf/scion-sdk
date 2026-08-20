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

//! # Hummingbird Redemption API client
//!
//! A [`CrpcHbirdRedemptionClient`] wraps the Hummingbird redemption connectRPC
//! service (`HBirdService`) and implements [`HbirdRedemptionService`].
//!
//! The client reaches the target AS's Hummingbird service via direct HTTP if the target AS is
//! local, or via SCION service-address routing (HTTP/3 over QUIC) for remote ASes.
//!
//! A remote service that speaks stock QUIC, or presents a control-plane PKI certificate, needs a
//! custom QUIC configuration — see
//! [`with_quic_config`](client::CrpcHbirdRedemptionClient::with_quic_config).
//!
//! ## Example Usage
//!
//! ```no_run
//! use std::{net::IpAddr, str::FromStr, sync::Arc, time::SystemTime};
//!
//! use hbird_redemption_api_client::client::{
//!     CrpcHbirdRedemptionClient, RedemptionRequestWithIsdAsn,
//! };
//! use hbird_redemption_api_models::{EgressToken, IngressToken, RedemptionInfo};
//! use scion_stack::ScionStackBuilder;
//! use sciparse::{
//!     address::ip_addr::ScionIpAddr, hummingbird::Bandwidth, identifier::isd_asn::IsdAsn,
//! };
//!
//! pub async fn redeem_flyover() -> anyhow::Result<()> {
//!     let stack = Arc::new(
//!         ScionStackBuilder::new()
//!             .with_endhost_api("http://127.0.0.1:48080/".parse()?)
//!             .build()
//!             .await?,
//!     );
//!     let local_isd_asn = IsdAsn::from_str("1-ff00:0:111")?;
//!     let local_ip: IpAddr = "127.0.0.1".parse()?;
//!     let local_addr = ScionIpAddr::new(local_isd_asn, local_ip);
//!     let local_hbird_service_url = "http://127.0.0.1:30258/".parse()?;
//!
//!     let client =
//!         CrpcHbirdRedemptionClient::new(stack, local_hbird_service_url, local_addr).await?;
//!
//!     let request = RedemptionRequestWithIsdAsn {
//!         isd_asn: IsdAsn::from_str("1-ff00:0:110")?,
//!         info: RedemptionInfo {
//!             ingress: 1,
//!             egress: 2,
//!             bandwidth: Bandwidth::from_bytes_per_sec(1024).unwrap(),
//!             start_time: SystemTime::now(),
//!             duration: 60,
//!         },
//!         ingress_token: IngressToken([0u8; 16]),
//!         egress_token: EgressToken([0u8; 16]),
//!     };
//!     let reservation = client.redeem_single(request).await?;
//!     println!("Redeemed reservation: {:?}", reservation);
//!     Ok(())
//! }
//! ```

pub mod client;
