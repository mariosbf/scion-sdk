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

//! Integration tests for service resolution against a PocketSCION network.
//!
//! Resolution is a network round trip against the destination AS, so a unit test on the response
//! conversion proves very little; these exercise the whole path from an anycast destination to a
//! concrete transport address.
//!
//! The service resolved is always in a *remote* AS. Anycast resolution is performed by the
//! destination AS's border router, and the UDP underlay short-circuits same-AS traffic straight to
//! the destination host, which an anycast address does not have — so a same-AS request never
//! reaches anything that could answer it.
//!
//! The shared topology helpers run no control service, so this builds its own two-AS topology with
//! one registered in the remote AS.

use std::{collections::BTreeMap, num::NonZeroU16, str::FromStr, time::Duration};

use chrono::Utc;
use pocketscion::{
    comp::control_service::ControlServiceState,
    network::scion::topology::{ScionAs, ScionLink, ScionLinkType, ScionTopologyBuilder},
    runtime::builder::PocketScionRuntimeBuilder,
    state::PocketScionState,
    util::addr_to_http_url,
};
use scion_stack::stack::ScionStackBuilder;
use sciparse::{
    address::{host_addr::ServiceAddr, socket_addr::ScionSocketAddrSvc},
    identifier::isd_asn::IsdAsn,
};
use snap_tokens::v0::dummy_snap_token;
use svc_resolution_client::UdpScionServiceResolutionClient;
use svc_resolution_models::{ServiceResolver, SvcResolutionError};
use test_log::test;

const TIMEOUT: Duration = Duration::from_secs(5);

/// The address the remote AS's control service is registered at, and therefore the address
/// resolution must hand back.
const CS_ADDR: &str = "1.2.3.4:12345";

struct Fixture {
    client: UdpScionServiceResolutionClient,
    remote_ia: IsdAsn,
    // Keeps the simulated network alive for the duration of the test.
    _runtime: pocketscion::runtime::PocketScionRuntime,
}

/// Two core ASes linked directly, each with a router, and a control service in the remote one.
async fn fixture() -> Fixture {
    scion_sdk_utils::rustls::select_ring_crypto_provider();

    let local_ia = IsdAsn::from_str("1-ff00:0:110").unwrap();
    let remote_ia = IsdAsn::from_str("1-ff00:0:111").unwrap();

    let mut pstate = PocketScionState::new(Utc::now());

    let mut topo = ScionTopologyBuilder::new();
    topo.add_as(ScionAs::new_core(local_ia))
        .unwrap()
        .add_as(ScionAs::new_core(remote_ia))
        .unwrap()
        .add_link(ScionLink::new(local_ia, 1, ScionLinkType::Core, remote_ia, 2).unwrap())
        .unwrap();
    pstate.set_topology(topo.build().unwrap());

    let endhost_api = pstate.add_endhost_api(vec![local_ia]);
    pstate.add_router(
        local_ia,
        vec![NonZeroU16::new(1).unwrap()],
        vec![],
        BTreeMap::new(),
    );
    pstate.add_router(
        remote_ia,
        vec![NonZeroU16::new(2).unwrap()],
        vec![],
        BTreeMap::new(),
    );

    // Registering the control service is what creates the QUIC transport mapping that the
    // remote AS answers resolution requests with.
    let mut cs = ControlServiceState::new();
    cs.set_virtual_addr(CS_ADDR.parse().unwrap());
    pstate.add_control_service(remote_ia, cs).unwrap();

    let runtime = PocketScionRuntimeBuilder::new()
        .with_system_state(pstate)
        .start()
        .await
        .expect("start PocketSCION");

    let endhost_api_url = addr_to_http_url(runtime.endhost_api_addr(endhost_api).unwrap());
    let stack = ScionStackBuilder::new()
        .with_endhost_api(endhost_api_url)
        .with_auth_token(dummy_snap_token())
        .build()
        .await
        .expect("build SCION stack");
    let socket = stack.bind(None).await.expect("bind socket");

    Fixture {
        client: UdpScionServiceResolutionClient::new(socket, Some(TIMEOUT)),
        remote_ia,
        _runtime: runtime,
    }
}

#[test(tokio::test)]
#[ntest::timeout(15_000)]
async fn resolves_the_control_service_to_a_concrete_transport_address() {
    let fx = fixture().await;

    let response = fx
        .client
        .resolve(ScionSocketAddrSvc::new(
            fx.remote_ia,
            ServiceAddr::CONTROL,
            0,
        ))
        .await
        .expect("control service should resolve");

    // The point of resolution: an anycast address in, the concrete host:port the remote AS
    // registered out.
    assert_eq!(response.quic_address, CS_ADDR.parse().unwrap());
}

#[test(tokio::test)]
#[ntest::timeout(15_000)]
async fn unmapped_service_reports_no_quic_transport() {
    let fx = fixture().await;

    // Nothing registers a transport for the daemon anycast address, so the AS answers with an
    // empty transport map rather than staying silent — which must surface as a distinct error and
    // not as a timeout.
    let result = fx
        .client
        .resolve(ScionSocketAddrSvc::new(
            fx.remote_ia,
            ServiceAddr::DAEMON,
            0,
        ))
        .await;

    assert!(
        matches!(result, Err(SvcResolutionError::NoQuicTransport)),
        "expected NoQuicTransport, got {result:?}"
    );
}
