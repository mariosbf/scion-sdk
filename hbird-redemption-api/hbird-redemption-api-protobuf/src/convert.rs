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
//! Conversions between Hummingbird redemption API protobuf types and models.

use hbird_redemption_api_models::{
    ClientPrivateKey, ClientPublicKey, EgressToken, HbirdRedemptionError, IngressToken,
    RedemptionInfo, RedemptionRequest, StatusInfo,
};
use rsa::{Oaep, pkcs1::DecodeRsaPublicKey};
use scion_proto::{
    address::IsdAsn,
    hummingbird::{Bandwidth, Reservation, ReservationInfo},
    path::hummingbird::HbirdAuthKey,
};
use sha2::Sha256;

use crate::hbird::v1;

impl From<RedemptionInfo> for v1::RedemptionInfo {
    fn from(info: RedemptionInfo) -> Self {
        v1::RedemptionInfo {
            ingress: info.ingress as u32,
            egress: info.egress as u32,
            // The bandwidth travels data-plane encoded (10-bit float format);
            // the redemption service uses it as-is, without conversion.
            bw: info.bandwidth.encode() as u32,
            start_time: info.start_time.timestamp() as u32,
            duration: info.duration as u32,
        }
    }
}

impl From<RedemptionRequest> for v1::RedemptionRequest {
    fn from(req: RedemptionRequest) -> Self {
        v1::RedemptionRequest {
            red_info: Some(req.info.into()),
            ingress_token: req.ingress_token.0.to_vec(),
            egress_token: req.egress_token.0.to_vec(),
        }
    }
}

/// Converts a model request and a client key into a proto [`v1::RedemptionRequests`].
pub fn to_proto_requests(
    requests: Vec<RedemptionRequest>,
    public_key: Vec<u8>,
) -> v1::RedemptionRequests {
    v1::RedemptionRequests {
        redemption: requests.into_iter().map(Into::into).collect(),
        client_key: public_key,
    }
}

/// Converts a proto [`v1::RedemptionRequests`] into model requests and a parsed client public key.
pub fn from_proto_requests(
    req: v1::RedemptionRequests,
) -> Result<(Vec<RedemptionRequest>, ClientPublicKey), HbirdRedemptionError> {
    let client_key = ClientPublicKey::from_pkcs1_der(&req.client_key)
        .map_err(|e| HbirdRedemptionError::InvalidReservation(e.to_string()))?;

    let requests = req
        .redemption
        .into_iter()
        .map(from_proto_request)
        .collect::<Result<Vec<_>, _>>()?;

    Ok((requests, client_key))
}

fn from_proto_request(
    req: v1::RedemptionRequest,
) -> Result<RedemptionRequest, HbirdRedemptionError> {
    let red_info = req
        .red_info
        .ok_or_else(|| HbirdRedemptionError::InvalidReservation("missing red_info".into()))?;

    let info = from_proto_redemption_info(red_info)?;

    let ingress_token_bytes: [u8; 16] = req.ingress_token.try_into().map_err(|v: Vec<u8>| {
        HbirdRedemptionError::InvalidReservation(format!(
            "ingress_token must be 16 bytes, got {}",
            v.len()
        ))
    })?;

    let egress_token_bytes: [u8; 16] = req.egress_token.try_into().map_err(|v: Vec<u8>| {
        HbirdRedemptionError::InvalidReservation(format!(
            "egress_token must be 16 bytes, got {}",
            v.len()
        ))
    })?;

    Ok(RedemptionRequest {
        info,
        ingress_token: IngressToken(ingress_token_bytes),
        egress_token: EgressToken(egress_token_bytes),
    })
}

fn from_proto_redemption_info(
    info: v1::RedemptionInfo,
) -> Result<RedemptionInfo, HbirdRedemptionError> {
    let start_time =
        chrono::DateTime::from_timestamp(info.start_time as i64, 0).ok_or_else(|| {
            HbirdRedemptionError::InvalidReservation("invalid start_time timestamp".into())
        })?;

    Ok(RedemptionInfo {
        ingress: info.ingress as u16,
        egress: info.egress as u16,
        bandwidth: Bandwidth::decode(info.bw as u16),
        start_time,
        duration: info.duration as u16,
    })
}

/// Converts a proto [`v1::Reservation`] combined with the originating [`RedemptionRequest`]
/// into a [`scion_proto::hummingbird::Reservation`].
pub fn from_proto_reservation(
    res: v1::Reservation,
    req: &RedemptionRequest,
    client_key: &ClientPrivateKey,
) -> Result<Reservation, HbirdRedemptionError> {
    let auth_key = client_key.decrypt(Oaep::new::<Sha256>(), &res.auth_key)?;

    if auth_key.len() != 16 {
        return Err(HbirdRedemptionError::InvalidReservation(format!(
            "auth_key must be 16 bytes (after decryption), got {}",
            auth_key.len()
        )));
    }
    let auth_key = HbirdAuthKey::clone_from_slice(&auth_key);

    Ok(Reservation {
        info: ReservationInfo {
            isd_as: IsdAsn::from(res.ia),
            ingress_interface: req.info.ingress,
            egress_interface: req.info.egress,
            res_id: res.res_id,
            bandwidth: req.info.bandwidth,
            start: req.info.start_time.timestamp() as u32,
            duration: req.info.duration,
        },
        reservation_key: auth_key,
    })
}

/// Converts proto [`v1::RedemptionResponses`] combined with the originating requests
/// into a [`Vec<Reservation>`].
pub fn from_proto_responses(
    responses: v1::RedemptionResponses,
    requests: &[RedemptionRequest],
    client_key: &ClientPrivateKey,
) -> Result<Vec<Reservation>, HbirdRedemptionError> {
    let proto_reservations = responses.reservation;
    if proto_reservations.len() != requests.len() {
        return Err(HbirdRedemptionError::ResponseMismatch {
            expected: requests.len(),
            got: proto_reservations.len(),
        });
    }
    proto_reservations
        .into_iter()
        .zip(requests.iter())
        .map(|(res, req)| from_proto_reservation(res, req, client_key))
        .collect()
}

impl From<Reservation> for v1::Reservation {
    fn from(r: Reservation) -> Self {
        v1::Reservation {
            ia: r.info.isd_as.into(),
            res_id: r.info.res_id,
            auth_key: r.reservation_key.to_vec(),
        }
    }
}

impl From<Vec<Reservation>> for v1::RedemptionResponses {
    fn from(reservations: Vec<Reservation>) -> Self {
        v1::RedemptionResponses {
            reservation: reservations.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<v1::StatusResponse> for StatusInfo {
    fn from(r: v1::StatusResponse) -> Self {
        StatusInfo { version: r.version }
    }
}
