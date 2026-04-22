//! Cryptographic functions for Hummingbird reservations.
//!
//! We divide keys into two categories:
//! - Hummingbird authentication keys: Used to authenticate attempts to use a reservation.
//!   Denoted A_K in the Hummingbird paper.
//! - Hummingbird keys: Used by ASes to derive authentication keys for
//!   reservations. Denoted SV_K in the Hummingbird paper.

use aes::cipher::{BlockEncrypt, consts::U16, generic_array::GenericArray};

use crate::{
    address::{Asn, Isd},
    hummingbird::Bandwidth,
    packet::CommonHeader,
};

/// 16-byte keys from which ASes derive Hummingbird authentication keys.
/// Denoted SV_K in the Hummingbird paper.
/// [`calculate_hbird_auth_key`] derives auth keys from this key.
pub type HbirdKey = GenericArray<u8, U16>;

/// 16-byte key used to authenticate Hummingbird reservations (by calculating
/// flyover MACs).
/// Denoted A_K in the Hummingbird paper.
pub type HbirdAuthKey = GenericArray<u8, U16>;

#[derive(Debug, thiserror::Error)]
pub enum FlyoverMacCalculationError {
    #[error("packet length overflow")]
    PacketLengthOverflow,
}

/// Calculates the flyover MAC for a flyover hop.
/// Note: Only calculates the flyover MAC, not the aggregated MAC.
///
/// Also note that some fields are not as wide as the types in the function
/// signature suggest:
/// - `dst_as` is only 48 bits wide,
/// - `millis_timestamp` is only 10 bits wide, and
/// - `counter` is only 22 bits wide.
///
/// These fields will be truncated to the appropriate width before being used in
/// the MAC.
pub fn calculate_flyover_mac(
    dst_isd: Isd,
    dst_as: Asn,
    payload_len: u16,
    res_start_offset: u16,
    millis_timestamp: u16,
    counter: u32,
    key: &HbirdAuthKey,
) -> Result<[u8; 6], FlyoverMacCalculationError> {
    use cmac::Mac;

    // Input data format (all fields are BE):
    //
    //	 0                   1                   2                   3
    //	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //	|            DstISD             |                               |
    //	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    //	|                             DstAS                             |
    //	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //	|            PktLen             |        ResStartOffset         |
    //	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //	|  MillisTimestamp  |                  Counter                  |
    //	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    let destination_address = ((dst_isd.0 as u64) << 48) | (dst_as.0 & 0xFFFFFFFFFFFF);
    let millis_and_counter = (((millis_timestamp & 0x3FF) as u32) << 22) | (counter & 0x3FFFFF);

    let pkt_len = payload_len.checked_add(4 * CommonHeader::LENGTH as u16)
        .ok_or(FlyoverMacCalculationError::PacketLengthOverflow)?;

    let mut mac_input_data = [0u8; 16];
    mac_input_data[0..8].copy_from_slice(&destination_address.to_be_bytes());
    mac_input_data[8..10].copy_from_slice(&pkt_len.to_be_bytes());
    mac_input_data[10..12].copy_from_slice(&res_start_offset.to_be_bytes());
    mac_input_data[12..16].copy_from_slice(&millis_and_counter.to_be_bytes());

    let mut maccer = cmac::Cmac::<aes::Aes128>::new(key);

    maccer.update(&mac_input_data);

    let mac: [u8; 16] = maccer.finalize().into_bytes().into();

    let mut result = [0u8; 6];
    result.copy_from_slice(&mac[..6]);

    Ok(result)
}

/// Derives the Hummingbird auth key for a reservation from the reservation key
/// and reservation parameters.
///
/// Note: Some fields are not as wide as the types in the function signature
/// suggest:
/// - `res_id` is only 22 bits wide, and
/// - `bw` is only 10 bits wide.
///
/// These fields will be truncated to the appropriate width before being used in
/// the key derivation.
pub fn calculate_hbird_auth_key(
    cons_ingress: u16,
    cons_egress: u16,
    res_id: u32,
    bw: Bandwidth,
    res_start: u32,
    res_duration: u16,
    key: &HbirdKey,
) -> HbirdAuthKey {
    use aes::cipher::KeyInit;

    // Input data format (all fields are BE):
    //
    //	 0                   1                   2                   3
    //	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //	|          ConsIngress          |          ConsEgress           |
    //	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                   ResID                   |        BW         |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                           ResStart                            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |          ResDuration          |               0               |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    let res_id_and_bw = ((res_id & 0x3FFFFF) << 10) | ((bw.encode() & 0x3FF) as u32);

    let mut key_input_data = [0u8; 16];
    key_input_data[0..2].copy_from_slice(&cons_ingress.to_be_bytes());
    key_input_data[2..4].copy_from_slice(&cons_egress.to_be_bytes());
    key_input_data[4..8].copy_from_slice(&res_id_and_bw.to_be_bytes());
    key_input_data[8..12].copy_from_slice(&res_start.to_be_bytes());
    key_input_data[12..14].copy_from_slice(&res_duration.to_be_bytes());
    // key_input_data[14..16]; // 0

    let cipher = aes::Aes128::new(key);

    let mut flyover_key = GenericArray::from([0u8; 16]);
    cipher.encrypt_block(&mut flyover_key);

    flyover_key
}

pub fn xor_in_place(a: &mut [u8], b: &[u8]) {
    a.iter_mut().zip(b.iter()).for_each(|(x, y)| *x ^= y);
}

pub fn xor(a: &[u8], b: &[u8]) -> impl Iterator<Item = u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y)
}
