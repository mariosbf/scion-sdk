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
};

/// 16-byte keys from which ASes derive Hummingbird authentication keys.
/// Denoted SV_K in the Hummingbird paper.
/// [`calculate_hbird_auth_key`] derives auth keys from this key.
pub type HbirdKey = GenericArray<u8, U16>;

/// 16-byte key used to authenticate Hummingbird reservations (by calculating
/// flyover MACs).
/// Denoted A_K in the Hummingbird paper.
pub type HbirdAuthKey = GenericArray<u8, U16>;

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
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
    pkt_len: u16,
    res_start_offset: u16,
    millis_timestamp: u16,
    counter: u32,
    key: &HbirdAuthKey,
) -> [u8; 6] {
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

    let mut mac_input_data = [0u8; 16];
    mac_input_data[0..8].copy_from_slice(&destination_address.to_be_bytes());
    mac_input_data[8..10].copy_from_slice(&pkt_len.to_be_bytes());
    mac_input_data[10..12].copy_from_slice(&res_start_offset.to_be_bytes());
    mac_input_data[12..16].copy_from_slice(&millis_and_counter.to_be_bytes());

    println!("MAC input data: {:02x?}", mac_input_data);

    use aes::cipher::KeyInit;

    let cipher = aes::Aes128::new(key);
    let mut block = GenericArray::from(mac_input_data);
    cipher.encrypt_block(&mut block);

    let mut result = [0u8; 6];
    result.copy_from_slice(&block[..6]);

    result
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

    let mut flyover_key = GenericArray::from(key_input_data);
    cipher.encrypt_block(&mut flyover_key);

    flyover_key
}

pub fn xor_in_place(a: &mut [u8], b: &[u8]) {
    a.iter_mut().zip(b.iter()).for_each(|(x, y)| *x ^= y);
}

pub fn xor(a: &[u8], b: &[u8]) -> impl Iterator<Item = u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y)
}

#[cfg(test)]
mod tests {
    use crate::{
        address::{Asn, Isd},
        path::hummingbird::{HbirdAuthKey, calculate_flyover_mac, xor},
    };

    #[test]
    pub fn correct_mac() {
        // Verifying flyover MAC {"ingress": 1, "egress": 2, "resID": 1, "Bw": 82, "startTime": 3, "Duration": 9,
        //   "ak": "66584cd6050116c228cc3b4dc2c9cc56"}
        // FullFlyoverMac input {"dstIA": "1-ff00:0:112", "pktlen": 22, "resStartTime": 3, "highResTime": 1476395008}
        // FullFlyoverMac buffer {"buffer": "AAH/AAAAARIAFgADWAAAAA=="}
        //   -> ISD=1, AS=ff00:0:112, pktlen=22, resStartOffset=3, highResTS=0x58000000
        //   -> millis=(0x58000000>>22)&0x3FF=352, counter=0
        // SCMP: Aggregate MAC verification failed
        //   {"expected": "39e6852b6e88", "scionMac": "c8ca9ceb3060", ...}
        //   -> flyover_mac = expected XOR scionMac = f1 2c 19 c0 5e e8

        let correct_aggregate_mac = [0x39, 0xe6, 0x85, 0x2b, 0x6e, 0x88];
        let scion_mac = [0xc8, 0xca, 0x9c, 0xeb, 0x30, 0x60];

        let correct_flyover_mac: [u8; 6] = xor(&correct_aggregate_mac, &scion_mac)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();

        let pkt_len = 22u16;
        let res_start_offset = 3u16;
        let millis_timestamp = 352u16; // (0x58000000 >> 22) & 0x3FF
        let counter = 0u32;

        let auth_key: HbirdAuthKey = [
            0x66, 0x58, 0x4c, 0xd6, 0x05, 0x01, 0x16, 0xc2, 0x28, 0xcc, 0x3b, 0x4d, 0xc2, 0xc9,
            0xcc, 0x56,
        ]
        .into();

        let flyover_mac = calculate_flyover_mac(
            Isd(1),
            Asn(0xFF00_0000_0112),
            pkt_len,
            res_start_offset,
            millis_timestamp,
            counter,
            &auth_key,
        );

        assert_eq!(flyover_mac, correct_flyover_mac);
    }
}
