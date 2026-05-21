// Copyright 2025 Mysten Labs
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

//! SCION packets containing UDP datagrams.

use bytes::{Buf, Bytes};

use super::{InadequateBufferSize, MessageChecksum, ScionHeaders, ScionPacket, ScionPacketRaw};
use crate::{
    address::SocketAddr,
    datagram::{UdpDecodeError, UdpMessage},
    packet::{AddressHeader, ByEndpoint, EncodeError, error::HbirdEncodeError},
    path::{DataPlanePath, Path, hummingbird::HummingbirdPath},
    wire_encoding::{WireDecode, WireEncodeVec},
};

/// A SCION packet containing a UDP datagram.
#[derive(Debug, Clone, PartialEq)]
pub struct ScionPacketUdp {
    /// Packet headers
    pub headers: ScionHeaders,
    /// The contained UDP datagram
    pub datagram: UdpMessage,
}

impl ScionPacketUdp {
    /// Returns the source socket address of the UDP packet.
    pub fn source(&self) -> Option<SocketAddr> {
        self.headers
            .address
            .source()
            .map(|scion_addr| SocketAddr::new(scion_addr, self.src_port()))
    }

    /// Returns the destination socket address of the UDP packet.
    pub fn destination(&self) -> Option<SocketAddr> {
        self.headers
            .address
            .destination()
            .map(|scion_addr| SocketAddr::new(scion_addr, self.dst_port()))
    }

    /// Returns the UDP packet payload.
    pub fn payload(&self) -> &Bytes {
        &self.datagram.payload
    }

    /// Returns the UDP source port
    pub fn src_port(&self) -> u16 {
        self.datagram.port.source
    }

    /// Returns the UDP destination port
    pub fn dst_port(&self) -> u16 {
        self.datagram.port.destination
    }
}

impl ScionPacketUdp {
    /// Creates a new SCION UDP packet based on the UDP payload
    pub fn new(
        endhosts: ByEndpoint<SocketAddr>,
        path: DataPlanePath,
        payload: Bytes,
    ) -> Result<Self, EncodeError> {
        let headers = ScionHeaders::new_with_ports(
            endhosts,
            path,
            UdpMessage::PROTOCOL_NUMBER,
            payload.len() + UdpMessage::HEADER_LEN,
        )?;
        let mut datagram =
            UdpMessage::new(endhosts.map(|e| e.port()), payload).map_err(|_| todo!())?;
        datagram.set_checksum(&headers.address);

        Ok(Self { headers, datagram })
    }

    /// Creates a new SCION UDP packet pased on the UDP payload and Hummingbird
    /// path.
    pub fn new_with_hbird_path(
        endhosts: ByEndpoint<SocketAddr>,
        hbird_path: &mut HummingbirdPath,
        payload: Bytes,
    ) -> Result<(Self, Path), HbirdEncodeError> {
        let address_header = AddressHeader::from(endhosts);

        let udp_header_len =
            u16::try_from(UdpMessage::HEADER_LEN).map_err(|_| EncodeError::PayloadTooLarge)?;

        let payload_len = u16::try_from(payload.len()).map_err(|_| EncodeError::PayloadTooLarge)?;

        let payload_len = payload_len
            .checked_add(udp_header_len)
            .ok_or(EncodeError::PayloadTooLarge)?;

        let path = hbird_path.to_bytes_path(
            endhosts.source.isd_asn(),
            endhosts.destination.isd_asn(),
            payload_len,
            address_header.total_length() as u16,
            None,
        )?;

        let headers = ScionHeaders::new_with_ports(
            endhosts,
            path.data_plane_path.clone(),
            UdpMessage::PROTOCOL_NUMBER,
            payload_len as usize,
        )?;

        let mut datagram = UdpMessage::new(endhosts.map(|e| e.port()), payload)
            .map_err(|_| EncodeError::PayloadTooLarge)?;
        datagram.set_checksum(&headers.address);

        Ok((Self { headers, datagram }, path))
    }
}

impl TryFrom<ScionPacketRaw> for ScionPacketUdp {
    type Error = UdpDecodeError;

    fn try_from(mut value: ScionPacketRaw) -> Result<Self, Self::Error> {
        if value.headers.common.next_header != UdpMessage::PROTOCOL_NUMBER {
            return Err(UdpDecodeError::WrongProtocolNumber(
                value.headers.common.next_header,
            ));
        }
        Ok(Self {
            headers: value.headers,
            datagram: UdpMessage::decode(&mut value.payload)?,
        })
    }
}

impl<T: Buf> WireDecode<T> for ScionPacketUdp {
    type Error = UdpDecodeError;

    fn decode(data: &mut T) -> Result<Self, Self::Error> {
        ScionPacketRaw::decode(data)?.try_into()
    }
}

impl WireEncodeVec<3> for ScionPacketUdp {
    type Error = InadequateBufferSize;

    fn encode_with_unchecked(&self, buffer: &mut bytes::BytesMut) -> [Bytes; 3] {
        let encoded_headers = self.headers.encode_with_unchecked(buffer);
        let encoded_datagram = self.datagram.encode_with_unchecked(buffer);
        [
            encoded_headers[0].clone(),
            encoded_datagram[0].clone(),
            encoded_datagram[1].clone(),
        ]
    }

    fn total_length(&self) -> usize {
        self.headers.total_length() + self.datagram.total_length()
    }

    fn required_capacity(&self) -> usize {
        self.headers.required_capacity() + self.datagram.required_capacity()
    }
}

impl ScionPacket<3> for ScionPacketUdp {}
