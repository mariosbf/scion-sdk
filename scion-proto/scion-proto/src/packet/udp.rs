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

use super::{
    E2EExtensionHeader, ExtensionOption, InadequateBufferSize, MessageChecksum, NonEncodeError,
    PathProviderEncodeError, ScionHeaders, ScionPacket, ScionPacketRaw,
};
use crate::{
    address::SocketAddr,
    datagram::{UdpDecodeError, UdpMessage},
    packet::{AddressHeader, ByEndpoint, EncodeError},
    path::{DataPlanePath, Path, PathProvider},
    wire_encoding::{WireDecode, WireEncode, WireEncodeVec},
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

    /// Creates a new SCION UDP packet based on the UDP payload and path provider.
    pub fn new_with_path_provider<E, P>(
        endhosts: ByEndpoint<SocketAddr>,
        path_provider: &P,
        payload: Bytes,
    ) -> Result<(Self, Path), PathProviderEncodeError<E>>
    where
        E: NonEncodeError,
        P: PathProvider<Error = E>,
    {
        let address_header = AddressHeader::from(endhosts);

        let udp_header_len =
            u16::try_from(UdpMessage::HEADER_LEN).map_err(|_| EncodeError::PayloadTooLarge)?;

        let payload_len = u16::try_from(payload.len()).map_err(|_| EncodeError::PayloadTooLarge)?;

        let payload_len = payload_len
            .checked_add(udp_header_len)
            .ok_or(EncodeError::PayloadTooLarge)?;

        let path = path_provider.build(
            endhosts.map(|e| e.isd_asn()),
            payload_len,
            address_header.total_length() as u16,
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

/// Builder for [`ScionPacketUdp`] with optional end-to-end extension header support.
///
/// # Example
///
/// ```ignore
/// let (packet, path) = ScionPacketUdpBuilder::new(endhosts, &hb_path, payload)
///     .add_e2e_option(opt1, None)
///     .add_e2e_option(opt2, Some(4))  // align opt2 to a 4-byte boundary
///     .build()?;
/// ```
pub struct ScionPacketUdpBuilder<'a, P> {
    endhosts: ByEndpoint<SocketAddr>,
    path_provider: &'a P,
    payload: Bytes,
    e2e_options: Vec<ExtensionOption>,
    /// Running total of encoded bytes added to the options region, used for alignment.
    e2e_options_len: usize,
}

impl<'a, P: PathProvider> ScionPacketUdpBuilder<'a, P> {
    /// Creates a new builder for a SCION UDP packet.
    pub fn new(endhosts: ByEndpoint<SocketAddr>, path_provider: &'a P, payload: Bytes) -> Self {
        Self {
            endhosts,
            path_provider,
            payload,
            e2e_options: Vec::new(),
            e2e_options_len: 0,
        }
    }

    /// Appends an end-to-end extension option.
    ///
    /// If `align` is `Some(n)`, inserts [`ExtensionOption::Pad1`] or
    /// [`ExtensionOption::PadN`] padding before the option so that the option's
    /// first byte is at a byte offset from the start of the SCION header that is
    /// a multiple of `n`.
    /// `n` must be in `1..=255`.
    ///
    /// The E2E extension header's first byte (`next_header`) is 4-byte aligned
    /// relative to the SCION header.
    ///
    pub fn add_e2e_option(mut self, option: ExtensionOption, align: Option<usize>) -> Self {
        if let Some(align) = align {
            debug_assert!(align > 0 && align <= 255, "alignment must be in 1..=255");
            // 2 = offset of the options region from the E2E header's first byte,
            // which is itself 4-byte aligned relative to the SCION header.
            let remainder = (2 + self.e2e_options_len) % align;
            if remainder != 0 {
                let padding = align - remainder;
                if padding == 1 {
                    self.e2e_options.push(ExtensionOption::Pad1);
                    self.e2e_options_len += 1;
                } else {
                    self.e2e_options.push(ExtensionOption::PadN(padding as u8));
                    self.e2e_options_len += padding;
                }
            }
        }
        self.e2e_options_len += WireEncode::encoded_length(&option);
        self.e2e_options.push(option);
        self
    }

    /// Builds the [`ScionPacketUdp`], calling the path provider with the correct
    /// total packet size including any accumulated E2E extension options.
    pub fn build(self) -> Result<(ScionPacketUdp, Path), PathProviderEncodeError<P::Error>> {
        let address_header = AddressHeader::from(self.endhosts);

        let udp_len = u16::try_from(UdpMessage::HEADER_LEN + self.payload.len())
            .map_err(|_| EncodeError::PayloadTooLarge)?;

        let e2e_len: u16 = if self.e2e_options.is_empty() {
            0
        } else {
            let stub = E2EExtensionHeader {
                next_header: 0,
                options: self.e2e_options.clone(),
            };
            u16::try_from(WireEncode::encoded_length(&stub))
                .map_err(|_| EncodeError::PayloadTooLarge)?
        };

        let path_payload = udp_len
            .checked_add(e2e_len)
            .ok_or(EncodeError::PayloadTooLarge)?;

        let path = self.path_provider.build(
            self.endhosts.map(|e| e.isd_asn()),
            path_payload,
            address_header.total_length() as u16,
        )?;

        let mut headers = ScionHeaders::new_with_ports(
            self.endhosts,
            path.data_plane_path.clone(),
            UdpMessage::PROTOCOL_NUMBER,
            udp_len as usize,
        )?;

        if !self.e2e_options.is_empty() {
            headers.set_e2e(self.e2e_options)?;
        }

        let mut datagram = UdpMessage::new(self.endhosts.map(|e| e.port()), self.payload)
            .map_err(|_| EncodeError::PayloadTooLarge)?;
        datagram.set_checksum(&headers.address);

        Ok((ScionPacketUdp { headers, datagram }, path))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bytes::Bytes;

    use super::*;
    use crate::{
        address::{IsdAsn, SocketAddr},
        path::{DataPlanePath, Path},
        wire_encoding::WireEncode,
    };

    fn endpoints() -> ByEndpoint<SocketAddr> {
        ByEndpoint {
            source: SocketAddr::from_str("[1-1,10.0.0.1]:1000").unwrap(),
            destination: SocketAddr::from_str("[1-2,10.0.0.2]:2000").unwrap(),
        }
    }

    fn empty_path_provider() -> Path {
        Path::new(
            DataPlanePath::EmptyPath,
            ByEndpoint {
                source: IsdAsn::from_str("1-1").unwrap(),
                destination: IsdAsn::from_str("1-2").unwrap(),
            },
            None,
        )
    }

    #[test]
    fn builder_no_e2e_matches_new_with_path_provider() {
        let endhosts = endpoints();
        let provider = empty_path_provider();
        let payload = Bytes::from_static(b"hello");

        let (via_builder, _) = ScionPacketUdpBuilder::new(endhosts, &provider, payload.clone())
            .build()
            .unwrap();
        let (via_fn, _) =
            ScionPacketUdp::new_with_path_provider(endhosts, &provider, payload).unwrap();

        assert_eq!(
            via_builder.headers.common.payload_length,
            via_fn.headers.common.payload_length
        );
    }

    #[test]
    fn builder_e2e_payload_length_includes_e2e_header() {
        let endhosts = endpoints();
        let provider = empty_path_provider();
        let payload = Bytes::from_static(b"hello");

        let opt = ExtensionOption::Other {
            opt_type: 253,
            data: Bytes::from_static(&[0xde, 0xad]),
        };

        let (packet, _) = ScionPacketUdpBuilder::new(endhosts, &provider, payload.clone())
            .add_e2e_option(opt.clone(), None)
            .build()
            .unwrap();

        let e2e_header = packet.headers.e2e_extn_header.as_ref().unwrap();
        let expected_payload_len = (UdpMessage::HEADER_LEN
            + payload.len()
            + WireEncode::encoded_length(e2e_header)) as u16;

        assert_eq!(packet.headers.common.payload_length, expected_payload_len);
    }

    #[test]
    fn add_e2e_alignment_inserts_correct_padding() {
        let endhosts = endpoints();
        let provider = empty_path_provider();
        let payload = Bytes::from_static(b"test");

        // opt1: Other with 1-byte data → 2 + 1 = 3 bytes.
        // Before opt2 with align=4: effective offset = 2 (E2E prefix) + 3 = 5.
        // 5 % 4 = 1 → padding needed = 3 → PadN(3).
        let opt1 = ExtensionOption::Other {
            opt_type: 253,
            data: Bytes::from_static(&[0x01]),
        };
        let opt2 = ExtensionOption::Other {
            opt_type: 254,
            data: Bytes::from_static(&[0x02]),
        };

        let (packet, _) = ScionPacketUdpBuilder::new(endhosts, &provider, payload)
            .add_e2e_option(opt1, None)
            .add_e2e_option(opt2, Some(4))
            .build()
            .unwrap();

        let options = &packet.headers.e2e_extn_header.unwrap().options;
        // Expected: [opt1(3 bytes), PadN(3)(3 bytes), opt2(3 bytes)]
        assert_eq!(options.len(), 3);
        assert!(matches!(options[1], ExtensionOption::PadN(3)));
    }
}
