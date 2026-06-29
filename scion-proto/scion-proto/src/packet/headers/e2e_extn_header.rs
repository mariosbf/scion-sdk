use bytes::{Buf, BufMut, Bytes};

use crate::{
    packet::{DecodeError, InadequateBufferSize},
    wire_encoding::{WireDecode, WireEncode},
};

/// SCION packet end-to-end extension header.
///
/// The end-to-end options header carries optional information intended to be examined
/// and processed only by the sender and/or the receiving endpoints of the packet.
/// It contains one or more TLV-encoded options and must appear at most once per packet,
/// after the hop-by-hop options header if that is also present. See the
/// [IETF SCION-dataplane RFC draft][rfc] for details about the end-to-end options header.
///
/// Wire format (4-byte aligned):
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    NextHdr    |     ExtLen    |            Options            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// [rfc]: https://scionassociation.github.io/scion-dp_I-D/draft-dekater-scion-dataplane.html#name-extension-headers
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct E2EExtensionHeader {
    /// Next layer SCION protocol number.
    ///
    /// Identifies the type of header immediately following this extension header.
    /// See the [IETF SCION-dataplane RFC draft][rfc] for possible values.
    ///
    /// [rfc]: https://scionassociation.github.io/scion-dp_I-D/draft-dekater-scion-dataplane.html#protnum
    pub next_header: u8,

    /// TLV-encoded options carried in this header.
    ///
    /// Options must be processed strictly in the order they appear. On encoding,
    /// padding is added automatically to satisfy the 4-byte alignment requirement;
    /// explicit [`ExtensionOption::Pad1`] or [`ExtensionOption::PadN`] options are
    /// only needed for intra-option alignment, not trailing alignment.
    pub options: Vec<ExtensionOption>,
}

impl E2EExtensionHeader {
    /// Total wire length of this header in bytes (always a multiple of 4).
    pub fn total_length(&self) -> usize {
        let opts = self.options_encoded_length();
        2 + opts + Self::padding_needed(opts)
    }

    /// `ExtLen` wire field value: `total_length / 4 - 1`.
    pub fn ext_len(&self) -> u8 {
        (self.total_length() / 4 - 1) as u8
    }

    fn options_encoded_length(&self) -> usize {
        self.options.iter().map(ExtensionOption::encoded_length).sum()
    }

    /// Bytes of trailing padding required so that `total_header = 2 + opts + padding`
    /// is a multiple of 4.
    fn padding_needed(options_len: usize) -> usize {
        (4 - (options_len + 2) % 4) % 4
    }
}

impl<T: Buf> WireDecode<T> for E2EExtensionHeader {
    type Error = DecodeError;

    fn decode(data: &mut T) -> Result<Self, Self::Error> {
        if data.remaining() < 2 {
            return Err(DecodeError::PacketEmptyOrTruncated);
        }
        let next_header = data.get_u8();
        let ext_len = data.get_u8();

        let options_len = (usize::from(ext_len) + 1) * 4 - 2;
        if data.remaining() < options_len {
            return Err(DecodeError::PacketEmptyOrTruncated);
        }

        let mut options_buf = data.copy_to_bytes(options_len);
        let mut options = Vec::new();
        while options_buf.has_remaining() {
            options.push(ExtensionOption::decode(&mut options_buf)?);
        }

        Ok(Self {
            next_header,
            options,
        })
    }
}

impl WireEncode for E2EExtensionHeader {
    type Error = InadequateBufferSize;

    fn encoded_length(&self) -> usize {
        self.total_length()
    }

    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        buffer.put_u8(self.next_header);
        buffer.put_u8(self.ext_len());

        for option in &self.options {
            option.encode_to_unchecked(buffer);
        }

        match Self::padding_needed(self.options_encoded_length()) {
            0 => {}
            1 => buffer.put_u8(ExtensionOption::OPT_TYPE_PAD1),
            n => {
                buffer.put_u8(ExtensionOption::OPT_TYPE_PADN);
                buffer.put_u8((n - 2) as u8);
                for _ in 0..(n - 2) {
                    buffer.put_u8(0);
                }
            }
        }
    }
}

/// A TLV-encoded option in the SCION extension header options field.
///
/// Wire formats:
///
/// Pad1 (single zero byte, no length/value fields):
/// ```text
///  0
///  0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+
/// |       0       |
/// +-+-+-+-+-+-+-+-+
/// ```
///
/// PadN (N >= 2 bytes of padding):
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       1       |  OptDataLen   |         Zero padding          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Other (unknown/custom type):
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    OptType    |  OptDataLen   |            OptData            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
/// |                              . . .                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ExtensionOption {
    /// Single byte of padding (OptType=0). No length or value fields.
    Pad1,

    /// N bytes of padding total (OptType=1, N >= 2).
    ///
    /// Wire encoding: `[0x01, N-2, 0x00, ..., 0x00]` (N-2 zero data bytes).
    PadN(u8),

    /// Unknown or custom option type.
    Other {
        /// The 8-bit option type identifier.
        opt_type: u8,
        /// The option data payload.
        data: Bytes,
    },
}

impl ExtensionOption {
    /// OptType=0: single-byte padding.
    pub const OPT_TYPE_PAD1: u8 = 0;
    /// OptType=1: multi-byte padding.
    pub const OPT_TYPE_PADN: u8 = 1;
    /// OptType=2: SCION Packet Authenticator Option (E2E only, experimental).
    pub const OPT_TYPE_AUTHENTICATOR: u8 = 2;

    fn encoded_length(&self) -> usize {
        match self {
            ExtensionOption::Pad1 => 1,
            ExtensionOption::PadN(n) => usize::from(*n),
            ExtensionOption::Other { data, .. } => 2 + data.len(),
        }
    }
}

impl<T: Buf> WireDecode<T> for ExtensionOption {
    type Error = DecodeError;

    fn decode(data: &mut T) -> Result<Self, Self::Error> {
        if !data.has_remaining() {
            return Err(DecodeError::PacketEmptyOrTruncated);
        }
        let opt_type = data.get_u8();
        match opt_type {
            Self::OPT_TYPE_PAD1 => Ok(ExtensionOption::Pad1),
            Self::OPT_TYPE_PADN => {
                if !data.has_remaining() {
                    return Err(DecodeError::PacketEmptyOrTruncated);
                }
                let opt_data_len = data.get_u8();
                if data.remaining() < usize::from(opt_data_len) {
                    return Err(DecodeError::PacketEmptyOrTruncated);
                }
                data.advance(usize::from(opt_data_len));
                Ok(ExtensionOption::PadN(opt_data_len + 2))
            }
            _ => {
                if !data.has_remaining() {
                    return Err(DecodeError::PacketEmptyOrTruncated);
                }
                let opt_data_len = usize::from(data.get_u8());
                if data.remaining() < opt_data_len {
                    return Err(DecodeError::PacketEmptyOrTruncated);
                }
                let option_data = data.copy_to_bytes(opt_data_len);
                Ok(ExtensionOption::Other {
                    opt_type,
                    data: option_data,
                })
            }
        }
    }
}

impl WireEncode for ExtensionOption {
    type Error = InadequateBufferSize;

    fn encoded_length(&self) -> usize {
        self.encoded_length()
    }

    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        match self {
            ExtensionOption::Pad1 => buffer.put_u8(Self::OPT_TYPE_PAD1),
            ExtensionOption::PadN(n) => {
                buffer.put_u8(Self::OPT_TYPE_PADN);
                buffer.put_u8(*n - 2);
                for _ in 0..(*n - 2) {
                    buffer.put_u8(0);
                }
            }
            ExtensionOption::Other { opt_type, data } => {
                buffer.put_u8(*opt_type);
                buffer.put_u8(data.len() as u8);
                buffer.put_slice(data);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // options: Other(2-byte data) = 4 bytes. padding_needed(4) = (4-(4+2)%4)%4 = 2.
    // total = 2 + 4 + 2 = 8, ext_len = 1.
    fn sample_header() -> E2EExtensionHeader {
        E2EExtensionHeader {
            next_header: 17,
            options: vec![ExtensionOption::Other {
                opt_type: 253,
                data: Bytes::from_static(&[0xde, 0xad]),
            }],
        }
    }

    #[test]
    fn total_length_is_multiple_of_4() {
        for n_data_bytes in 0usize..=16 {
            let header = E2EExtensionHeader {
                next_header: 0,
                options: vec![ExtensionOption::Other {
                    opt_type: 253,
                    data: Bytes::from(vec![0u8; n_data_bytes]),
                }],
            };
            assert_eq!(header.total_length() % 4, 0, "n_data_bytes={n_data_bytes}");
        }
    }

    #[test]
    fn empty_options_minimum_header() {
        let header = E2EExtensionHeader {
            next_header: 0,
            options: vec![],
        };
        // 0 opts → padding=2 → total=4, ext_len=0
        assert_eq!(header.total_length(), 4);
        assert_eq!(header.ext_len(), 0);
    }

    #[test]
    fn encode_auto_pads() {
        let header = sample_header();
        let encoded = header.encode_to_bytes();
        assert_eq!(encoded.len(), 8);
        assert_eq!(encoded[1], 1); // ext_len = 1
        // Last 2 bytes are auto-padding: PadN(2) = [0x01, 0x00]
        assert_eq!(&encoded[6..], &[0x01, 0x00]);
    }

    #[test]
    fn decode_includes_padding_options() {
        let header = sample_header();
        let encoded = header.encode_to_bytes();
        let decoded = E2EExtensionHeader::decode(&mut encoded.clone()).expect("decode succeeds");

        assert_eq!(decoded.next_header, 17);
        assert_eq!(decoded.options.len(), 2);
        assert_eq!(decoded.options[0], header.options[0]);
        assert_eq!(decoded.options[1], ExtensionOption::PadN(2));
    }

    #[test]
    fn encode_decode_stable() {
        // A decoded header re-encodes to identical bytes (padding is now explicit in options).
        let encoded = sample_header().encode_to_bytes();
        let decoded = E2EExtensionHeader::decode(&mut encoded.clone()).expect("decode");
        assert_eq!(decoded.encode_to_bytes(), encoded);
    }

    #[test]
    fn pad1_option_roundtrip() {
        let option = ExtensionOption::Pad1;
        let encoded = option.encode_to_bytes();
        assert_eq!(encoded.as_ref(), &[0x00]);
        assert_eq!(ExtensionOption::decode(&mut encoded.clone()).unwrap(), option);
    }

    #[test]
    fn padn_option_roundtrip() {
        let option = ExtensionOption::PadN(4);
        let encoded = option.encode_to_bytes();
        assert_eq!(encoded.as_ref(), &[0x01, 0x02, 0x00, 0x00]);
        assert_eq!(ExtensionOption::decode(&mut encoded.clone()).unwrap(), option);
    }
}
