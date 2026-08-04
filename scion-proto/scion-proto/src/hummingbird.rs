//! Hummingbird-specific types and functions.
//!
//! See also [path::hummingbird].

use std::{
    sync::{Arc, OnceLock},
    time::SystemTime,
};

use aes::{Aes128Enc, cipher::KeyInit};
use bytes::{Buf, BufMut, Bytes};
use chrono::{DateTime, Duration, Utc};

use crate::{
    address::IsdAsn,
    packet::{DecodeError, InadequateBufferSize},
    path::hummingbird::{HbirdAuthKey, calculate_flyover_mac_with_cipher},
    wire_encoding::{WireDecode, WireEncode},
};

/// Maximum allowed clock skew, in seconds, when checking reservation/MAC
/// freshness against the current time.
pub const MAX_FRESHNESS_TOLERANCE: i64 = 5;

/// Bandwidth for Hummingbird reservations, in bytes per second.
///
/// Stored as a 10-bit floating-point encoding (5-bit exponent, 5-bit
/// significand), matching the data-plane wire format from the Hummingbird
/// paper. The encoded value travels end-to-end unmodified: it is what the
/// redemption service derives the authentication key from and what the border
/// router decodes (as bytes per second) to enforce the bandwidth restriction.
#[derive(Clone, PartialEq, Eq, Hash, Copy, Debug, Default)]
pub struct Bandwidth {
    /// Exponent
    exponent: u8,

    /// Significand
    significand: u8,
}

impl Bandwidth {
    /// The length of the bandwidth encoding in bits.
    pub const ENCODED_LENGTH: usize = 10;

    /// The number of bits used for the exponent in the bandwidth encoding.
    pub const EXPONENT_BITS: usize = 5;

    /// The number of bits used for the significand in the bandwidth encoding.
    pub const SIGNIFICAND_BITS: usize = Self::ENCODED_LENGTH - Self::EXPONENT_BITS;

    /// The maximum value of the bandwidth encoding, which is 2^10 - 1 = 1023.
    pub const MASK: u16 = (1 << Self::ENCODED_LENGTH) - 1;

    /// Creates a new Bandwidth from a given bandwidth in bytes per second.
    /// Returns an error if the bandwidth is too large to be represented in the
    /// 10-bit encoding. If the value is not exactly representable, the closest
    /// representation that is less than the provided bandwidth is used.
    pub fn from_bytes_per_sec(bytes_per_sec: u64) -> Result<Self, String> {
        let max_significand = (1 << Self::SIGNIFICAND_BITS) - 1;
        let max_exponent = (1 << Self::EXPONENT_BITS) - 1;

        // Special case: exponent = 0
        if bytes_per_sec <= max_significand {
            return Ok(Self {
                exponent: 0,
                significand: bytes_per_sec as u8,
            });
        }

        let exponent = 64 - (bytes_per_sec.leading_zeros() as usize) - Self::SIGNIFICAND_BITS;
        if exponent > max_exponent {
            return Err(format!(
                "bandwidth too large, cannot convert to wire format: {} bytes/s",
                bytes_per_sec
            ));
        }

        // Compute significand: shift right by (exponent - 1), then subtract the
        // implicit prepended '1'.
        let significand = (bytes_per_sec >> (exponent - 1)) - (1 << Self::SIGNIFICAND_BITS);

        Ok(Self {
            exponent: exponent as u8,
            significand: significand as u8,
        })
    }

    /// Converts the bandwidth to bytes per second.
    pub fn to_bytes_per_sec(&self) -> u64 {
        if self.exponent == 0 {
            self.significand as u64
        } else {
            ((self.significand as u64) + (1 << Self::SIGNIFICAND_BITS))
                << (self.exponent - 1) as u64
        }
    }

    /// Encodes the bandwidth as a 16-bit integer.
    /// Note that the bandwidth is encoded as a 10-bit value. Thus, the leading 6
    /// bits of the encoded value are always 0.
    pub fn encode(&self) -> u16 {
        ((self.exponent as u16) << Self::SIGNIFICAND_BITS) | (self.significand as u16)
    }

    /// Decodes a 16-bit integer to a Bandwidth. Note that the bandwidth is
    /// encoded as a 10-bit value. Thus, if the leading 6 bits of the input are
    /// not 0, the function will return an error.
    pub fn decode(encoded: u16) -> Self {
        let exponent = (encoded >> Self::SIGNIFICAND_BITS) as u8;
        let significand = (encoded & ((1 << Self::SIGNIFICAND_BITS) - 1)) as u8;
        Self {
            exponent,
            significand,
        }
    }
}

impl PartialOrd for Bandwidth {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Bandwidth {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_bytes_per_sec().cmp(&other.to_bytes_per_sec())
    }
}

/// Information about a Hummingbird reservation.
///
/// Wire format:
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |              ISD              |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+              AS               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           ConsIngress         |           ConsEgress          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   ResID                   |        BW         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           ResStart                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          ResDuration          |            Padding            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationInfo {
    /// The ISD-AS for which bandwidth was reserved.
    pub isd_as: IsdAsn,

    /// The ingress interface for which bandwidth was reserved.
    pub ingress_interface: u16,

    /// The egress interface for which bandwidth was reserved.
    pub egress_interface: u16,

    /// The reservation ID.
    pub res_id: u32,

    /// The reserved bandwidth.
    pub bandwidth: Bandwidth,

    /// The start time of the reservation.
    pub start: DateTime<Utc>,

    /// The duration for which the bandwidth is reserved in seconds.
    pub duration: u16,
}

impl ReservationInfo {
    /// The start time of the reservation.
    pub fn start(&self) -> DateTime<Utc> {
        self.start
    }

    /// The end time of the reservation, i.e., when the reservation expires.
    pub fn end(&self) -> DateTime<Utc> {
        self.start + Duration::seconds(self.duration as i64)
    }

    /// Returns whether the reservation's validity window has passed.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.end()
    }

    /// Returns whether the reservation is valid right now, i.e. its validity
    /// window has started but not yet passed.
    pub fn is_valid_now(&self) -> bool {
        let now = Utc::now();
        self.start <= now && now < self.end()
    }

    /// Returns the encoding of the reservation start time according to the
    /// Hummingbird specification.
    pub fn encode_start(&self) -> u32 {
        self.start.timestamp() as u32
    }

    /// Returns the result of decoding `value` as start time according to the
    /// Hummingbird specification
    pub fn decode_start(value: u32) -> DateTime<Utc> {
        DateTime::from_timestamp(value as i64, 0).unwrap()
    }

    /// Computes `ResStartOffset`: the number of whole seconds between this
    /// reservation's start and `base_timestamp` (a path meta header's base
    /// timestamp — a Unix timestamp with 1-second granularity).
    ///
    /// Returns `None` if `base_timestamp` is before the reservation's start, or
    /// if the offset does not fit in the 16-bit wire encoding.
    pub fn res_start_offset(&self, base_timestamp: u32) -> Option<u16> {
        u16::try_from(i64::from(base_timestamp) - self.start.timestamp()).ok()
    }
}

impl ReservationInfo {
    /// Wire-encoded length of a [`ReservationInfo`] in bytes.
    pub const ENCODED_LENGTH: usize = 24;
}

impl WireEncode for ReservationInfo {
    type Error = InadequateBufferSize;

    fn encoded_length(&self) -> usize {
        Self::ENCODED_LENGTH
    }

    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        buffer.put_u64(self.isd_as.0);
        buffer.put_u16(self.ingress_interface);
        buffer.put_u16(self.egress_interface);
        let res_id_and_bw = ((self.res_id & 0x3F_FFFF) << 10) | self.bandwidth.encode() as u32;
        buffer.put_u32(res_id_and_bw);
        buffer.put_u32(self.encode_start());
        buffer.put_u16(self.duration);
        buffer.put_u16(0); // padding
    }
}

impl WireDecode<Bytes> for ReservationInfo {
    type Error = DecodeError;

    fn decode(data: &mut Bytes) -> Result<Self, Self::Error> {
        if data.remaining() < Self::ENCODED_LENGTH {
            return Err(DecodeError::PacketEmptyOrTruncated);
        }
        let isd_as = IsdAsn(data.get_u64());
        let ingress_interface = data.get_u16();
        let egress_interface = data.get_u16();
        let res_id_and_bw = data.get_u32();
        let res_id = res_id_and_bw >> 10;
        let bandwidth = Bandwidth::decode((res_id_and_bw & 0x3FF) as u16);
        let res_start = data.get_u32();
        let start = ReservationInfo::decode_start(res_start);
        let duration = data.get_u16();
        let _ = data.get_u16(); // padding
        Ok(Self {
            isd_as,
            ingress_interface,
            egress_interface,
            res_id,
            bandwidth,
            start,
            duration,
        })
    }
}

/// A full Hummingbird reservation.
///
/// Wire format:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |              ISD              |                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+              AS               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           ConsIngress         |           ConsEgress          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   ResID                   |        BW         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           ResStart                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          ResDuration          |            Padding            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                       ReservationKey                          +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone)]
pub struct Reservation {
    /// Information about the reservation.
    ///
    /// Kept private so it cannot change after construction: [`Self::valid_from`]
    /// and [`Self::valid_until`] cache its validity window.
    info: ReservationInfo,

    /// The key used to authenticate use of this reservation.
    ///
    /// Kept private so it cannot change after construction: [`Self::cipher`]
    /// caches the AES key schedule derived from it.
    reservation_key: HbirdAuthKey,

    /// Start of the validity window, precomputed from `info`.
    ///
    /// Reservation selection tests this once per candidate per packet, and
    /// converting `info.start` out of the chrono calendar representation each
    /// time dominated the cost of selection (it runs the civil-from-days
    /// algorithm). Storing both bounds reduces the test to two integer
    /// comparisons.
    valid_from: SystemTime,

    /// End of the validity window, precomputed from `info`. Inclusive.
    valid_until: SystemTime,

    /// AES key schedule for `reservation_key`, expanded lazily on first MAC
    /// computation and reused for the lifetime of the reservation.
    ///
    /// Behind an [`Arc`] so that the reservation stays small (it is moved and
    /// cloned per packet on the encoding hot path) and so that clones share
    /// the cache: the encoder clones the stored reservation before computing
    /// MACs, and the expansion done through a clone must warm the original.
    cipher: Arc<OnceLock<Aes128Enc>>,
}

impl PartialEq for Reservation {
    fn eq(&self, other: &Self) -> bool {
        // The cipher is a pure function of `reservation_key`; its cache state
        // must not affect equality.
        self.info == other.info && self.reservation_key == other.reservation_key
    }
}

impl Eq for Reservation {}

impl Reservation {
    /// Wire-encoded length of a [`Reservation`] in bytes.
    pub const ENCODED_LENGTH: usize = ReservationInfo::ENCODED_LENGTH + 16;

    /// Creates a new reservation from its info and authentication key.
    pub fn new(info: ReservationInfo, reservation_key: HbirdAuthKey) -> Self {
        Self {
            valid_from: info.start().into(),
            valid_until: info.end().into(),
            info,
            reservation_key,
            cipher: Arc::new(OnceLock::new()),
        }
    }

    /// Information about the reservation.
    pub fn info(&self) -> &ReservationInfo {
        &self.info
    }

    /// The key used to authenticate use of this reservation.
    pub fn reservation_key(&self) -> &HbirdAuthKey {
        &self.reservation_key
    }

    /// Whether this reservation's validity window contains `now`.
    ///
    /// Both bounds are inclusive — unlike [`Self::is_valid_now`], whose upper
    /// bound is exclusive. This is the check reservation trackers perform when
    /// selecting a reservation for a packet.
    pub fn is_valid_at(&self, now: SystemTime) -> bool {
        self.valid_from <= now && now <= self.valid_until
    }

    /// The AES key schedule for [`Self::reservation_key`], expanded on first
    /// use and cached.
    pub(crate) fn cipher(&self) -> &Aes128Enc {
        self.cipher
            .get_or_init(|| Aes128Enc::new(&self.reservation_key))
    }

    /// Returns whether the reservation's validity window has passed.
    pub fn is_expired(&self) -> bool {
        self.info.is_expired()
    }

    /// Returns whether the reservation is valid right now, i.e. its validity
    /// window has started but not yet passed.
    pub fn is_valid_now(&self) -> bool {
        self.info.is_valid_now()
    }

    /// Generates the flyover MAC for this reservation, for a packet of length
    /// `pkt_len` bound for `destination`, sent at `timestamp`.
    ///
    /// `counter` defaults to `0` when `None`.
    ///
    /// Note: this computes only the flyover MAC, not the aggregated MAC — the
    /// caller must XOR it with the underlying standard hop field's MAC.
    ///
    /// Returns `None` if `timestamp` is before this reservation's start, or if
    /// the resulting start offset does not fit in the wire encoding.
    pub fn generate_flyover_mac(
        &self,
        destination: IsdAsn,
        pkt_len: u16,
        timestamp: DateTime<Utc>,
        counter: Option<u32>,
    ) -> Option<FlyoverMAC> {
        let base_timestamp = u32::try_from(timestamp.timestamp()).ok()?;
        let res_start_offset = self.info.res_start_offset(base_timestamp)?;
        let millis_timestamp = timestamp.timestamp_subsec_millis() as u16;
        let counter = counter.unwrap_or(0);

        let mac = calculate_flyover_mac_with_cipher(
            destination.isd(),
            destination.asn(),
            pkt_len,
            res_start_offset,
            millis_timestamp,
            counter,
            self.cipher(),
        );

        Some(FlyoverMAC {
            mac,
            reservation_info: self.info.clone(),
            dst_isd_asn: destination,
            base_timestamp,
            millis_timestamp,
            counter,
            packet_length: pkt_len,
        })
    }
}

impl WireEncode for Reservation {
    type Error = InadequateBufferSize;

    fn encoded_length(&self) -> usize {
        Self::ENCODED_LENGTH
    }

    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        self.info.encode_to_unchecked(buffer);
        buffer.put_slice(self.reservation_key.as_slice());
    }
}

impl WireDecode<Bytes> for Reservation {
    type Error = DecodeError;

    fn decode(data: &mut Bytes) -> Result<Self, Self::Error> {
        if data.remaining() < Self::ENCODED_LENGTH {
            return Err(DecodeError::PacketEmptyOrTruncated);
        }
        let info = ReservationInfo::decode(data)?;
        let reservation_key = HbirdAuthKey::clone_from_slice(&data.split_to(16));
        Ok(Self::new(info, reservation_key))
    }
}

/// A pre-computed flyover MAC.
///
/// Can be used to turn a matching standard hop into a flyover hop.
pub struct FlyoverMAC {
    /// The actual flyover MAC.
    pub mac: [u8; 6],
    /// The details of the reservation corresponding to this MAC.
    pub reservation_info: ReservationInfo,
    /// The ISD-ASN to send packets to when using this MAC.
    pub dst_isd_asn: IsdAsn,
    /// The path meta header base timestamp used when calculating the MAC: a
    /// Unix timestamp with 1-second granularity.
    pub base_timestamp: u32,
    /// The millis timestamp used when calculating the MAC.
    pub millis_timestamp: u16,
    /// The counter value used when calculating the MAC.
    pub counter: u32,
    /// The packet length used when calculating the MAC.
    pub packet_length: u16,
}

impl FlyoverMAC {
    /// Returns the timestamp encoded by this flyover MAC's `base_timestamp`
    /// and `millis_timestamp`.
    pub fn packet_timestamp(&self) -> DateTime<Utc> {
        ReservationInfo::decode_start(self.base_timestamp)
            + Duration::milliseconds(i64::from(self.millis_timestamp))
    }

    /// Returns when the flyover MAC becomes valid, i.e., if a packet using this  
    /// MAC arrives at this point in time it should be valid (but not before
    /// then).
    /// If the flyover MAC is never vaild, returns the end time of the
    /// reservation.
    pub fn valid_from(&self) -> DateTime<Utc> {
        self.packet_timestamp().min(self.reservation_info.end())
    }

    /// Returns until when the flyover MAC is valid, i.e., the last point in time
    /// at which the packet can arrive at the border router such that the border
    /// router forwards the packet with priority.
    pub fn valid_until(&self) -> DateTime<Utc> {
        self.reservation_info
            .end()
            .min(self.packet_timestamp() + Duration::seconds(MAX_FRESHNESS_TOLERANCE))
    }

    /// Returns whether this flyover MAC's validity window has passed.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.valid_until()
    }

    /// Returns whether the flyover MAC is valid right now, i.e. its validity
    /// window has started but not yet passed.
    pub fn is_valid_now(&self) -> bool {
        let now = Utc::now();
        self.valid_from() <= now && self.valid_until() >= now
    }
}

/// One entry within a [`FlyoverMACs`] batch — a single reservation's
/// precomputed flyover MAC, targeting a specific hop.
///
/// Wire format (15 bytes total):
/// - `mac`: 6 bytes.
/// - `res_id` (22 bits) and `bandwidth` (10 bits) packed into 4 bytes, using the same `(res_id <<
///   10) | bandwidth` layout as [`ReservationInfo`]'s `ResID`/`BW` field.
/// - `res_start_offset`: 2 bytes.
/// - `res_duration`: 2 bytes.
/// - `hop_index`: 1 byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlyoverMACEntry {
    /// Raw flyover MAC — not yet XORed with the underlying standard hop
    /// field's own MAC. Mirrors [`FlyoverMAC::mac`].
    pub mac: [u8; 6],
    /// The reservation ID.
    pub res_id: u32,
    /// The reserved bandwidth.
    pub bandwidth: Bandwidth,
    /// Offset (seconds) between the reservation's start and the batch's
    /// shared `base_timestamp` (see [`FlyoverMACs::base_timestamp`]).
    pub res_start_offset: u16,
    /// The duration for which the bandwidth is reserved, in seconds.
    pub res_duration: u16,
    /// Flat hop index across all segments (same numbering as
    /// [`crate::path::Path::reservable_hops`] /
    /// [`crate::path::Path::reservation_hop_index`]).
    pub hop_index: u8,
}

impl FlyoverMACEntry {
    /// Wire-encoded length of a [`FlyoverMACEntry`] in bytes.
    pub const ENCODED_LENGTH: usize = 15;
}

impl WireEncode for FlyoverMACEntry {
    type Error = InadequateBufferSize;

    fn encoded_length(&self) -> usize {
        Self::ENCODED_LENGTH
    }

    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        buffer.put_slice(&self.mac);
        let res_id_and_bw = ((self.res_id & 0x3F_FFFF) << 10) | self.bandwidth.encode() as u32;
        buffer.put_u32(res_id_and_bw);
        buffer.put_u16(self.res_start_offset);
        buffer.put_u16(self.res_duration);
        buffer.put_u8(self.hop_index);
    }
}

impl WireDecode<Bytes> for FlyoverMACEntry {
    type Error = DecodeError;

    fn decode(data: &mut Bytes) -> Result<Self, Self::Error> {
        if data.remaining() < Self::ENCODED_LENGTH {
            return Err(DecodeError::PacketEmptyOrTruncated);
        }
        let mac_bytes = data.split_to(6);
        let mac: [u8; 6] = mac_bytes.as_ref().try_into().unwrap();
        let res_id_and_bw = data.get_u32();
        let res_id = res_id_and_bw >> 10;
        let bandwidth = Bandwidth::decode((res_id_and_bw & 0x3FF) as u16);
        let res_start_offset = data.get_u16();
        let res_duration = data.get_u16();
        let hop_index = data.get_u8();
        Ok(Self {
            mac,
            res_id,
            bandwidth,
            res_start_offset,
            res_duration,
            hop_index,
        })
    }
}

/// Compact set of flyover MACs sharing packet-level context. Lets a
/// component without reservation keys turn a `Standard` path into a
/// `Hummingbird` path with flyover hops, given precomputed MACs. See
/// `HummingbirdPath::generate_flyover_macs` and
/// `HummingbirdPath::apply_flyover_macs`.
///
/// Wire format:
/// - `dst_isd_asn`: 8 bytes.
/// - `base_timestamp`: 4 bytes.
/// - `millis_timestamp`: 2 bytes.
/// - `counter`: 4 bytes.
/// - `packet_length`: 2 bytes.
/// - `payload_length_suggestion`: 2 bytes.
/// - `entry_count`: 1 byte.
/// - `entries`: `entry_count` repetitions of [`FlyoverMACEntry`] (15 bytes each).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlyoverMACs {
    /// The destination ISD-AS these MACs were computed for.
    pub dst_isd_asn: IsdAsn,
    /// The path meta header base timestamp shared by every entry: a Unix
    /// timestamp with 1-second granularity.
    pub base_timestamp: u32,
    /// The millis timestamp shared by every entry.
    pub millis_timestamp: u16,
    /// The counter value shared by every entry.
    pub counter: u32,
    /// The total packet length (common + address + path header + payload)
    /// this batch of MACs was computed for. Required both for matching
    /// (does this batch apply to the packet we're about to build) and for
    /// deriving `payload_length_suggestion`.
    pub packet_length: u16,
    /// Suggested payload length: if the caller produces exactly this many
    /// bytes of payload, and SCION adds a common header, address header, and
    /// path header (with every hop in `entries` applied as a flyover, and no
    /// extension headers), the resulting packet length equals
    /// `packet_length` and the MACs remain valid.
    pub payload_length_suggestion: u16,
    /// The individual flyover MACs making up this batch.
    pub entries: Vec<FlyoverMACEntry>,
}

impl FlyoverMACs {
    fn packet_timestamp(&self) -> DateTime<Utc> {
        ReservationInfo::decode_start(self.base_timestamp)
            + Duration::milliseconds(i64::from(self.millis_timestamp))
    }

    /// When `entry`'s underlying reservation ends, derived from
    /// `entry.res_start_offset`/`entry.res_duration` and this batch's shared
    /// `base_timestamp`.
    fn entry_reservation_end(&self, entry: &FlyoverMACEntry) -> DateTime<Utc> {
        ReservationInfo::decode_start(self.base_timestamp)
            - Duration::seconds(i64::from(entry.res_start_offset))
            + Duration::seconds(i64::from(entry.res_duration))
    }

    fn entry_valid_from(&self, entry: &FlyoverMACEntry) -> DateTime<Utc> {
        self.packet_timestamp()
            .min(self.entry_reservation_end(entry))
    }

    fn entry_valid_until(&self, entry: &FlyoverMACEntry) -> DateTime<Utc> {
        self.entry_reservation_end(entry)
            .min(self.packet_timestamp() + Duration::seconds(MAX_FRESHNESS_TOLERANCE))
    }

    fn entry_is_valid_now(&self, entry: &FlyoverMACEntry, now: DateTime<Utc>) -> bool {
        self.entry_valid_from(entry) <= now && self.entry_valid_until(entry) >= now
    }

    /// Returns the number of entries that are valid right now, i.e. whose
    /// validity window has started but not yet passed.
    pub fn num_valid(&self) -> usize {
        let now = Utc::now();
        self.entries
            .iter()
            .filter(|e| self.entry_is_valid_now(e, now))
            .count()
    }

    /// Returns the number of entries whose validity window has passed.
    pub fn num_expired(&self) -> usize {
        let now = Utc::now();
        self.entries
            .iter()
            .filter(|e| now >= self.entry_valid_until(e))
            .count()
    }

    /// Returns whether every entry's validity window has passed.
    pub fn all_expired(&self) -> bool {
        self.num_expired() == self.entries.len()
    }

    /// Returns whether any entry's validity window has passed.
    pub fn any_expired(&self) -> bool {
        self.num_expired() > 0
    }

    /// Returns whether every entry is valid right now, i.e. each entry's
    /// validity window has started but not yet passed.
    pub fn all_valid(&self) -> bool {
        self.num_valid() == self.entries.len()
    }

    /// Returns whether any entry is valid right now.
    pub fn any_valid(&self) -> bool {
        self.num_valid() > 0
    }
}

impl WireEncode for FlyoverMACs {
    type Error = InadequateBufferSize;

    fn encoded_length(&self) -> usize {
        8 + 4 + 2 + 4 + 2 + 2 + 1 + self.entries.len() * FlyoverMACEntry::ENCODED_LENGTH
    }

    fn encode_to_unchecked<T: BufMut>(&self, buffer: &mut T) {
        buffer.put_u64(self.dst_isd_asn.0);
        buffer.put_u32(self.base_timestamp);
        buffer.put_u16(self.millis_timestamp);
        buffer.put_u32(self.counter);
        buffer.put_u16(self.packet_length);
        buffer.put_u16(self.payload_length_suggestion);
        buffer.put_u8(self.entries.len() as u8);
        for entry in &self.entries {
            entry.encode_to_unchecked(buffer);
        }
    }
}

impl WireDecode<Bytes> for FlyoverMACs {
    type Error = DecodeError;

    fn decode(data: &mut Bytes) -> Result<Self, Self::Error> {
        const FIXED_LEN: usize = 8 + 4 + 2 + 4 + 2 + 2 + 1;
        if data.remaining() < FIXED_LEN {
            return Err(DecodeError::PacketEmptyOrTruncated);
        }
        let dst_isd_asn = IsdAsn(data.get_u64());
        let base_timestamp = data.get_u32();
        let millis_timestamp = data.get_u16();
        let counter = data.get_u32();
        let packet_length = data.get_u16();
        let payload_length_suggestion = data.get_u16();
        let entry_count = data.get_u8();

        let mut entries = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            entries.push(FlyoverMACEntry::decode(data)?);
        }

        Ok(Self {
            dst_isd_asn,
            base_timestamp,
            millis_timestamp,
            counter,
            packet_length,
            payload_length_suggestion,
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire_encoding::{WireDecode, WireEncode};

    #[test]
    fn zero_bandwidth() {
        let bw = Bandwidth::from_bytes_per_sec(0).unwrap();
        assert_eq!(bw.to_bytes_per_sec(), 0);
    }

    #[test]
    fn bandwidth_ord_matches_bytes_per_sec_ordering() {
        let low = Bandwidth::from_bytes_per_sec(10).unwrap();
        let high = Bandwidth::from_bytes_per_sec(1024).unwrap();
        assert!(low < high);

        // Exponent boundary: 31 uses exponent=0, 32 uses exponent=1.
        let boundary_low = Bandwidth::from_bytes_per_sec(31).unwrap();
        let boundary_high = Bandwidth::from_bytes_per_sec(32).unwrap();
        assert!(boundary_low < boundary_high);
    }

    #[test]
    fn small_bandwidth_uses_exponent_zero() {
        // Values 0..=31 are stored directly as the significand (exponent = 0).
        for bytes_per_sec in [1u64, 15, 31] {
            let bw = Bandwidth::from_bytes_per_sec(bytes_per_sec).unwrap();
            assert_eq!(bw.exponent, 0, "bytes_per_sec={bytes_per_sec}");
            assert_eq!(
                bw.to_bytes_per_sec(),
                bytes_per_sec,
                "bytes_per_sec={bytes_per_sec}"
            );
        }
    }

    #[test]
    fn boundary_between_exponent_zero_and_one() {
        // 31 fits in exponent=0; 32 requires exponent=1.
        let bw31 = Bandwidth::from_bytes_per_sec(31).unwrap();
        assert_eq!(bw31.exponent, 0);

        let bw32 = Bandwidth::from_bytes_per_sec(32).unwrap();
        assert_eq!(bw32.exponent, 1);
        assert_eq!(bw32.to_bytes_per_sec(), 32);
    }

    #[test]
    fn roundtrip_various_values() {
        // Values that are exactly representable should survive a roundtrip.
        // For exponent E, only multiples of 2^(E-1) are exactly representable.
        for bytes_per_sec in [32u64, 63, 64, 128, 1024] {
            let bw = Bandwidth::from_bytes_per_sec(bytes_per_sec).unwrap();
            assert_eq!(
                bw.to_bytes_per_sec(),
                bytes_per_sec,
                "roundtrip failed for {bytes_per_sec} bytes/s"
            );
        }
    }

    #[test]
    fn non_representable_value_rounds_down() {
        // For exponent=2 the stride is 2, so odd values in [64,126] are not
        // representable. 65 should encode as 64.
        let bw = Bandwidth::from_bytes_per_sec(65).unwrap();
        assert!(bw.to_bytes_per_sec() <= 65);
        assert_eq!(bw.to_bytes_per_sec(), 64);
    }

    #[test]
    fn too_large_returns_error() {
        // Max exponent is 31. An error is triggered when the required exponent
        // would be 32, which first happens at 2^36 bytes/s.
        let just_fits: u64 = (1 << 36) - 1;
        assert!(Bandwidth::from_bytes_per_sec(just_fits).is_ok());
        assert!(Bandwidth::from_bytes_per_sec(1u64 << 36).is_err());
    }

    #[test]
    fn encode_decode_roundtrip() {
        for bytes_per_sec in [0u64, 1, 31, 32, 64, 1024, 1_000_000] {
            let bw = Bandwidth::from_bytes_per_sec(bytes_per_sec).unwrap();
            let decoded = Bandwidth::decode(bw.encode());
            assert_eq!(
                bw, decoded,
                "encode/decode roundtrip failed for {bytes_per_sec} bytes/s"
            );
        }
    }

    #[test]
    fn encode_fits_in_10_bits() {
        for bytes_per_sec in [0u64, 1, 31, 32, 64, 1_000_000] {
            let encoded = Bandwidth::from_bytes_per_sec(bytes_per_sec)
                .unwrap()
                .encode();
            assert_eq!(
                encoded & !Bandwidth::MASK,
                0,
                "encoded value exceeds 10 bits for {bytes_per_sec} bytes/s"
            );
        }
    }

    #[test]
    fn reservation_info_encode_decode_roundtrip() {
        use crate::address::IsdAsn;

        let info = ReservationInfo {
            isd_as: IsdAsn(0x1_ff00_0000_0110),
            ingress_interface: 1,
            egress_interface: 2,
            res_id: 0x3FFFFF,
            bandwidth: Bandwidth::from_bytes_per_sec(1024).unwrap(),
            start: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            duration: 3600,
        };
        assert_eq!(info.encoded_length(), ReservationInfo::ENCODED_LENGTH);

        let encoded = info.encode_to_bytes();
        assert_eq!(encoded.len(), ReservationInfo::ENCODED_LENGTH);

        let decoded = ReservationInfo::decode(&mut encoded.clone()).unwrap();
        assert_eq!(decoded, info);
    }

    #[test]
    fn reservation_stays_small() {
        // Reservations sit in a `Vec` that reservation selection scans once
        // per packet (see `ReservationTracker::select`), so the cached AES key
        // schedule must live behind a pointer, not inline. The two cached
        // validity bounds are stored inline on purpose: they are read on every
        // scan, and 32 bytes buys removing a calendar conversion per candidate.
        assert!(std::mem::size_of::<Reservation>() <= 96);
    }

    #[test]
    fn cached_validity_window_matches_reservation_info() {
        use std::time::Duration;

        use crate::address::IsdAsn;

        let info = ReservationInfo {
            isd_as: IsdAsn(0x1_ff00_0000_0110),
            ingress_interface: 1,
            egress_interface: 2,
            res_id: 7,
            bandwidth: Bandwidth::from_bytes_per_sec(1024).unwrap(),
            start: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            duration: 3600,
        };
        let reservation = Reservation::new(info.clone(), HbirdAuthKey::from([0xAB; 16]));

        // The cache must agree with the window `info` describes, including
        // that both bounds are inclusive.
        let start: SystemTime = info.start().into();
        let end: SystemTime = info.end().into();

        assert!(reservation.is_valid_at(start));
        assert!(reservation.is_valid_at(end));
        assert!(reservation.is_valid_at(start + Duration::from_secs(1800)));
        assert!(!reservation.is_valid_at(start - Duration::from_nanos(1)));
        assert!(!reservation.is_valid_at(end + Duration::from_nanos(1)));
    }

    #[test]
    fn reservation_encode_decode_roundtrip() {
        use crate::address::IsdAsn;

        let res = Reservation::new(
            ReservationInfo {
                isd_as: IsdAsn(0x1_ff00_0000_0110),
                ingress_interface: 3,
                egress_interface: 4,
                res_id: 42,
                bandwidth: Bandwidth::from_bytes_per_sec(64).unwrap(),
                start: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                duration: 600,
            },
            HbirdAuthKey::from([0xABu8; 16]),
        );
        assert_eq!(res.encoded_length(), Reservation::ENCODED_LENGTH);

        let encoded = res.encode_to_bytes();
        assert_eq!(encoded.len(), Reservation::ENCODED_LENGTH);

        let decoded = Reservation::decode(&mut encoded.clone()).unwrap();
        assert_eq!(decoded, res);
    }

    #[test]
    fn flyover_mac_entry_encode_decode_roundtrip() {
        let entry = FlyoverMACEntry {
            mac: [1, 2, 3, 4, 5, 6],
            res_id: 0x3FFFFF,
            bandwidth: Bandwidth::from_bytes_per_sec(1024).unwrap(),
            res_start_offset: 1000,
            res_duration: 600,
            hop_index: 3,
        };
        assert_eq!(entry.encoded_length(), FlyoverMACEntry::ENCODED_LENGTH);

        let encoded = entry.encode_to_bytes();
        assert_eq!(encoded.len(), FlyoverMACEntry::ENCODED_LENGTH);

        let decoded = FlyoverMACEntry::decode(&mut encoded.clone()).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn flyover_macs_encode_decode_roundtrip() {
        use crate::address::IsdAsn;

        let macs = FlyoverMACs {
            dst_isd_asn: IsdAsn(0x1_ff00_0000_0110),
            base_timestamp: 1_700_000_000,
            millis_timestamp: 250,
            counter: 7,
            packet_length: 1000,
            payload_length_suggestion: 900,
            entries: vec![
                FlyoverMACEntry {
                    mac: [1; 6],
                    res_id: 1,
                    bandwidth: Bandwidth::from_bytes_per_sec(64).unwrap(),
                    res_start_offset: 10,
                    res_duration: 20,
                    hop_index: 0,
                },
                FlyoverMACEntry {
                    mac: [2; 6],
                    res_id: 2,
                    bandwidth: Bandwidth::from_bytes_per_sec(128).unwrap(),
                    res_start_offset: 30,
                    res_duration: 40,
                    hop_index: 2,
                },
            ],
        };

        let encoded = macs.encode_to_bytes();
        assert_eq!(encoded.len(), macs.encoded_length());

        let decoded = FlyoverMACs::decode(&mut encoded.clone()).unwrap();
        assert_eq!(decoded, macs);
    }

    #[test]
    fn flyover_macs_mixed_valid_and_expired_entries() {
        use crate::address::IsdAsn;

        let now = Utc::now();
        let base_timestamp = now.timestamp() as u32;

        let macs = FlyoverMACs {
            dst_isd_asn: IsdAsn(0x1_ff00_0000_0110),
            base_timestamp,
            millis_timestamp: 0,
            counter: 0,
            packet_length: 100,
            payload_length_suggestion: 50,
            entries: vec![
                // Expired: reservation ended 50s before base_timestamp.
                FlyoverMACEntry {
                    mac: [0; 6],
                    res_id: 1,
                    bandwidth: Bandwidth::from_bytes_per_sec(64).unwrap(),
                    res_start_offset: 100,
                    res_duration: 50,
                    hop_index: 0,
                },
                // Valid: reservation still has plenty of time left.
                FlyoverMACEntry {
                    mac: [0; 6],
                    res_id: 2,
                    bandwidth: Bandwidth::from_bytes_per_sec(64).unwrap(),
                    res_start_offset: 0,
                    res_duration: 600,
                    hop_index: 1,
                },
            ],
        };

        assert_eq!(macs.num_expired(), 1);
        assert_eq!(macs.num_valid(), 1);
        assert!(macs.any_expired());
        assert!(!macs.all_expired());
        assert!(macs.any_valid());
        assert!(!macs.all_valid());
    }

    #[test]
    fn flyover_macs_all_expired_when_every_entry_expired() {
        use crate::address::IsdAsn;

        // base_timestamp near the epoch: any reservation ending shortly
        // after it is long expired relative to Utc::now().
        let macs = FlyoverMACs {
            dst_isd_asn: IsdAsn(0x1_ff00_0000_0110),
            base_timestamp: 1,
            millis_timestamp: 0,
            counter: 0,
            packet_length: 100,
            payload_length_suggestion: 50,
            entries: vec![FlyoverMACEntry {
                mac: [0; 6],
                res_id: 1,
                bandwidth: Bandwidth::from_bytes_per_sec(64).unwrap(),
                res_start_offset: 0,
                res_duration: 1,
                hop_index: 0,
            }],
        };

        assert_eq!(macs.num_expired(), 1);
        assert_eq!(macs.num_valid(), 0);
        assert!(macs.all_expired());
        assert!(macs.any_expired());
        assert!(!macs.all_valid());
        assert!(!macs.any_valid());
    }
}
