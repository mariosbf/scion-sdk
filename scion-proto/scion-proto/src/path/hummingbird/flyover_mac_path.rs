//! `PathProvider` for applying precomputed flyover MACs to a bare `Standard`
//! path, without needing per-hop metadata or a reservation key.

use bytes::{Bytes, BytesMut};
use chrono::Duration;

use crate::{
    address::IsdAsn,
    hummingbird::{FlyoverMAC, FlyoverMACEntry, FlyoverMACs, ReservationInfo},
    packet::{ByEndpoint, CommonHeader, DecodeError},
    path::{
        DataPlanePath, MetaHeader, Path, PathProvider, StandardHopField, StandardPath,
        encoded::EncodedStandardPath,
        hummingbird::{
            EncodedHummingbirdPath, FlyoverHopField, HummingbirdBaseTimestamp, HummingbirdCounter,
            HummingbirdHopField, HummingbirdHopfieldIndex, HummingbirdMetaHeader,
            HummingbirdMetaReserved, HummingbirdMillisTimestamp, HummingbirdPathError,
            HummingbirdSegmentLength,
        },
    },
    wire_encoding::WireEncode,
};

/// Applies a precomputed batch of flyover MACs (see
/// `HummingbirdPath::generate_flyover_macs`) to `path`'s hop fields,
/// producing an [`EncodedHummingbirdPath`]. Needs no reservation key: hops
/// are matched purely by
/// [`crate::hummingbird::FlyoverMACEntry::hop_index`], and the resulting
/// flyover hop fields are built by XORing each matching hop's own MAC with
/// the entry's precomputed raw flyover MAC.
///
/// If `macs.entries` contains more than one entry for the same `hop_index`
/// (never produced by `generate_flyover_macs`, but `FlyoverMACs` crosses a
/// wire boundary so a malformed or malicious batch could contain one), the
/// first matching entry (in `entries` order) is applied and the rest are
/// ignored for that hop — see [`flyover_hop_count`] for the matching count
/// used to validate a candidate's projected packet length before calling
/// this function.
///
/// Works directly on a decoded [`StandardPath`] rather than going through
/// `HummingbirdPath`: this operation needs neither a reservation key nor
/// per-hop ISD-AS/interface metadata (which is all `HummingbirdPath` adds on
/// top of a `StandardPath`), so there's nothing to gain from the heavier
/// type.
pub fn apply_flyover_macs(
    path: &StandardPath,
    macs: &FlyoverMACs,
) -> Result<EncodedHummingbirdPath<Bytes>, HummingbirdPathError> {
    let base_timestamp = HummingbirdBaseTimestamp::new(macs.base_timestamp)
        .expect("u32 always fits a 32-bit-wide bounded integer");
    let millis_timestamp = HummingbirdMillisTimestamp::new(macs.millis_timestamp).ok_or(
        HummingbirdPathError::InvalidMillisTimestamp(macs.millis_timestamp as u32),
    )?;
    let counter = HummingbirdCounter::new(macs.counter)
        .ok_or(HummingbirdPathError::InvalidCounter(macs.counter))?;

    let orig_current_hop_field_offset =
        HummingbirdHopfieldIndex::from(path.path_meta.current_hop_field).byte_offset();
    let mut curr_hf_index = orig_current_hop_field_offset;
    let mut hop_offset = 0usize;
    let mut seglens = [0usize; 3];
    let mut hop_fields = Vec::with_capacity(path.hop_fields.len());

    let mut remaining_hops = path.hop_fields.as_slice();
    for (seg_idx, segment_len) in path
        .path_meta
        .segment_lengths
        .iter()
        .map(|s| s.length())
        .enumerate()
    {
        let (segment_hops, rest) = remaining_hops.split_at(segment_len);
        remaining_hops = rest;

        for hop in segment_hops {
            let flat_idx = hop_fields.len() as u8;
            let entry = macs.entries.iter().find(|e| e.hop_index == flat_idx);

            let hop_field = if let Some(entry) = entry {
                if hop_offset < orig_current_hop_field_offset {
                    curr_hf_index +=
                        FlyoverHopField::ENCODED_SIZE - StandardHopField::ENCODED_SIZE;
                }

                let flyover_mac = FlyoverMAC {
                    mac: entry.mac,
                    reservation_info: ReservationInfo {
                        isd_as: macs.dst_isd_asn,
                        ingress_interface: 0,
                        egress_interface: 0,
                        res_id: entry.res_id,
                        bandwidth: entry.bandwidth,
                        start: ReservationInfo::decode_start(macs.base_timestamp)
                            - Duration::seconds(entry.res_start_offset as i64),
                        duration: entry.res_duration,
                    },
                    dst_isd_asn: macs.dst_isd_asn,
                    base_timestamp: macs.base_timestamp,
                    millis_timestamp: macs.millis_timestamp,
                    counter: macs.counter,
                    packet_length: macs.packet_length,
                };

                HummingbirdHopField::Flyover(hop.apply_flyover_mac(&flyover_mac)?)
            } else {
                HummingbirdHopField::Standard(hop.clone())
            };

            hop_offset += hop_field.encoded_length();
            seglens[seg_idx] += hop_field.encoded_length();
            hop_fields.push(hop_field);
        }
    }

    let mut segment_lengths = [HummingbirdSegmentLength::new_unchecked(0); 3];
    for (seg_idx, seg_len) in seglens.iter().enumerate() {
        segment_lengths[seg_idx] =
            HummingbirdSegmentLength::new(*seg_len).ok_or(HummingbirdPathError::SegmentTooLong)?;
    }

    let current_hop_field = HummingbirdHopfieldIndex::new(curr_hf_index)
        .ok_or(HummingbirdPathError::InvalidHopFieldIndex)?;

    let meta_header = HummingbirdMetaHeader {
        current_info_field: path.path_meta.current_info_field.into(),
        current_hop_field,
        reserved: HummingbirdMetaReserved::default(),
        segment_lengths,
        base_timestamp,
        millis_timestamp,
        counter,
    };

    let mut buffer = BytesMut::new();
    meta_header.encode_to_unchecked(&mut buffer);
    for info in &path.info_fields {
        info.encode_to_unchecked(&mut buffer);
    }
    for hop in &hop_fields {
        hop.encode_to_unchecked(&mut buffer);
    }

    Ok(EncodedHummingbirdPath {
        meta_header,
        encoded_path: buffer.freeze(),
    })
}

/// Returns the number of *distinct* hops `entries` will turn into flyovers
/// when applied via [`apply_flyover_macs`].
///
/// This is not simply `entries.len()`: if two entries share a `hop_index`,
/// [`apply_flyover_macs`] applies only the first and leaves the hop a single
/// flyover, so counting every entry would overstate the resulting packet
/// length and cause a correctly-sized candidate to be rejected by
/// [`FlyoverMACHbirdPath::build`]'s length filter.
fn flyover_hop_count(entries: &[FlyoverMACEntry]) -> usize {
    let mut hop_indices: Vec<u8> = entries.iter().map(|e| e.hop_index).collect();
    hop_indices.sort_unstable();
    hop_indices.dedup();
    hop_indices.len()
}

/// A [`PathProvider`] that turns a bare `Standard` path into a `Hummingbird`
/// path by applying whichever precomputed [`FlyoverMACs`] batch matches the
/// packet actually being built, without ever holding a reservation key.
///
/// Falls back to the plain `Standard` path when no candidate matches, or
/// when applying the best match fails for any reason — [`Self::build`] never
/// hard-fails.
///
/// Treated as a one-time-use object: candidates are stored in an unordered
/// `Vec` (`push` is O(1)); pruning expired candidates is the caller's
/// responsibility via [`Self::remove_expired`].
pub struct FlyoverMACHbirdPath {
    path: Path<Bytes>,
    candidates: Vec<FlyoverMACs>,
}

impl FlyoverMACHbirdPath {
    /// Creates a new `FlyoverMACHbirdPath` wrapping `path`, with no
    /// candidates yet.
    pub fn new(path: Path<Bytes>) -> Self {
        Self {
            path,
            candidates: Vec::new(),
        }
    }

    /// Adds a batch of precomputed flyover MACs as a candidate for
    /// [`Self::build`].
    pub fn push(&mut self, macs: FlyoverMACs) {
        self.candidates.push(macs);
    }

    /// Removes candidates that are entirely useless — every entry's
    /// validity window has passed. Candidates with only *some* expired
    /// entries are kept: applying them still gives flyover treatment to
    /// whichever entries are still valid (some benefit beats none), so
    /// [`Self::build`] ranks candidates by valid-entry count rather than
    /// rejecting them outright.
    pub fn remove_expired(&mut self) {
        self.candidates.retain(|c| !c.all_expired());
    }

    fn apply_candidate(
        &self,
        encoded_std: &EncodedStandardPath<Bytes>,
        candidate: &FlyoverMACs,
    ) -> Result<Path<Bytes>, ApplyCandidateError> {
        let standard_path: StandardPath = encoded_std.clone().try_into()?;
        let encoded = apply_flyover_macs(&standard_path, candidate)?;

        let mut path = Path::new(
            DataPlanePath::Hummingbird(encoded),
            self.path.isd_asn,
            self.path.underlay_next_hop,
        );
        path.metadata = self.path.metadata.clone();

        Ok(path)
    }
}

/// Internal error type for [`FlyoverMACHbirdPath::apply_candidate`]. Never
/// surfaces past [`PathProvider::build`], which treats any failure here as
/// "this candidate is unusable" and falls through to the next one (or to a
/// plain path).
#[derive(Debug, thiserror::Error)]
enum ApplyCandidateError {
    #[error("failed to decode standard path: {0}")]
    Decode(#[from] DecodeError),
    #[error("failed to apply flyover MACs: {0}")]
    Path(#[from] HummingbirdPathError),
}

impl PathProvider for FlyoverMACHbirdPath {
    type Error = std::convert::Infallible;

    fn build(
        &self,
        isd_asn: ByEndpoint<IsdAsn>,
        payload_len: u16,
        address_header_len: u16,
    ) -> Result<Path, Self::Error> {
        let DataPlanePath::Standard(encoded_std) = &self.path.data_plane_path else {
            return Ok(self.path.to_bytes_path());
        };

        let base_length = CommonHeader::LENGTH
            + address_header_len as usize
            + self.path.data_plane_path.raw().len()
            + payload_len as usize;

        // Candidates keep entries whose reservation window has already
        // lapsed rather than being rejected outright — some flyover benefit
        // beats none. All entries are still applied as a unit (the packet
        // length the MACs were computed for assumes every distinct hop
        // becomes a flyover; dropping expired entries at apply time would
        // change the resulting packet length and invalidate the *other*
        // entries' MACs). Only candidates with zero currently-valid entries
        // are excluded, since applying those would add flyover-hop-field
        // overhead for no benefit at all.
        let best = self
            .candidates
            .iter()
            .filter(|c| c.dst_isd_asn == isd_asn.destination && !c.all_expired())
            .filter(|c| {
                let projected = base_length
                    + (HummingbirdMetaHeader::LENGTH - MetaHeader::LENGTH)
                    + flyover_hop_count(&c.entries)
                        * (FlyoverHopField::ENCODED_SIZE - StandardHopField::ENCODED_SIZE);
                u16::try_from(projected) == Ok(c.packet_length)
            })
            .max_by_key(|c| {
                let min_bw = c.entries.iter().map(|e| e.bandwidth).min();
                (c.num_valid(), min_bw)
            });

        match best.and_then(|c| self.apply_candidate(encoded_std, c).ok()) {
            Some(path) => Ok(path),
            None => Ok(self.path.to_bytes_path()),
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use chrono::Utc;

    use super::*;
    use crate::{
        address::{Asn, EndhostAddr, Isd, IsdAsn},
        hummingbird::{Bandwidth, FlyoverMACEntry, FlyoverMACs},
        path::test_builder::TestPathBuilder,
    };

    fn build_two_hop_path() -> Path<Bytes> {
        let src = EndhostAddr::new(IsdAsn::new(Isd(1), Asn(110)), [127, 0, 0, 1].into());
        let dst = EndhostAddr::new(IsdAsn::new(Isd(1), Asn(111)), [127, 0, 0, 1].into());
        TestPathBuilder::new(src.into(), dst.into())
            .using_info_timestamp(1000)
            .up()
            .with_asn(110)
            .add_hop(0, 1)
            .with_asn(111)
            .add_hop(1, 0)
            .build(2000)
            .path()
    }

    fn fresh_candidate(dst: IsdAsn, packet_length: u16, hop_index: u8) -> FlyoverMACs {
        FlyoverMACs {
            dst_isd_asn: dst,
            base_timestamp: Utc::now().timestamp() as u32,
            millis_timestamp: 0,
            counter: 0,
            packet_length,
            payload_length_suggestion: 0,
            entries: vec![FlyoverMACEntry {
                mac: [0xAB; 6],
                res_id: 1,
                bandwidth: Bandwidth::from_kbps(64).unwrap(),
                res_start_offset: 0,
                res_duration: 600,
                hop_index,
            }],
        }
    }

    /// Two-entry candidate (packet_length must match a path with 2 flyovers
    /// applied) where one entry's reservation has already lapsed and the
    /// other is still fresh.
    fn partially_expired_candidate(dst: IsdAsn, packet_length: u16) -> FlyoverMACs {
        let base_timestamp = Utc::now().timestamp() as u32;
        FlyoverMACs {
            dst_isd_asn: dst,
            base_timestamp,
            millis_timestamp: 0,
            counter: 0,
            packet_length,
            payload_length_suggestion: 0,
            entries: vec![
                FlyoverMACEntry {
                    mac: [0xAB; 6],
                    res_id: 1,
                    // Reservation ended 50s before base_timestamp.
                    bandwidth: Bandwidth::from_kbps(64).unwrap(),
                    res_start_offset: 100,
                    res_duration: 50,
                    hop_index: 0,
                },
                FlyoverMACEntry {
                    mac: [0xCD; 6],
                    res_id: 2,
                    bandwidth: Bandwidth::from_kbps(64).unwrap(),
                    res_start_offset: 0,
                    res_duration: 600,
                    hop_index: 1,
                },
            ],
        }
    }

    #[test]
    fn build_applies_best_matching_candidate() {
        let path = build_two_hop_path();
        let isd_asn = path.isd_asn;
        // Standard path: 4 (meta) + 8 (info) + 2×12 (hops) = 36 bytes.
        let address_header_len = 8u16;
        let payload_len = 50u16;
        let base_length =
            12 /* CommonHeader */ + address_header_len as usize + 36 + payload_len as usize;
        let packet_length = (base_length + (12 - 4) + (20 - 12)) as u16;

        let mut provider = FlyoverMACHbirdPath::new(path);
        provider.push(fresh_candidate(isd_asn.destination, packet_length, 0));

        let built = provider
            .build(isd_asn, payload_len, address_header_len)
            .unwrap();
        let DataPlanePath::Hummingbird(encoded) = &built.data_plane_path else {
            panic!("expected a Hummingbird path");
        };
        assert_eq!(encoded.flyover_hop_fields().count(), 1);
    }

    #[test]
    fn build_falls_back_to_plain_path_when_no_candidate_matches() {
        let path = build_two_hop_path();
        let isd_asn = path.isd_asn;

        let mut provider = FlyoverMACHbirdPath::new(path);
        // Wrong packet_length -> arithmetic filter rejects this candidate.
        provider.push(fresh_candidate(isd_asn.destination, 1, 0));

        let built = provider.build(isd_asn, 50, 8).unwrap();
        assert!(matches!(built.data_plane_path, DataPlanePath::Standard(_)));
    }

    #[test]
    fn build_falls_back_to_plain_path_when_all_candidates_expired() {
        let path = build_two_hop_path();
        let isd_asn = path.isd_asn;

        let mut expired = fresh_candidate(isd_asn.destination, 1000, 0);
        expired.base_timestamp = 1; // near the epoch: long expired by now
        expired.entries[0].res_start_offset = 0;
        expired.entries[0].res_duration = 1;

        let mut provider = FlyoverMACHbirdPath::new(path);
        provider.push(expired);

        let built = provider.build(isd_asn, 50, 8).unwrap();
        assert!(matches!(built.data_plane_path, DataPlanePath::Standard(_)));
    }

    #[test]
    fn build_applies_candidate_with_some_expired_entries() {
        // Some valid reservations beat no valid reservations: a candidate
        // with one expired and one valid entry still gets selected and
        // applied over falling back to a plain path.
        let path = build_two_hop_path();
        let isd_asn = path.isd_asn;
        let address_header_len = 8u16;
        let payload_len = 50u16;
        let base_length =
            12 /* CommonHeader */ + address_header_len as usize + 36 + payload_len as usize;
        // Two flyovers applied: +8 (meta header delta) + 2×8 (flyover delta).
        let packet_length = (base_length + (12 - 4) + 2 * (20 - 12)) as u16;

        let mut provider = FlyoverMACHbirdPath::new(path);
        provider.push(partially_expired_candidate(isd_asn.destination, packet_length));

        let built = provider
            .build(isd_asn, payload_len, address_header_len)
            .unwrap();
        let DataPlanePath::Hummingbird(encoded) = &built.data_plane_path else {
            panic!("expected a Hummingbird path even though one entry had expired");
        };
        assert_eq!(encoded.flyover_hop_fields().count(), 2);
    }

    #[test]
    fn build_applies_only_one_flyover_when_entries_share_hop_index() {
        // Two entries target the same hop_index (never produced by
        // generate_flyover_macs, but a malformed/adversarial batch could
        // have one). apply_flyover_macs applies only the first, so the
        // length projection — and the resulting path — must account for
        // exactly one flyover, not two.
        let path = build_two_hop_path();
        let isd_asn = path.isd_asn;
        let address_header_len = 8u16;
        let payload_len = 50u16;
        let base_length =
            12 /* CommonHeader */ + address_header_len as usize + 36 + payload_len as usize;
        let packet_length = (base_length + (12 - 4) + (20 - 12)) as u16;

        let mut candidate = fresh_candidate(isd_asn.destination, packet_length, 0);
        let mut duplicate = candidate.entries[0].clone();
        duplicate.res_id = 99;
        candidate.entries.push(duplicate);

        let mut provider = FlyoverMACHbirdPath::new(path);
        provider.push(candidate);

        let built = provider
            .build(isd_asn, payload_len, address_header_len)
            .unwrap();
        let DataPlanePath::Hummingbird(encoded) = &built.data_plane_path else {
            panic!("expected a Hummingbird path");
        };
        assert_eq!(encoded.flyover_hop_fields().count(), 1);
    }

    #[test]
    fn remove_expired_prunes_expired_candidates() {
        let path = build_two_hop_path();
        let isd_asn = path.isd_asn;

        let mut expired = fresh_candidate(isd_asn.destination, 1000, 0);
        expired.base_timestamp = 1;
        expired.entries[0].res_start_offset = 0;
        expired.entries[0].res_duration = 1;

        let mut provider = FlyoverMACHbirdPath::new(path);
        provider.push(expired);
        assert_eq!(provider.candidates.len(), 1);

        provider.remove_expired();
        assert_eq!(provider.candidates.len(), 0);
    }

    #[test]
    fn end_to_end_generate_and_apply_flyover_macs_with_real_hop_macs() {
        use crate::{
            hummingbird::{Bandwidth, Reservation, ReservationInfo},
            packet::CommonHeader,
            path::hummingbird::calculate_flyover_mac,
        };
        use chrono::DateTime;

        let src = EndhostAddr::new(IsdAsn::new(Isd(1), Asn(110)), [127, 0, 0, 1].into());
        let dst = EndhostAddr::new(IsdAsn::new(Isd(1), Asn(112)), [127, 0, 0, 1].into());

        let ctx = TestPathBuilder::new(src.into(), dst.into())
            .using_info_timestamp(42)
            .up()
            .with_asn(110)
            .add_hop(0, 1)
            .with_asn(111)
            .add_hop(1, 0)
            .down()
            .with_asn(111)
            .add_hop(0, 2)
            .with_asn(112)
            .add_hop(1, 0)
            .build(1000);

        let path = ctx.path();
        let isd_asn = path.isd_asn;

        let reservation = Reservation {
            info: ReservationInfo {
                isd_as: IsdAsn::new(Isd(1), Asn(111)),
                ingress_interface: 1,
                egress_interface: 2,
                res_id: 7,
                bandwidth: Bandwidth::from_kbps(512).unwrap(),
                start: DateTime::from_timestamp(Utc::now().timestamp() - 10, 0).unwrap(),
                duration: 600,
            },
            reservation_key: [0x42u8; 16].into(),
        };

        let hop_idx = path.reservation_hop_index(&reservation).unwrap();
        assert_eq!(hop_idx, 1, "sanity check: transit hop at flat index 1");

        let mut hbird = path.to_hbird().unwrap();
        hbird.add_reservation(hop_idx, reservation.clone()).unwrap();

        let destination = isd_asn.destination;
        let address_header_len = 8u16;
        let payload_len = 50u16;
        // path_header_len with one flyover among four standard hops:
        // 12 (meta) + 2×8 (info) + 3×12 (standard) + 20 (flyover) = 84 bytes.
        let path_header_len = 84u16;
        let packet_length =
            CommonHeader::LENGTH as u16 + address_header_len + path_header_len + payload_len;

        let macs = hbird
            .generate_flyover_macs(destination, packet_length, address_header_len)
            .unwrap();
        assert_eq!(macs.entries.len(), 1);
        assert_eq!(macs.entries[0].hop_index, hop_idx);
        assert_eq!(macs.payload_length_suggestion, payload_len);

        let mut provider = FlyoverMACHbirdPath::new(path.clone());
        provider.push(macs);

        let built = provider
            .build(isd_asn, payload_len, address_header_len)
            .unwrap();
        let DataPlanePath::Hummingbird(encoded) = &built.data_plane_path else {
            panic!("expected a Hummingbird path");
        };

        assert_eq!(encoded.flyover_hop_fields().count(), 1);
        let flyover = encoded.flyover_hop_fields().next().unwrap();
        assert_eq!(flyover.reservation_id(), 7);
        assert_eq!(flyover.bandwidth(), Bandwidth::from_kbps(512).unwrap());

        // The flyover's aggregated MAC must equal the original standard
        // hop's MAC XORed with a freshly computed flyover MAC, using the
        // same reservation key, timing, and packet length that
        // generate_flyover_macs used internally.
        let DataPlanePath::Standard(original) = &path.data_plane_path else {
            panic!("expected a Standard path");
        };
        let original_mac: [u8; 6] = original.hop_fields().nth(hop_idx as usize).unwrap().as_ref()
            [6..12]
            .try_into()
            .unwrap();

        let base_timestamp = encoded.meta_header().base_timestamp.get();
        let res_start_offset = reservation.info.res_start_offset(base_timestamp).unwrap();
        let raw_flyover_mac = calculate_flyover_mac(
            destination.isd(),
            destination.asn(),
            packet_length,
            res_start_offset,
            encoded.meta_header().millis_timestamp.get(),
            encoded.meta_header().counter.get(),
            &reservation.reservation_key,
        );

        let mut expected_mac = original_mac;
        for (a, b) in expected_mac.iter_mut().zip(raw_flyover_mac.iter()) {
            *a ^= b;
        }

        assert_eq!(&flyover.as_ref()[6..12], &expected_mac);
    }
}
