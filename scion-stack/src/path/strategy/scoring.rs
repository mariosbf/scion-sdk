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

//! Path scoring is the central component of path selection.
//!
//! Each path is scored based on multiple metrics, and the scores are aggregated to form a final
//! score. Higher scores indicate more preferred paths.
//!
//! The scoring system is designed to be extensible, allowing new scoring metrics to be added as
//! needed. Scores from multiple metrics can be weighted to reflect their relative importance in
//! path selection.

use std::{
    collections::BTreeMap,
    fmt::Display,
    sync::{Arc, RwLock},
    time::SystemTime,
};

use scion_proto::path::{
    EncodedHopField,
    hummingbird::{ReservationInterfaces, ReservationMap},
};

use crate::path::types::{PathManagerPath, Score};

/// Trait for scoring paths based on specific metrics.
///
/// Implementors provide a method to score a path, returning a floating point score between -1.0 and
/// 1.0. Higher scores indicate more preferred paths.
///
/// Scores from multiple implementations are aggregated to form a composite path score, which is
/// used for selecting a preferred path.
pub trait PathScoring: 'static + Send + Sync {
    /// Name of the metric being scored.
    /// Used for debugging path scoring decisions.
    fn metric_name(&self) -> &'static str;
    /// Scores the given path, returning a floating point score.
    ///
    /// Higher scores indicate more preferred paths.
    ///
    /// `path` - The path to score.
    /// `now` - The current system time for time sensitive scores.
    fn score(&self, path: &PathManagerPath, now: SystemTime) -> Score;
}

/// Scores paths based on their length with a 0.02 penalty per hop.
///
/// Shorter paths receive slightly higher scores.
struct PathLengthScorer;

impl PathScoring for PathLengthScorer {
    fn metric_name(&self) -> &'static str {
        "Path Length"
    }

    fn score(&self, path: &PathManagerPath, _now: SystemTime) -> Score {
        let length = match &path.path.data_plane_path {
            scion_proto::path::DataPlanePath::EmptyPath => 0,
            scion_proto::path::DataPlanePath::Standard(encoded_standard_path) => {
                encoded_standard_path
                    .segments()
                    .map(|seg| seg.hop_fields().len() - 2)
                    .sum()
            }
            scion_proto::path::DataPlanePath::Hummingbird(encoded_hummingbird_path) => {
                // TODO: This is a comparatively expensive operation. Calculating
                // the number of hop fields in a Hummingbird path requires iterating
                // through the path to see which hop fields have the flyover bit
                // set.
                // Should this be replaced with some heuristic value or is this fine?
                encoded_hummingbird_path
                    .hop_fields()
                    .map(|_| 1)
                    .sum::<usize>()
                    - 2
            }
            scion_proto::path::DataPlanePath::Unsupported { .. } => {
                HOP_COUNT_FOR_MIN_SCORE as usize
            }
        };

        const MAX_SCORE: f32 = 1.0;
        const MIN_SCORE: f32 = 0.0;
        const HOP_COUNT_FOR_MIN_SCORE: f32 = 50.0;
        const PER_HOP_PENALTY: f32 = (MAX_SCORE - MIN_SCORE) / HOP_COUNT_FOR_MIN_SCORE;
        let score_value = MAX_SCORE - (length as f32 * PER_HOP_PENALTY);
        Score::new_clamped(score_value)
    }
}

/// Scores paths based on their Hummingbird coverage.
/// Paths with more Hummingbird hops receive higher scores.
pub struct PathHbirdCoverageScorer {
    /// Reservations that are taken into account.
    reservations: Arc<RwLock<ReservationMap>>,
}

impl PathHbirdCoverageScorer {
    /// Creates a new PathHbirdCoverageScorer with the given reservations.
    pub fn new(reservations: Arc<RwLock<ReservationMap>>) -> Self {
        Self { reservations }
    }
}

impl PathScoring for PathHbirdCoverageScorer {
    fn metric_name(&self) -> &'static str {
        "Hummingbird Coverage"
    }

    fn score(&self, path: &PathManagerPath, now: SystemTime) -> Score {
        let reservations = self.reservations.read().unwrap();
        let (total_hops, covered_hops) = match &path.path.data_plane_path {
            scion_proto::path::DataPlanePath::EmptyPath => (0, 0),
            scion_proto::path::DataPlanePath::Standard(p) => {
                let mut total_hops = 0;
                let mut covered_hops = 0;

                for segment in p.segments() {
                    let info = segment.info_field();

                    for hop in segment.hop_fields() {
                        total_hops += 1;

                        let interfaces = ReservationInterfaces {
                            ingress_interface: hop
                                .ingress_interface(info)
                                .map(|v| v.get())
                                .unwrap_or(0),
                            egress_interface: hop
                                .egress_interface(info)
                                .map(|v| v.get())
                                .unwrap_or(0),
                        };

                        if reservations.contains_key(&interfaces) {
                            covered_hops += 1;
                        }
                    }
                }

                (total_hops, covered_hops)
            }
            scion_proto::path::DataPlanePath::Hummingbird(p) => {
                let mut total_hops = 0;
                let mut covered_hops = 0;

                for segment in p.segments() {
                    let info = segment.info_field();

                    for hop in segment.hop_fields() {
                        total_hops += 1;

                        let interfaces = ReservationInterfaces {
                            ingress_interface: hop
                                .ingress_interface(info)
                                .map(|v| v.get())
                                .unwrap_or(0),
                            egress_interface: hop
                                .egress_interface(info)
                                .map(|v| v.get())
                                .unwrap_or(0),
                        };

                        let have_reservation = reservations
                            .get(&interfaces)
                            .is_some_and(|v| !v.iter().any(|r| !r.is_expired_at(now)));

                        if have_reservation || hop.is_flyover() {
                            covered_hops += 1;
                        }
                    }
                }

                (total_hops, covered_hops)
            }
            scion_proto::path::DataPlanePath::Unsupported { .. } => {
                // Assume that unsupported paths have no Hummingbird coverage.
                return Score::new_clamped(-1.0);
            }
        };

        if total_hops == 0 {
            // Every hop is covered by Hummingbird.
            return Score::new_clamped(1.0);
        }

        let covered_hops = covered_hops as f32;
        let total_hops = total_hops as f32;

        let percentage_covered = covered_hops / total_hops;

        Score::new_clamped(percentage_covered * 2.0 - 1.0)
    }
}

/// Scores paths based on their reliability metric.
///
/// Without this scorer, path issues will be ignored in path selection.
pub struct PathReliabilityScorer;

impl PathScoring for PathReliabilityScorer {
    fn metric_name(&self) -> &'static str {
        "Reliability"
    }

    fn score(&self, path: &PathManagerPath, now: SystemTime) -> Score {
        path.reliability.score(now)
    }
}

/// Aggregates multiple path scorers into a single scoring function.
#[derive(Clone)]
pub struct PathScorer {
    scorers: Vec<(Arc<dyn PathScoring>, f32)>,
}

impl Default for PathScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl PathScorer {
    fn new() -> Self {
        Self { scorers: vec![] }
    }

    /// Returns false if no scorers are configured.
    pub fn is_empty(&self) -> bool {
        self.scorers.is_empty()
    }

    /// Default impact weight for reliability scorer.
    pub const DEFAULT_RELIABILITY_IMPACT: f32 = 1.0;
    /// Default impact weight for length scorer.
    pub const DEFAULT_LENGTH_IMPACT: f32 = 0.1;

    /// Uses default path scorers
    ///
    /// - [PathReliabilityScorer] with weight [PathScorer::DEFAULT_RELIABILITY_IMPACT]
    /// - [PathLengthScorer] with weight [PathScorer::DEFAULT_LENGTH_IMPACT]
    ///
    /// The PathLengthScorer's impact on path decision is minimal, to avoid ignoring reliability.
    pub(crate) fn use_default_scorers(&mut self) {
        self.scorers.push((
            Arc::new(PathReliabilityScorer),
            Self::DEFAULT_RELIABILITY_IMPACT,
        ));
        self.scorers
            .push((Arc::new(PathLengthScorer), Self::DEFAULT_LENGTH_IMPACT));
    }

    /// Adds a scorer with the given impact weight.
    ///
    /// `scorer` - The path scorer to add.
    /// `impact` - The weight of the scorer in the final score aggregation.
    ///            e.g. Impact of 0.2 means the scorer can change the final score by up to ±0.2.
    ///
    /// Note:
    /// The impact weight does not need to sum to 1.0 across all scorers.
    pub fn with_scorer(mut self, scorer: impl PathScoring + 'static, impact: f32) -> Self {
        self.scorers.push((Arc::new(scorer), impact));
        self
    }

    /// Scores the given path by aggregating scores from all configured scorers.
    ///
    /// Total score is the weighted sum of individual scorer scores.
    /// No Normalization is applied.
    pub fn score(&self, path: &PathManagerPath, now: SystemTime) -> f32 {
        let mut total_score = 0.0;
        for (scorer, impact) in &self.scorers {
            let score = scorer.score(path, now).value();
            total_score += score * impact;
        }
        total_score
    }

    /// Generates a report detailing individual scorer contributions to the total score of the path.
    pub fn score_report(&self, path: &PathManagerPath, now: SystemTime) -> ScoreReport {
        let mut report = ScoreReport::default();
        for (scorer, impact) in &self.scorers {
            let score = scorer.score(path, now).value();
            report.add_score(scorer.metric_name(), score * impact);
        }
        report
    }
}

/// A report of weighted scores contributing to a path's total score.
///
/// Used for debugging path scoring decisions.
#[derive(Default, Debug)]
pub struct ScoreReport(pub BTreeMap<&'static str, f32>);

impl ScoreReport {
    fn add_score(&mut self, metric: &'static str, score: f32) {
        self.0.insert(metric, score);
    }
}

impl Display for ScoreReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total: f32 = self.0.values().sum();
        for (metric, score) in &self.0 {
            write!(f, "{}: {:.3} ", metric, score)?;
        }
        write!(f, "Total: {:.3}", total)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cmp::Ordering,
        collections::HashMap,
        hash::{DefaultHasher, Hash, Hasher},
        net::{IpAddr, Ipv4Addr},
        time::SystemTime,
    };

    use bytes::Bytes;
    use chrono::{TimeZone, Utc};
    use scion_proto::{
        address::{Asn, EndhostAddr, Isd, IsdAsn},
        hummingbird::{Bandwidth, Reservation, ReservationInfo},
        packet::ByEndpoint,
        path::{
            DataPlanePath, InfoField, Path, PathType, StandardHopField,
            hummingbird::{HummingbirdHopField, HummingbirdPath},
            test_builder::TestPathBuilder,
        },
    };

    use super::*;
    use crate::path::types::PathManagerPath;

    pub const SRC_ADDR: EndhostAddr = EndhostAddr::new(
        IsdAsn::new(Isd(1), Asn(1)),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    );
    pub const DST_ADDR: EndhostAddr = EndhostAddr::new(
        IsdAsn::new(Isd(2), Asn(1)),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
    );

    pub fn path(hop_count: u16, timestamp: u32, exp_units: u8, asn_seed: u32) -> Path {
        let mut builder = TestPathBuilder::new(SRC_ADDR, DST_ADDR)
            .using_info_timestamp(timestamp)
            .with_hop_expiry(exp_units)
            .up();

        builder = builder.add_hop(0, 1);

        for cnt in 0..hop_count {
            let mut hash = DefaultHasher::new();
            asn_seed.hash(&mut hash);
            cnt.hash(&mut hash);
            let hash = hash.finish() as u32;

            builder = builder.with_asn(hash).add_hop(cnt + 1, cnt + 2);
        }

        builder = builder.add_hop(1, 0);

        builder.build(timestamp).path()
    }

    struct Simulation {
        paths: Vec<PathManagerPath>,
        current_path_index: usize,
        scoring: PathScorer,
        // (sec since start, action)
        actions: Vec<(usize, SimulationAction)>,
        switch_threshold: f32,
    }

    enum SimulationAction {
        UpdateReliability { path_index: usize, score: Score },
        Evaluate,
    }

    impl Simulation {
        fn new(
            scoring: PathScorer,
            initial_paths: Vec<PathManagerPath>,
            switch_threshold: f32,
        ) -> Self {
            Self {
                paths: initial_paths,
                current_path_index: 0,
                scoring,
                actions: vec![],
                switch_threshold,
            }
        }

        fn add_step(self, time: usize, action: SimulationAction) -> Self {
            let mut sim = self;
            sim.actions.push((time, action));
            sim
        }

        fn run(&mut self) {
            let actions = std::mem::take(&mut self.actions);
            const BASE_TIME: SystemTime = SystemTime::UNIX_EPOCH;
            for (time_delta, action) in actions.into_iter() {
                println!("(Time +{}s) -------------------", time_delta);
                let timestamp = BASE_TIME + std::time::Duration::from_secs(time_delta as u64);
                match action {
                    SimulationAction::UpdateReliability { path_index, score } => {
                        println!(
                            "Updating reliability of path {} to score {:.3}",
                            path_index,
                            score.value(),
                        );
                        let path = &mut self.paths[path_index];
                        path.reliability.update(score, timestamp);
                        self.maybe_switch_path(timestamp);
                    }
                    SimulationAction::Evaluate => {
                        println!("Evaluating paths");
                        self.maybe_switch_path(timestamp);
                    }
                }
                println!("-------------------------------");
                self.print_all(timestamp);
                println!("-------------------------------");
            }
        }

        fn maybe_switch_path(&mut self, now: SystemTime) {
            let best_path_index = self.best_path_idx(now);
            let current_path = &self.paths[self.current_path_index];
            let current_score = self.scoring.score(current_path, now);

            let best_path = &self.paths[best_path_index];
            let best_score = self.scoring.score(best_path, now);

            let diff = best_score - current_score;

            if best_path_index == self.current_path_index {
                println!(
                    "Staying on current path {} (score {:.3}) is best path",
                    self.current_path_index, current_score,
                );
                return;
            }

            if diff > self.switch_threshold {
                println!(
                    "Switching from path {} (score {:.3}) to path {} (score {:.3})",
                    self.current_path_index, current_score, best_path_index, best_score
                );
                println!("New path: {}", self.scoring.score_report(best_path, now));
                println!("Old path: {}", self.scoring.score_report(current_path, now));

                self.current_path_index = best_path_index;
            } else {
                println!(
                    "Staying on current path {} (score {:.3}), best path {} (score {:.3}) diff {:.3} below threshold {:.3}",
                    self.current_path_index,
                    current_score,
                    best_path_index,
                    best_score,
                    diff,
                    self.switch_threshold
                );
            }
        }

        fn print_all(&self, now: SystemTime) {
            let mut sorted = self.paths.iter().enumerate().collect::<Vec<_>>();
            sorted.sort_by(|(_, a), (_, b)| {
                let score_a = self.scoring.score(a, now);
                let score_b = self.scoring.score(b, now);
                score_b.partial_cmp(&score_a).unwrap_or(Ordering::Equal)
            });

            for (idx, path) in sorted.iter() {
                println!("Path {}: {}", idx, self.scoring.score_report(path, now));
            }
        }

        fn best_path_idx(&self, now: SystemTime) -> usize {
            self.paths
                .iter()
                .enumerate()
                .max_by(|(_, a), (_, b)| {
                    let score_a = self.scoring.score(a, now);
                    let score_b = self.scoring.score(b, now);
                    score_a.partial_cmp(&score_b).unwrap_or(Ordering::Equal)
                })
                .unwrap()
                .0
        }
    }

    // --- PathHbirdCoverageScorer helpers ---

    fn empty_scorer_reservations() -> Arc<RwLock<ReservationMap>> {
        Arc::new(RwLock::new(HashMap::new()))
    }

    fn scorer_reservations(interfaces: &[(u16, u16)]) -> Arc<RwLock<ReservationMap>> {
        let mut map: ReservationMap = HashMap::new();
        for &(ingress, egress) in interfaces {
            map.insert(
                ReservationInterfaces {
                    ingress_interface: ingress,
                    egress_interface: egress,
                },
                vec![Reservation {
                    info: ReservationInfo {
                        isd_as: SRC_ADDR.isd_asn(),
                        ingress_interface: ingress,
                        egress_interface: egress,
                        res_id: 1,
                        bandwidth: Bandwidth::from_kbps(1000).unwrap(),
                        start: 0,  // Tests assume current time is UNIX_EPOCH
                        duration: 100,   // Lasts for 100 seconds
                    },
                    reservation_key: [0u8; 16].into(),
                }],
            );
        }
        Arc::new(RwLock::new(map))
    }

    fn wrap_dp(dp: DataPlanePath) -> PathManagerPath {
        PathManagerPath::new(Path {
            data_plane_path: dp,
            underlay_next_hop: None,
            isd_asn: ByEndpoint {
                source: SRC_ADDR.isd_asn(),
                destination: DST_ADDR.isd_asn(),
            },
            metadata: None,
        })
    }

    /// Builds a Hummingbird path (cons_dir=true) with the given hop interface pairs.
    /// Hops whose interfaces appear in `flyover_interfaces` are encoded as flyover hops.
    fn build_hbird_path(
        hop_pairs: &[(u16, u16)],
        flyover_interfaces: &[(u16, u16)],
    ) -> DataPlanePath {
        let dst = DST_ADDR.isd_asn();
        let mut hpath =
            HummingbirdPath::new_with_timestamp(Utc.timestamp_opt(1000, 0).single().unwrap(), None);

        let hop_fields: Vec<HummingbirdHopField> = hop_pairs
            .iter()
            .map(|&(ing, eg)| {
                HummingbirdHopField::Standard(StandardHopField {
                    ingress_router_alert: false,
                    egress_router_alert: false,
                    exp_time: 63,
                    cons_ingress: ing,
                    cons_egress: eg,
                    mac: [0u8; 6],
                })
            })
            .collect();

        hpath
            .add_segment(
                InfoField {
                    peer: false,
                    cons_dir: true,
                    seg_id: 0,
                    timestamp_epoch: 1000,
                },
                hop_fields,
            )
            .unwrap();

        for &(ing, eg) in flyover_interfaces {
            hpath
                .add_reservation(Reservation {
                    info: ReservationInfo {
                        isd_as: SRC_ADDR.isd_asn(),
                        ingress_interface: ing,
                        egress_interface: eg,
                        res_id: 1,
                        bandwidth: Bandwidth::from_kbps(1000).unwrap(),
                        start: 900,
                        duration: 200,
                    },
                    reservation_key: [0u8; 16].into(),
                })
                .unwrap();
        }

        let encoded = hpath.to_encoded(dst, 100, None).unwrap();
        DataPlanePath::Hummingbird(encoded)
    }

    fn cov_score(scorer: &PathHbirdCoverageScorer, path: &PathManagerPath) -> f32 {
        PathScoring::score(scorer, path, SystemTime::UNIX_EPOCH).value()
    }

    // --- PathHbirdCoverageScorer tests ---

    #[test]
    fn hbird_coverage_empty_path_returns_max_score() {
        let scorer = PathHbirdCoverageScorer::new(empty_scorer_reservations());
        let path = wrap_dp(DataPlanePath::EmptyPath);
        assert_eq!(cov_score(&scorer, &path), 1.0);
    }

    #[test]
    fn hbird_coverage_unsupported_path_returns_min_score() {
        let scorer = PathHbirdCoverageScorer::new(empty_scorer_reservations());
        let path = wrap_dp(DataPlanePath::Unsupported {
            path_type: PathType::Other(99),
            bytes: Bytes::new(),
        });
        assert_eq!(cov_score(&scorer, &path), -1.0);
    }

    #[test]
    fn hbird_coverage_standard_path_no_reservations_returns_min_score() {
        let scorer = PathHbirdCoverageScorer::new(empty_scorer_reservations());
        let p = TestPathBuilder::new(SRC_ADDR, DST_ADDR)
            .down()
            .add_hop(0, 1)
            .add_hop(1, 0)
            .build(1000)
            .path();
        assert_eq!(cov_score(&scorer, &PathManagerPath::new(p)), -1.0);
    }

    #[test]
    fn hbird_coverage_standard_path_all_covered_returns_max_score() {
        // 2-hop down segment (cons_dir=true): ingress/egress interfaces are {0,1} and {1,0}.
        let scorer = PathHbirdCoverageScorer::new(scorer_reservations(&[(0, 1), (1, 0)]));
        let p = TestPathBuilder::new(SRC_ADDR, DST_ADDR)
            .down()
            .add_hop(0, 1)
            .add_hop(1, 0)
            .build(1000)
            .path();
        assert_eq!(cov_score(&scorer, &PathManagerPath::new(p)), 1.0);
    }

    #[test]
    fn hbird_coverage_standard_path_half_covered_returns_zero() {
        // 2 hops, 1 matching reservation → 50% coverage → score = 0.0.
        let scorer = PathHbirdCoverageScorer::new(scorer_reservations(&[(0, 1)]));
        let p = TestPathBuilder::new(SRC_ADDR, DST_ADDR)
            .down()
            .add_hop(0, 1)
            .add_hop(1, 0)
            .build(1000)
            .path();
        assert_eq!(cov_score(&scorer, &PathManagerPath::new(p)), 0.0);
    }

    #[test]
    fn hbird_coverage_hbird_all_flyover_returns_max_score() {
        // Both hops are flyover → 100% covered regardless of scorer reservations.
        let scorer = PathHbirdCoverageScorer::new(empty_scorer_reservations());
        let path = wrap_dp(build_hbird_path(&[(1, 2), (3, 4)], &[(1, 2), (3, 4)]));
        assert_eq!(cov_score(&scorer, &path), 1.0);
    }

    #[test]
    fn hbird_coverage_hbird_no_flyover_no_reservations_returns_min_score() {
        // All standard hops, no scorer reservations → 0% covered.
        let scorer = PathHbirdCoverageScorer::new(empty_scorer_reservations());
        let path = wrap_dp(build_hbird_path(&[(1, 2), (3, 4)], &[]));
        assert_eq!(cov_score(&scorer, &path), -1.0);
    }

    #[test]
    fn hbird_coverage_hbird_half_flyover_returns_zero() {
        // 2 hops, 1 flyover → 50% → score = 0.0.
        let scorer = PathHbirdCoverageScorer::new(empty_scorer_reservations());
        let path = wrap_dp(build_hbird_path(&[(1, 2), (3, 4)], &[(1, 2)]));
        assert_eq!(cov_score(&scorer, &path), 0.0);
    }

    #[test]
    fn hbird_coverage_hbird_standard_hop_covered_by_scorer_reservation() {
        // Standard hops on a Hummingbird path covered by scorer reservations → 100%.
        let scorer = PathHbirdCoverageScorer::new(scorer_reservations(&[(1, 2), (3, 4)]));
        let path = wrap_dp(build_hbird_path(&[(1, 2), (3, 4)], &[]));
        assert_eq!(cov_score(&scorer, &path), 1.0);
    }

    #[test]
    #[ignore = "Simulation test for manual inspection"]
    fn simulation() {
        // Create some sample paths with different lengths and reliability scores.
        /// Score differences after which we switch preference between two paths.
        const SWITCH_THRESHOLD: f32 = 0.4;

        let paths: Vec<_> = (1..=10)
            .map(|len| {
                let path = path(len, 1000, 100, len as u32);
                PathManagerPath::new(path)
            })
            .collect();

        let scoring = PathScorer::new()
            .with_scorer(PathReliabilityScorer, 1.0)
            .with_scorer(PathLengthScorer, 0.125);

        use SimulationAction::*;
        Simulation::new(scoring, paths, SWITCH_THRESHOLD)
            .add_step(0, Evaluate)
            .add_step(
                10,
                UpdateReliability {
                    path_index: 0,
                    score: Score::new_clamped(-0.5),
                },
            )
            .add_step(
                20,
                UpdateReliability {
                    path_index: 5,
                    score: Score::new_clamped(0.5),
                },
            )
            .add_step(30, Evaluate)
            .add_step(60, Evaluate)
            .add_step(600, Evaluate)
            .add_step(1200, Evaluate)
            .run();
    }
}
