use std::{
    sync::{Arc, RwLock},
    time::SystemTime,
};

use scion_proto::{
    address::IsdAsn,
    path::{DataPlanePath, Path, StandardPath, hummingbird::ReservationMap},
    scmp::ScmpErrorMessage,
};

use crate::{
    path::{
        PathStrategy,
        fetcher::{
            PathFetcherImpl,
            traits::{PathFetchError, PathFetcher},
        },
        manager::{
            MultiPathManager, MultiPathManagerConfig,
            issues::IssueKind,
            traits::{PathManager, PathPrefetcher, PathWaitError, SyncPathManager},
        },
    },
    scionstack::{
        ScionSocketSendError, scmp_handler::ScmpErrorReceiver, socket::SendErrorReceiver,
    },
};

/// Path manager for managing paths when using Hummingbird.
#[derive(Clone)]
pub struct HummingbirdPathManager<F: PathFetcher = PathFetcherImpl> {
    multi_path_manager: MultiPathManager<F>,
    reservations: Arc<RwLock<ReservationMap>>,
}

impl<F: PathFetcher> HummingbirdPathManager<F> {
    /// Creates a new [`HummingbirdPathManager`].
    pub fn new(
        config: MultiPathManagerConfig,
        fetcher: F,
        path_strategy: PathStrategy,
        reservations: Arc<RwLock<ReservationMap>>,
    ) -> Result<Self, &'static str> {
        Ok(Self {
            multi_path_manager: MultiPathManager::new(config, fetcher, path_strategy)?,
            reservations,
        })
    }

    /// Tries to get the active path for the given src-dst pair.
    ///
    /// If no active path is set, returns None.
    ///
    /// If the src-dst pair is not yet managed, starts managing it.
    ///
    /// Reservations can only be used if `payload_len` is provided.
    pub fn try_path(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        payload_len: Option<usize>,
        now: SystemTime,
    ) -> Option<Path> {
        self.multi_path_manager
            .try_path(src, dst, now)
            .map(|path| self.apply_reservations(path, payload_len, now))
    }

    fn apply_reservations(
        &self,
        mut path: Path,
        payload_len: Option<usize>,
        now: SystemTime,
    ) -> Path {
        // No payload length, no Hummingbird
        if payload_len.is_none() {
            return path;
        }
        let payload_len = payload_len.unwrap();

        // Cast payload length to u16
        if payload_len > u16::MAX as usize {
            tracing::warn!(%payload_len, "Payload length too large for Hummingbird reservations, skipping reservation application");
            return path;
        }
        let payload_len = payload_len as u16;

        let src = path.source();
        let dst = path.destination();
        let reservations = self.reservations.read().unwrap();

        // Try to convert to Hummingbird path
        let hbird_path = match path.data_plane_path.clone() {
            DataPlanePath::Standard(p) => p
                .try_into()
                .map(|p: StandardPath| p.to_hummingbird_with_timestamp(now.into(), None)),
            DataPlanePath::Hummingbird(p) => p.try_into(),
            _ => return path,
        };
        if hbird_path.is_err() {
            tracing::warn!(%src, %dst, "Failed to convert path to Hummingbird format: {}", hbird_path.err().unwrap());
            return path;
        }
        let mut hbird_path = hbird_path.unwrap();

        // Encode path with reservations
        let hbird_path = hbird_path.to_encoded(dst, payload_len, Some(&reservations));
        if hbird_path.is_err() {
            tracing::warn!(%src, %dst, "Failed to encode Hummingbird path with reservations: {}", hbird_path.err().unwrap());
            return path;
        }
        let hbird_path = hbird_path.unwrap();

        path.data_plane_path = DataPlanePath::Hummingbird(hbird_path);
        path
    }

    /// Gets the active path for the given src-dst pair.
    ///
    /// If the src-dst pair is not yet managed, starts managing it, possibly waiting for the first
    /// path fetch.
    ///
    /// Returns an error if no path is available after waiting.
    pub async fn path(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        payload_len: Option<usize>,
        now: SystemTime,
    ) -> Result<Path, Arc<PathFetchError>> {
        self.multi_path_manager
            .path(src, dst, now)
            .await
            .map(|path| self.apply_reservations(path, payload_len, now))
    }

    /// Starts managing paths for the given src-dst pair.
    fn ensure_managed_paths(&self, src: IsdAsn, dst: IsdAsn) {
        self.multi_path_manager.ensure_managed_paths(src, dst);
    }

    /// Stops managing paths for the given src-dst pair.
    pub fn stop_managing_paths(&self, src: IsdAsn, dst: IsdAsn) {
        self.multi_path_manager.stop_managing_paths(src, dst);
    }

    /// report error
    pub fn report_path_issue(&self, timestamp: SystemTime, issue: IssueKind, path: Option<&Path>) {
        // TODO: Check if this works as intended
        self.multi_path_manager
            .report_path_issue(timestamp, issue, path);
    }
}

impl<F: PathFetcher> ScmpErrorReceiver for HummingbirdPathManager<F> {
    fn report_scmp_error(&self, scmp_error: ScmpErrorMessage, path: &Path) {
        self.multi_path_manager.report_scmp_error(scmp_error, path);
    }
}

impl<F: PathFetcher> SendErrorReceiver for HummingbirdPathManager<F> {
    fn report_send_error(&self, error: &ScionSocketSendError) {
        self.multi_path_manager.report_send_error(error);
    }
}

impl<F: PathFetcher> SyncPathManager for HummingbirdPathManager<F> {
    fn register_path(
        &self,
        _src: IsdAsn,
        _dst: IsdAsn,
        _now: chrono::DateTime<chrono::Utc>,
        _path: Path<bytes::Bytes>,
    ) {
        self.multi_path_manager
            .register_path(_src, _dst, _now, _path);
    }

    fn try_cached_path(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        now: chrono::DateTime<chrono::Utc>,
    ) -> std::io::Result<Option<Path<bytes::Bytes>>> {
        self.multi_path_manager
            .try_cached_path(src, dst, now)
            .map(|opt_path| opt_path.map(|path| self.apply_reservations(path, None, now.into())))
    }
}

impl<F: PathFetcher> PathManager for HummingbirdPathManager<F> {
    fn path_wait(
        &self,
        src: IsdAsn,
        dst: IsdAsn,
        payload_len: Option<usize>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> impl crate::types::ResFut<'_, Path<bytes::Bytes>, PathWaitError> {
        async move {
            self.multi_path_manager
                .path_wait(src, dst, payload_len, now)
                .await
                .map(move |path| self.apply_reservations(path, payload_len, now.into()))
        }
    }
}

impl<F: PathFetcher> PathPrefetcher for HummingbirdPathManager<F> {
    fn prefetch_path(&self, src: IsdAsn, dst: IsdAsn) {
        self.ensure_managed_paths(src, dst);
    }
}
