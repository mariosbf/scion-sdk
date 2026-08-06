// Copyright 2026 Anapaya Systems
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

//! QUIC configuration options.

use std::time::Duration;

pub use squiche::{PROTOCOL_VERSION, SCION_PROTOCOL_VERSION};

use crate::DEFAULT_MAX_UDP_PAYLOAD_SIZE;

/// Default handshake timeout.
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default idle timeout for connections.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// QUIC client configuration.
#[derive(Debug, Clone)]
pub struct QuicConfig {
    /// QUIC wire version to use for the handshake.
    ///
    /// Defaults to [`squiche::SCION_PROTOCOL_VERSION`], which permits shorter Initial packets
    /// (600 instead of 1200 bytes) but is only understood by squiche peers. Set this to
    /// [`squiche::PROTOCOL_VERSION`] when talking to a stack built on a stock QUIC
    /// implementation, such as the quic-go based open-source SCION services, which will not
    /// negotiate an unknown version.
    pub protocol_version: u32,
    /// Timeout for QUIC handshake completion.
    pub handshake_timeout: Duration,
    /// Idle timeout for connections.
    pub idle_timeout: Duration,
    /// Maximum UDP payload size.
    pub max_udp_payload_size: usize,
    /// Application protocols to advertise (ALPN).
    pub application_protos: Vec<Vec<u8>>,
    /// Whether to verify the server certificate.
    pub verify_peer: bool,
    /// Whether the server certificate must match the server name.
    ///
    /// Defaults to `true`. Set this to `false` for peers whose certificates carry no
    /// `subjectAltName` to match against, such as SCION control-plane PKI certificates, which
    /// identify the AS through a private OID in the subject instead. Note that squiche couples
    /// the two uses of the server name, so disabling the check also stops the name from being
    /// sent as SNI; the `:authority` header is taken from the request URL and is unaffected.
    pub verify_server_name: bool,
    /// Optional path to CA certificates directory.
    ///
    /// This is looked up in OpenSSL hashed-directory form: each trust anchor must be a file named
    /// `<subject_hash>.<n>`, as produced by `c_rehash` or `openssl x509 -hash -noout -in <cert>`.
    /// A directory of plainly-named `.crt`/`.pem` files silently yields no trust anchors, and
    /// every handshake then fails with `TlsFail`.
    pub ca_certs_directory: Option<String>,
    /// Initial max data.
    pub initial_max_data: u64,
    /// Initial max stream data for bidirectional local streams.
    pub initial_max_stream_data_bidi_local: u64,
    /// Initial max stream data for bidirectional remote streams.
    pub initial_max_stream_data_bidi_remote: u64,
    /// Initial max stream data for unidirectional streams.
    pub initial_max_stream_data_uni: u64,
    /// Initial max bidirectional streams.
    pub initial_max_streams_bidi: u64,
    /// Initial max unidirectional streams.
    pub initial_max_streams_uni: u64,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            protocol_version: squiche::SCION_PROTOCOL_VERSION,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_udp_payload_size: DEFAULT_MAX_UDP_PAYLOAD_SIZE,
            application_protos: vec![b"h3".to_vec()],
            verify_peer: true,
            verify_server_name: true,
            ca_certs_directory: None,
            initial_max_data: 10_000_000,
            initial_max_stream_data_bidi_local: 1_000_000,
            initial_max_stream_data_bidi_remote: 1_000_000,
            initial_max_stream_data_uni: 1_000_000,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
        }
    }
}

impl QuicConfig {
    /// Creates a new configuration builder.
    pub fn builder() -> QuicConfigBuilder {
        QuicConfigBuilder::default()
    }

    /// Creates a squiche::Config from this configuration.
    pub fn to_quiche_config(&self) -> Result<squiche::Config, squiche::Error> {
        let mut config = squiche::Config::new(self.protocol_version)?;

        config.set_application_protos(
            &self
                .application_protos
                .iter()
                .map(|p| p.as_slice())
                .collect::<Vec<_>>(),
        )?;

        if let Some(ca_certs_dir) = &self.ca_certs_directory {
            config.load_verify_locations_from_directory(ca_certs_dir)?;
        }

        config.set_max_idle_timeout(self.idle_timeout.as_millis() as u64);
        config.set_max_recv_udp_payload_size(self.max_udp_payload_size);
        config.set_max_send_udp_payload_size(self.max_udp_payload_size);
        config.set_initial_max_data(self.initial_max_data);
        config.set_initial_max_stream_data_bidi_local(self.initial_max_stream_data_bidi_local);
        config.set_initial_max_stream_data_bidi_remote(self.initial_max_stream_data_bidi_remote);
        config.set_initial_max_stream_data_uni(self.initial_max_stream_data_uni);
        config.set_initial_max_streams_bidi(self.initial_max_streams_bidi);
        config.set_initial_max_streams_uni(self.initial_max_streams_uni);
        config.set_disable_active_migration(true);

        config.verify_peer(self.verify_peer);

        Ok(config)
    }
}

/// Builder for [`QuicConfig`].
#[derive(Debug, Default)]
pub struct QuicConfigBuilder {
    config: QuicConfig,
}

impl QuicConfigBuilder {
    /// Sets the QUIC wire version used for the handshake.
    pub fn protocol_version(mut self, version: u32) -> Self {
        self.config.protocol_version = version;
        self
    }

    /// Sets the handshake timeout.
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.config.handshake_timeout = timeout;
        self
    }

    /// Sets the idle timeout.
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.config.idle_timeout = timeout;
        self
    }

    /// Sets the maximum UDP payload size.
    pub fn max_udp_payload_size(mut self, size: usize) -> Self {
        self.config.max_udp_payload_size = size;
        self
    }

    /// Sets the application protocols (ALPN).
    pub fn application_protos(mut self, protos: Vec<Vec<u8>>) -> Self {
        self.config.application_protos = protos;
        self
    }

    /// Sets whether to verify the peer's certificate.
    pub fn verify_peer(mut self, verify: bool) -> Self {
        self.config.verify_peer = verify;
        self
    }

    /// Sets whether the peer's certificate must match the server name.
    pub fn verify_server_name(mut self, verify: bool) -> Self {
        self.config.verify_server_name = verify;
        self
    }

    /// Sets the path to CA certificates file for verification.
    ///
    /// The directory must be in OpenSSL hashed form; see [`QuicConfig::ca_certs_directory`].
    pub fn ca_certs_dir(mut self, path: impl Into<String>) -> Self {
        self.config.ca_certs_directory = Some(path.into());
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> QuicConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_the_scion_quic_version_with_full_verification() {
        let config = QuicConfig::default();

        assert_eq!(config.protocol_version, squiche::SCION_PROTOCOL_VERSION);
        assert!(config.verify_peer);
        assert!(config.verify_server_name);
    }

    #[test]
    fn builder_overrides_the_protocol_version() {
        let config = QuicConfig::builder()
            .protocol_version(squiche::PROTOCOL_VERSION)
            .verify_server_name(false)
            .build();

        assert_eq!(config.protocol_version, squiche::PROTOCOL_VERSION);
        assert!(config.verify_peer);
        assert!(!config.verify_server_name);
    }

    #[test]
    fn quiche_config_rejects_an_unknown_protocol_version() {
        let config = QuicConfig::builder().protocol_version(0xdead_beef).build();

        assert!(matches!(
            config.to_quiche_config(),
            Err(squiche::Error::UnknownVersion)
        ));
    }
}
