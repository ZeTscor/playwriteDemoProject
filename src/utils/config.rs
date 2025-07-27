//! Configuration management for the secure P2P messenger.
//!
//! This module provides TOML-based configuration with support for multiple
//! configuration sources (default, file-based, environment variables) and
//! validation of configuration parameters.

use crate::utils::{ConfigError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::net::SocketAddr;

/// Default configuration file name
pub const DEFAULT_CONFIG_FILE: &str = "messenger.toml";

/// Environment variable prefix for configuration
pub const ENV_PREFIX: &str = "MESSENGER";

/// Complete configuration for the messenger application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessengerConfig {
    /// Network configuration
    pub network: NetworkConfig,
    /// Cryptographic configuration
    pub crypto: CryptoConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Performance tuning
    pub performance: PerformanceConfig,
}

/// Network and transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Port to listen on for P2P connections
    pub listen_port: u16,
    /// External address for NAT traversal (optional)
    pub external_address: Option<SocketAddr>,
    /// Bootstrap nodes for initial peer discovery
    pub bootstrap_nodes: Vec<String>,
    /// Maximum number of concurrent connections
    pub max_connections: usize,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Message timeout in seconds
    pub message_timeout: u64,
    /// Enable mDNS discovery
    pub enable_mdns: bool,
    /// Enable DHT for peer discovery
    pub enable_dht: bool,
    /// Enable UPnP for NAT traversal
    pub enable_upnp: bool,
    /// Enable relay nodes for NAT traversal
    pub enable_relay: bool,
    /// Custom relay addresses
    pub relay_addresses: Vec<String>,
}

/// Cryptographic configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Key rotation interval in seconds
    pub key_rotation_interval: u64,
    /// Number of one-time prekeys to maintain
    pub prekey_count: usize,
    /// Maximum age for signed prekeys in seconds
    pub signed_prekey_max_age: u64,
    /// Enable perfect forward secrecy
    pub enable_pfs: bool,
    /// Message key cache size
    pub message_key_cache_size: usize,
}

/// Storage and persistence configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Base directory for data storage
    pub data_dir: PathBuf,
    /// Directory for storing keys
    pub keys_dir: PathBuf,
    /// Directory for message storage
    pub messages_dir: PathBuf,
    /// Directory for session storage
    pub sessions_dir: PathBuf,
    /// Maximum storage size in bytes (0 = unlimited)
    pub max_storage_size: u64,
    /// Enable compression for stored data
    pub enable_compression: bool,
    /// Backup interval in seconds (0 = disabled)
    pub backup_interval: u64,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (error, warn, info, debug, trace)
    pub level: String,
    /// Enable file logging
    pub enable_file_logging: bool,
    /// Log file path
    pub log_file: Option<PathBuf>,
    /// Maximum log file size in bytes
    pub max_log_size: u64,
    /// Number of log files to keep
    pub log_rotation_count: usize,
    /// Enable structured JSON logging
    pub json_format: bool,
}

/// Performance tuning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Number of worker threads for async runtime
    pub worker_threads: Option<usize>,
    /// Buffer size for network operations
    pub network_buffer_size: usize,
    /// Maximum message queue size
    pub max_message_queue_size: usize,
    /// Enable optimizations for low-latency mode
    pub low_latency_mode: bool,
    /// Batch size for database operations
    pub batch_size: usize,
}

impl Default for MessengerConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            crypto: CryptoConfig::default(),
            storage: StorageConfig::default(),
            logging: LoggingConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_port: crate::defaults::DEFAULT_PORT,
            external_address: None,
            bootstrap_nodes: Vec::new(),
            max_connections: crate::defaults::DEFAULT_MAX_PEERS,
            connection_timeout: 30,
            message_timeout: crate::defaults::DEFAULT_MESSAGE_TIMEOUT,
            enable_mdns: true,
            enable_dht: true,
            enable_upnp: true,
            enable_relay: true,
            relay_addresses: Vec::new(),
        }
    }
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            key_rotation_interval: crate::defaults::DEFAULT_KEY_ROTATION_INTERVAL,
            prekey_count: crate::crypto::DEFAULT_PREKEY_COUNT,
            signed_prekey_max_age: crate::crypto::SIGNED_PREKEY_MAX_AGE,
            enable_pfs: true,
            message_key_cache_size: 1000,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("secure-p2p-messenger");

        Self {
            keys_dir: data_dir.join("keys"),
            messages_dir: data_dir.join("messages"),
            sessions_dir: data_dir.join("sessions"),
            data_dir: data_dir.clone(),
            max_storage_size: 0, // Unlimited
            enable_compression: true,
            backup_interval: 3600, // 1 hour
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            enable_file_logging: true,
            log_file: None,
            max_log_size: 10 * 1024 * 1024, // 10MB
            log_rotation_count: 5,
            json_format: false,
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            worker_threads: None, // Use tokio default
            network_buffer_size: 64 * 1024, // 64KB
            max_message_queue_size: 10000,
            low_latency_mode: false,
            batch_size: 100,
        }
    }
}

impl MessengerConfig {
    /// Load configuration from a TOML file
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the configuration file
    ///
    /// # Errors
    ///
    /// Returns error if file cannot be read or parsed
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|_| ConfigError::FileNotFound {
            path: path.display().to_string(),
        })?;

        let config: Self = toml::from_str(&content).map_err(ConfigError::from)?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration with multiple sources (default, file, environment)
    ///
    /// # Arguments
    ///
    /// * `config_file` - Optional path to configuration file
    ///
    /// # Returns
    ///
    /// Configuration with values merged from multiple sources
    pub fn load(config_file: Option<&Path>) -> Result<Self> {
        let mut config = Self::default();

        // Load from file if provided
        if let Some(path) = config_file {
            if path.exists() {
                let file_config = Self::from_file(path)?;
                config = config.merge(file_config);
            }
        } else {
            // Try default config file locations
            let default_locations = [
                PathBuf::from(DEFAULT_CONFIG_FILE),
                dirs::config_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("secure-p2p-messenger")
                    .join(DEFAULT_CONFIG_FILE),
            ];

            for location in &default_locations {
                if location.exists() {
                    let file_config = Self::from_file(location)?;
                    config = config.merge(file_config);
                    break;
                }
            }
        }

        // Override with environment variables
        config = config.merge_from_env()?;
        config.validate()?;

        Ok(config)
    }

    /// Save configuration to a TOML file
    ///
    /// # Arguments
    ///
    /// * `path` - Path where to save the configuration
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self).map_err(|e| ConfigError::ParseError {
            reason: e.to_string(),
        })?;

        std::fs::write(path, content)?;
        Ok(())
    }

    /// Merge this configuration with another, preferring values from other
    ///
    /// # Arguments
    ///
    /// * `other` - Configuration to merge with
    pub fn merge(mut self, other: Self) -> Self {
        // For this example, we'll do a simple replacement merge
        // In a real implementation, you might want field-level merging
        self.network = other.network;
        self.crypto = other.crypto;
        self.storage = other.storage;
        self.logging = other.logging;
        self.performance = other.performance;
        self
    }

    /// Merge configuration from environment variables
    fn merge_from_env(mut self) -> Result<Self> {
        // Example environment variable overrides
        if let Ok(port) = std::env::var("MESSENGER_NETWORK_LISTEN_PORT") {
            self.network.listen_port = port.parse().map_err(|_| ConfigError::InvalidValue {
                field: "MESSENGER_NETWORK_LISTEN_PORT".to_string(),
                value: port,
            })?;
        }

        if let Ok(level) = std::env::var("MESSENGER_LOGGING_LEVEL") {
            self.logging.level = level;
        }

        if let Ok(data_dir) = std::env::var("MESSENGER_STORAGE_DATA_DIR") {
            self.storage.data_dir = PathBuf::from(data_dir);
        }

        Ok(self)
    }

    /// Validate the configuration for consistency and correctness
    pub fn validate(&self) -> Result<()> {
        // Validate network configuration
        if self.network.listen_port == 0 {
            return Err(ConfigError::InvalidValue {
                field: "network.listen_port".to_string(),
                value: "0".to_string(),
            }
            .into());
        }

        if self.network.max_connections == 0 {
            return Err(ConfigError::InvalidValue {
                field: "network.max_connections".to_string(),
                value: "0".to_string(),
            }
            .into());
        }

        // Validate crypto configuration
        if self.crypto.prekey_count == 0 {
            return Err(ConfigError::InvalidValue {
                field: "crypto.prekey_count".to_string(),
                value: "0".to_string(),
            }
            .into());
        }

        // Validate logging level
        match self.logging.level.as_str() {
            "error" | "warn" | "info" | "debug" | "trace" => {}
            _ => {
                return Err(ConfigError::InvalidValue {
                    field: "logging.level".to_string(),
                    value: self.logging.level.clone(),
                }
                .into());
            }
        }

        Ok(())
    }

    /// Ensure all required directories exist
    pub fn ensure_directories(&self) -> Result<()> {
        let dirs_to_create = [
            &self.storage.data_dir,
            &self.storage.keys_dir,
            &self.storage.messages_dir,
            &self.storage.sessions_dir,
        ];

        for dir in &dirs_to_create {
            if !dir.exists() {
                std::fs::create_dir_all(dir).map_err(|_| ConfigError::DirectoryCreation {
                    path: dir.display().to_string(),
                })?;
            }
        }

        Ok(())
    }

    /// Get the configuration as a pretty-printed TOML string
    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| ConfigError::ParseError {
            reason: e.to_string(),
        }.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = MessengerConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.network.listen_port, crate::defaults::DEFAULT_PORT);
        assert!(config.network.enable_mdns);
        assert!(config.crypto.enable_pfs);
    }

    #[test]
    fn test_config_serialization() {
        let config = MessengerConfig::default();
        let toml_str = config.to_toml_string().unwrap();
        assert!(toml_str.contains("listen_port"));
        assert!(toml_str.contains("enable_mdns"));
    }

    #[test]
    fn test_config_file_operations() {
        let config = MessengerConfig::default();
        let temp_file = NamedTempFile::new().unwrap();
        
        // Save and load
        config.save(temp_file.path()).unwrap();
        let loaded_config = MessengerConfig::from_file(temp_file.path()).unwrap();
        
        assert_eq!(config.network.listen_port, loaded_config.network.listen_port);
        assert_eq!(config.crypto.prekey_count, loaded_config.crypto.prekey_count);
    }

    #[test]
    fn test_config_validation() {
        let mut config = MessengerConfig::default();
        
        // Valid config should pass
        assert!(config.validate().is_ok());
        
        // Invalid port should fail
        config.network.listen_port = 0;
        assert!(config.validate().is_err());
        
        // Reset and test invalid prekey count
        config = MessengerConfig::default();
        config.crypto.prekey_count = 0;
        assert!(config.validate().is_err());
        
        // Reset and test invalid log level
        config = MessengerConfig::default();
        config.logging.level = "invalid".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_merge() {
        let mut config1 = MessengerConfig::default();
        let mut config2 = MessengerConfig::default();
        
        config1.network.listen_port = 4001;
        config2.network.listen_port = 4002;
        
        let merged = config1.merge(config2);
        assert_eq!(merged.network.listen_port, 4002);
    }

    #[test]
    fn test_env_override() {
        std::env::set_var("MESSENGER_NETWORK_LISTEN_PORT", "9999");
        
        let config = MessengerConfig::default().merge_from_env().unwrap();
        assert_eq!(config.network.listen_port, 9999);
        
        std::env::remove_var("MESSENGER_NETWORK_LISTEN_PORT");
    }

    #[test]
    fn test_directory_paths() {
        let config = MessengerConfig::default();
        
        // All directory paths should be under data_dir
        assert!(config.storage.keys_dir.starts_with(&config.storage.data_dir));
        assert!(config.storage.messages_dir.starts_with(&config.storage.data_dir));
        assert!(config.storage.sessions_dir.starts_with(&config.storage.data_dir));
    }
}