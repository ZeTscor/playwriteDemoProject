//! Error types and handling for the secure P2P messenger.
//!
//! This module provides a unified error handling system across all components
//! of the messenger, implementing proper error propagation and user-friendly
//! error messages.

use thiserror::Error;

/// Result type alias for the messenger library
pub type Result<T> = std::result::Result<T, MessengerError>;

/// Comprehensive error type for all messenger operations
#[derive(Error, Debug, Clone)]
pub enum MessengerError {
    /// Cryptographic operation errors
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    /// Network and transport layer errors
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    /// Session management errors
    #[error("Session error: {0}")]
    Session(#[from] SessionError),

    /// Configuration and I/O errors
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// Protocol-level errors
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    /// Generic I/O errors
    #[error("I/O error: {0}")]
    Io(String),

    /// JSON serialization errors
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Base64 encoding/decoding errors
    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// UTF-8 conversion errors
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    /// Generic error for unexpected conditions
    #[error("Unexpected error: {0}")]
    Unexpected(String),
}

/// Cryptographic operation errors
#[derive(Error, Debug, Clone)]
pub enum CryptoError {
    /// Invalid key format or size
    #[error("Invalid key: {reason}")]
    InvalidKey { reason: String },

    /// Key generation failure
    #[error("Key generation failed: {reason}")]
    KeyGeneration { reason: String },

    /// Signature verification failure
    #[error("Signature verification failed")]
    SignatureVerification,

    /// Encryption operation failure
    #[error("Encryption failed: {reason}")]
    Encryption { reason: String },

    /// Decryption operation failure
    #[error("Decryption failed: {reason}")]
    Decryption { reason: String },

    /// Key derivation failure
    #[error("Key derivation failed: {reason}")]
    KeyDerivation { reason: String },

    /// Invalid cryptographic parameters
    #[error("Invalid crypto parameters: {reason}")]
    InvalidParameters { reason: String },

    /// Random number generation failure
    #[error("RNG error: {reason}")]
    Rng { reason: String },
}

/// Network and transport layer errors
#[derive(Error, Debug, Clone)]
pub enum NetworkError {
    /// Connection establishment failure
    #[error("Connection failed to {peer}: {reason}")]
    ConnectionFailed { peer: String, reason: String },

    /// Peer discovery failure
    #[error("Peer discovery failed: {reason}")]
    DiscoveryFailed { reason: String },

    /// Network transport error
    #[error("Transport error: {reason}")]
    Transport { reason: String },

    /// Timeout during network operation
    #[error("Network timeout: {operation}")]
    Timeout { operation: String },

    /// Invalid network address
    #[error("Invalid address: {address}")]
    InvalidAddress { address: String },

    /// Peer not found in routing table
    #[error("Peer not found: {peer_id}")]
    PeerNotFound { peer_id: String },

    /// NAT traversal failure
    #[error("NAT traversal failed: {reason}")]
    NatTraversal { reason: String },

    /// DHT operation failure
    #[error("DHT operation failed: {operation}: {reason}")]
    DhtFailure { operation: String, reason: String },
}

/// Session management errors
#[derive(Error, Debug, Clone)]
pub enum SessionError {
    /// Session not found
    #[error("Session not found: {session_id}")]
    NotFound { session_id: String },

    /// Session key derivation failure
    #[error("Session key derivation failed: {reason}")]
    KeyDerivation { reason: String },

    /// Invalid session state for operation
    #[error("Invalid session state: {state}")]
    InvalidState { state: String },

    /// X3DH protocol failure
    #[error("X3DH failure: {reason}")]
    X3DHFailure { reason: String },

    /// Double Ratchet operation failure
    #[error("Double Ratchet failure: {reason}")]
    DoubleRatchetFailure { reason: String },

    /// Message ordering violation
    #[error("Message ordering violation: expected {expected}, got {actual}")]
    MessageOrdering { expected: u32, actual: u32 },

    /// Session expired
    #[error("Session expired: {session_id}")]
    Expired { session_id: String },

    /// Prekey bundle invalid or expired
    #[error("Invalid prekey bundle: {reason}")]
    InvalidPrekeyBundle { reason: String },
}

/// Configuration and setup errors
#[derive(Error, Debug, Clone)]
pub enum ConfigError {
    /// Missing required configuration
    #[error("Missing configuration: {field}")]
    MissingField { field: String },

    /// Invalid configuration value
    #[error("Invalid configuration value for {field}: {value}")]
    InvalidValue { field: String, value: String },

    /// Configuration file not found
    #[error("Configuration file not found: {path}")]
    FileNotFound { path: String },

    /// Configuration parsing error
    #[error("Configuration parse error: {reason}")]
    ParseError { reason: String },

    /// TOML parsing error
    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),

    /// Directory creation failure
    #[error("Failed to create directory: {path}")]
    DirectoryCreation { path: String },
}

/// Protocol-level errors
#[derive(Error, Debug, Clone)]
pub enum ProtocolError {
    /// Unsupported protocol version
    #[error("Unsupported protocol version: {version}")]
    UnsupportedVersion { version: String },

    /// Invalid message format
    #[error("Invalid message format: {reason}")]
    InvalidMessage { reason: String },

    /// Message too large
    #[error("Message too large: {size} bytes (max: {max})")]
    MessageTooLarge { size: usize, max: usize },

    /// Invalid message type for current context
    #[error("Invalid message type: {message_type}")]
    InvalidMessageType { message_type: String },

    /// Missing required message field
    #[error("Missing required field: {field}")]
    MissingField { field: String },

    /// Checksum verification failure
    #[error("Checksum verification failed")]
    ChecksumMismatch,

    /// Message replay detected
    #[error("Message replay detected: {message_id}")]
    ReplayDetected { message_id: String },
}

impl MessengerError {
    /// Creates a new unexpected error with a custom message
    pub fn unexpected<S: Into<String>>(msg: S) -> Self {
        Self::Unexpected(msg.into())
    }

    /// Returns true if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::Network(NetworkError::Timeout { .. })
                | Self::Network(NetworkError::ConnectionFailed { .. })
                | Self::Session(SessionError::Expired { .. })
                | Self::Protocol(ProtocolError::MessageTooLarge { .. })
        )
    }

    /// Returns true if this error indicates a security violation
    pub fn is_security_violation(&self) -> bool {
        matches!(
            self,
            Self::Crypto(CryptoError::SignatureVerification)
                | Self::Crypto(CryptoError::Decryption { .. })
                | Self::Protocol(ProtocolError::ReplayDetected { .. })
                | Self::Protocol(ProtocolError::ChecksumMismatch)
        )
    }
}

impl From<std::io::Error> for MessengerError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

impl From<serde_json::Error> for MessengerError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}

impl From<libp2p::swarm::DialError> for MessengerError {
    fn from(err: libp2p::swarm::DialError) -> Self {
        Self::Network(NetworkError::ConnectionFailed {
            peer: "unknown".to_string(),
            reason: err.to_string(),
        })
    }
}

impl From<libp2p::swarm::ConnectionDenied> for MessengerError {
    fn from(err: libp2p::swarm::ConnectionDenied) -> Self {
        Self::Network(NetworkError::ConnectionFailed {
            peer: "unknown".to_string(),
            reason: err.to_string(),
        })
    }
}

impl From<bincode::Error> for MessengerError {
    fn from(err: bincode::Error) -> Self {
        Self::Protocol(ProtocolError::InvalidMessage {
            reason: err.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = MessengerError::Crypto(CryptoError::InvalidKey {
            reason: "Invalid key length".to_string(),
        });
        assert!(error.to_string().contains("Invalid key"));
    }

    #[test]
    fn test_error_recovery() {
        let timeout_error = MessengerError::Network(NetworkError::Timeout {
            operation: "connect".to_string(),
        });
        assert!(timeout_error.is_recoverable());

        let crypto_error = MessengerError::Crypto(CryptoError::SignatureVerification);
        assert!(!crypto_error.is_recoverable());
    }

    #[test]
    fn test_security_violations() {
        let sig_error = MessengerError::Crypto(CryptoError::SignatureVerification);
        assert!(sig_error.is_security_violation());

        let network_error = MessengerError::Network(NetworkError::Timeout {
            operation: "connect".to_string(),
        });
        assert!(!network_error.is_security_violation());
    }
}