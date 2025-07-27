//! # Secure P2P Messenger
//!
//! A secure peer-to-peer messaging library implementing the Double Ratchet algorithm
//! and X3DH key agreement protocol for end-to-end encrypted communication.
//!
//! ## Features
//!
//! - **End-to-End Encryption**: Uses Double Ratchet algorithm for forward secrecy
//! - **Key Agreement**: X3DH protocol for secure key establishment
//! - **P2P Networking**: Built on libp2p with DHT discovery and NAT traversal
//! - **Identity Management**: Ed25519-based cryptographic identities
//! - **Modular Design**: Clean separation of concerns across modules
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use secure_p2p_messenger::{App, MessengerConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = MessengerConfig::default();
//!     let mut app = App::new(config).await?;
//!     app.run().await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture
//!
//! The library is organized into several key modules:
//!
//! - [`crypto`]: Cryptographic primitives and identity management
//! - [`session`]: Session management and key agreement protocols
//! - [`transport`]: Low-level transport protocols and message handling
//! - [`utils`]: Configuration, error handling, and utilities
//!
//! Each module is designed to be used independently or as part of the complete
//! messaging system.

#![warn(missing_docs)]
#![deny(unsafe_code)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::cargo)]
#![allow(clippy::module_name_repetitions)]

pub mod app;
pub mod crypto;
pub mod network;
pub mod session;
pub mod transport;
pub mod utils;

// Re-export commonly used types for convenience
pub use app::App;
pub use crypto::{Identity, IdentityKeyPair, UserProfile};
pub use session::SessionManager;
pub use transport::{P2PMessage, MessageType};
pub use utils::{MessengerConfig, MessengerError, Result};

/// Version information for the messenger protocol
pub const PROTOCOL_VERSION: &str = "1.0.0";

/// Maximum message size in bytes (1MB)
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Default configuration values
pub mod defaults {
    /// Default port for P2P communication
    pub const DEFAULT_PORT: u16 = 4001;
    
    /// Default maximum number of peers to maintain connections with
    pub const DEFAULT_MAX_PEERS: usize = 50;
    
    /// Default message timeout in seconds
    pub const DEFAULT_MESSAGE_TIMEOUT: u64 = 30;
    
    /// Default key rotation interval in seconds (24 hours)
    pub const DEFAULT_KEY_ROTATION_INTERVAL: u64 = 86400;
}