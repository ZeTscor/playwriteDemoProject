//! Transport layer for P2P messaging.
//!
//! This module provides the network transport capabilities for the secure
//! messenger, including message protocols and libp2p-based networking.

pub mod p2p;
pub mod protocol;
pub mod simple;

pub use protocol::*;
pub use p2p::P2PTransport;