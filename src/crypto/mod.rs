//! Cryptographic primitives and identity management.
//!
//! This module provides all cryptographic functionality needed for the secure
//! P2P messenger, including identity management, prekey generation, and key
//! agreement protocols.

pub mod identity;
pub mod prekeys;
pub mod simple_prekeys;

pub use identity::*;
pub use prekeys::*;