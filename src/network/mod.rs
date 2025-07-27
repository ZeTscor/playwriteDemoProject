//! Network layer for peer discovery and connectivity.
//!
//! This module provides network-level functionality including peer discovery,
//! NAT traversal, and connectivity testing.

pub mod discovery;

pub use discovery::*;