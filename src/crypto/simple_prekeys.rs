//! Simplified prekey generation for demonstration purposes.
//!
//! This module provides a simplified version of prekey generation without
//! complex X25519 dependencies, suitable for demonstrating the overall
//! architecture.

use crate::crypto::IdentityKeyPair;
use crate::utils::{CryptoError, Result};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Number of one-time prekeys to generate by default
pub const DEFAULT_PREKEY_COUNT: usize = 100;

/// Maximum age of a signed prekey before rotation (30 days in seconds)
pub const SIGNED_PREKEY_MAX_AGE: u64 = 30 * 24 * 60 * 60;

/// A one-time prekey for key agreement (simplified)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePrekey {
    /// Unique identifier for this prekey
    pub id: u32,
    /// Simplified public key (32 bytes for demo)
    pub public_key: Vec<u8>,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl OneTimePrekey {
    /// Create a new one-time prekey
    pub fn new(id: u32) -> (Self, [u8; 32]) {
        let mut private_key = [0u8; 32];
        let mut public_key = [0u8; 32];
        
        // Generate random keys (simplified)
        rand::RngCore::fill_bytes(&mut OsRng, &mut private_key);
        rand::RngCore::fill_bytes(&mut OsRng, &mut public_key);

        let prekey = Self {
            id,
            public_key: public_key.to_vec(),
            created_at: chrono::Utc::now(),
        };

        (prekey, private_key)
    }
}

/// A signed prekey that proves ownership by the identity key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPrekey {
    /// Unique identifier for this signed prekey
    pub id: u32,
    /// Simplified public key (32 bytes for demo)
    pub public_key: Vec<u8>,
    /// Ed25519 signature over the public key
    pub signature: Vec<u8>,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl SignedPrekey {
    /// Create a new signed prekey
    pub fn new(id: u32, identity_keypair: &IdentityKeyPair) -> (Self, [u8; 32]) {
        let mut private_key = [0u8; 32];
        let mut public_key = [0u8; 32];
        
        // Generate random keys (simplified)
        rand::RngCore::fill_bytes(&mut OsRng, &mut private_key);
        rand::RngCore::fill_bytes(&mut OsRng, &mut public_key);

        // Sign the public key with the identity key
        let signature = identity_keypair.sign(&public_key);

        let signed_prekey = Self {
            id,
            public_key: public_key.to_vec(),
            signature: signature.to_vec(),
            created_at: chrono::Utc::now(),
        };

        (signed_prekey, private_key)
    }

    /// Verify the signature on this signed prekey
    pub fn verify_signature(&self, identity: &crate::crypto::Identity) -> Result<()> {
        identity.verify_signature(&self.public_key, &self.signature)
    }

    /// Check if this signed prekey should be rotated
    pub fn should_rotate(&self) -> bool {
        let age = chrono::Utc::now()
            .signed_duration_since(self.created_at)
            .num_seconds() as u64;
        age > SIGNED_PREKEY_MAX_AGE
    }
}

/// A complete prekey bundle for key agreement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrekeyBundle {
    /// The user's identity
    pub identity: crate::crypto::Identity,
    /// The current signed prekey
    pub signed_prekey: SignedPrekey,
    /// Available one-time prekeys
    pub one_time_prekeys: Vec<OneTimePrekey>,
}

impl PrekeyBundle {
    /// Create a new prekey bundle
    pub fn new(
        identity: crate::crypto::Identity,
        signed_prekey: SignedPrekey,
        one_time_prekeys: Vec<OneTimePrekey>,
    ) -> Self {
        Self {
            identity,
            signed_prekey,
            one_time_prekeys,
        }
    }

    /// Verify the integrity of this prekey bundle
    pub fn verify(&self) -> Result<()> {
        self.signed_prekey.verify_signature(&self.identity)
    }

    /// Get a one-time prekey and remove it from the bundle
    pub fn consume_one_time_prekey(&mut self) -> Option<OneTimePrekey> {
        if self.one_time_prekeys.is_empty() {
            None
        } else {
            Some(self.one_time_prekeys.remove(0))
        }
    }

    /// Check if more one-time prekeys should be generated
    pub fn needs_more_prekeys(&self) -> bool {
        self.one_time_prekeys.len() < 10
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(Into::into)
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        let bundle: Self = serde_json::from_str(json)?;
        bundle.verify()?;
        Ok(bundle)
    }
}

/// Manager for prekey generation and storage (simplified)
#[derive(Debug)]
pub struct PrekeyManager {
    /// Current signed prekey ID counter
    signed_prekey_counter: u32,
    /// Current one-time prekey ID counter
    one_time_prekey_counter: u32,
    /// Stored one-time prekey private keys
    one_time_private_keys: HashMap<u32, [u8; 32]>,
    /// Stored signed prekey private keys
    signed_private_keys: HashMap<u32, [u8; 32]>,
}

impl PrekeyManager {
    /// Create a new prekey manager
    pub fn new() -> Self {
        Self {
            signed_prekey_counter: 1,
            one_time_prekey_counter: 1,
            one_time_private_keys: HashMap::new(),
            signed_private_keys: HashMap::new(),
        }
    }

    /// Generate a new signed prekey
    pub fn generate_signed_prekey(&mut self, identity_keypair: &IdentityKeyPair) -> SignedPrekey {
        let id = self.signed_prekey_counter;
        self.signed_prekey_counter += 1;

        let (signed_prekey, private_key) = SignedPrekey::new(id, identity_keypair);
        self.signed_private_keys.insert(id, private_key);

        signed_prekey
    }

    /// Generate multiple one-time prekeys
    pub fn generate_one_time_prekeys(&mut self, count: usize) -> Vec<OneTimePrekey> {
        let mut prekeys = Vec::with_capacity(count);

        for _ in 0..count {
            let id = self.one_time_prekey_counter;
            self.one_time_prekey_counter += 1;

            let (prekey, private_key) = OneTimePrekey::new(id);
            self.one_time_private_keys.insert(id, private_key);
            prekeys.push(prekey);
        }

        prekeys
    }

    /// Generate a complete prekey bundle
    pub fn generate_prekey_bundle(
        &mut self,
        identity: crate::crypto::Identity,
        identity_keypair: &IdentityKeyPair,
        prekey_count: Option<usize>,
    ) -> PrekeyBundle {
        let signed_prekey = self.generate_signed_prekey(identity_keypair);
        let one_time_prekeys = self.generate_one_time_prekeys(
            prekey_count.unwrap_or(DEFAULT_PREKEY_COUNT)
        );

        PrekeyBundle::new(identity, signed_prekey, one_time_prekeys)
    }

    /// Get the private key for a one-time prekey
    pub fn get_one_time_private_key(&mut self, id: u32) -> Option<[u8; 32]> {
        self.one_time_private_keys.remove(&id)
    }

    /// Get the private key for a signed prekey
    pub fn get_signed_private_key(&self, id: u32) -> Option<&[u8; 32]> {
        self.signed_private_keys.get(&id)
    }
}

impl Default for PrekeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IdentityKeyPair;

    #[test]
    fn test_one_time_prekey_generation() {
        let (prekey, _private_key) = OneTimePrekey::new(1);
        assert_eq!(prekey.id, 1);
        assert_eq!(prekey.public_key.len(), 32);
    }

    #[test]
    fn test_signed_prekey_generation() {
        let identity_keypair = IdentityKeyPair::generate();
        let (signed_prekey, _private_key) = SignedPrekey::new(1, &identity_keypair);
        
        assert_eq!(signed_prekey.id, 1);
        assert_eq!(signed_prekey.public_key.len(), 32);
        assert_eq!(signed_prekey.signature.len(), 64);
    }

    #[test]
    fn test_prekey_manager() {
        let mut manager = PrekeyManager::new();
        let identity_keypair = IdentityKeyPair::generate();
        let identity = crate::crypto::Identity::new(&identity_keypair, "Test".to_string());
        
        let bundle = manager.generate_prekey_bundle(identity, &identity_keypair, Some(5));
        
        assert!(bundle.verify().is_ok());
        assert_eq!(bundle.one_time_prekeys.len(), 5);
    }
}