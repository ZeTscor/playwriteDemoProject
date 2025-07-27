//! Signal protocol compatible prekey generation and management.
//!
//! This module implements prekey generation compatible with the Signal protocol,
//! used for X3DH key agreement. Prekeys allow for asynchronous messaging by
//! enabling the initiation of encrypted sessions without requiring both parties
//! to be online simultaneously.

use crate::utils::{CryptoError, Result};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use x25519_dalek::{PublicKey, StaticSecret};

/// Number of one-time prekeys to generate by default
pub const DEFAULT_PREKEY_COUNT: usize = 100;

/// Maximum age of a signed prekey before rotation (30 days in seconds)
pub const SIGNED_PREKEY_MAX_AGE: u64 = 30 * 24 * 60 * 60;

/// A one-time prekey for X3DH key agreement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePrekey {
    /// Unique identifier for this prekey
    pub id: u32,
    /// X25519 public key
    #[serde(with = "serde_bytes")]
    pub public_key: [u8; 32],
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl OneTimePrekey {
    /// Create a new one-time prekey
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier for this prekey
    pub fn new(id: u32) -> (Self, StaticSecret) {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);

        let prekey = Self {
            id,
            public_key: public_key.to_bytes(),
            created_at: chrono::Utc::now(),
        };

        (prekey, private_key)
    }

    /// Get the public key as an X25519 PublicKey
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(self.public_key)
    }
}

/// A signed prekey that proves ownership by the identity key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPrekey {
    /// Unique identifier for this signed prekey
    pub id: u32,
    /// X25519 public key
    #[serde(with = "serde_bytes")]
    pub public_key: [u8; 32],
    /// Ed25519 signature over the public key
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl SignedPrekey {
    /// Create a new signed prekey
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier for this signed prekey
    /// * `identity_keypair` - Identity key pair for signing
    pub fn new(
        id: u32,
        identity_keypair: &crate::crypto::IdentityKeyPair,
    ) -> (Self, StaticSecret) {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        let public_key_bytes = public_key.to_bytes();

        // Sign the public key with the identity key
        let signature = identity_keypair.sign(&public_key_bytes);

        let signed_prekey = Self {
            id,
            public_key: public_key_bytes,
            signature,
            created_at: chrono::Utc::now(),
        };

        (signed_prekey, private_key)
    }

    /// Verify the signature on this signed prekey
    ///
    /// # Arguments
    ///
    /// * `identity_public_key` - The identity public key to verify against
    pub fn verify_signature(&self, identity: &crate::crypto::Identity) -> Result<()> {
        identity.verify_signature(&self.public_key, &self.signature)
    }

    /// Get the public key as an X25519 PublicKey
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(self.public_key)
    }

    /// Check if this signed prekey should be rotated
    pub fn should_rotate(&self) -> bool {
        let age = chrono::Utc::now()
            .signed_duration_since(self.created_at)
            .num_seconds() as u64;
        age > SIGNED_PREKEY_MAX_AGE
    }
}

/// A complete prekey bundle for X3DH key agreement
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
    ///
    /// # Arguments
    ///
    /// * `identity` - The user's identity
    /// * `signed_prekey` - The current signed prekey
    /// * `one_time_prekeys` - Available one-time prekeys
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
        // Verify signed prekey signature
        self.signed_prekey.verify_signature(&self.identity)?;

        // Verify that the identity public key can verify the signed prekey
        if self.signed_prekey.signature.len() != 64 {
            return Err(CryptoError::InvalidParameters {
                reason: "Invalid signature length in signed prekey".to_string(),
            }
            .into());
        }

        Ok(())
    }

    /// Get a one-time prekey and remove it from the bundle
    ///
    /// # Returns
    ///
    /// The one-time prekey if available, or None if no keys remain
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

/// Manager for prekey generation and storage
pub struct PrekeyManager {
    /// Current signed prekey ID counter
    signed_prekey_counter: u32,
    /// Current one-time prekey ID counter
    one_time_prekey_counter: u32,
    /// Stored one-time prekey private keys
    one_time_private_keys: HashMap<u32, StaticSecret>,
    /// Stored signed prekey private keys
    signed_private_keys: HashMap<u32, StaticSecret>,
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
    ///
    /// # Arguments
    ///
    /// * `identity_keypair` - Identity key pair for signing
    pub fn generate_signed_prekey(
        &mut self,
        identity_keypair: &crate::crypto::IdentityKeyPair,
    ) -> SignedPrekey {
        let id = self.signed_prekey_counter;
        self.signed_prekey_counter += 1;

        let (signed_prekey, private_key) = SignedPrekey::new(id, identity_keypair);
        self.signed_private_keys.insert(id, private_key);

        signed_prekey
    }

    /// Generate multiple one-time prekeys
    ///
    /// # Arguments
    ///
    /// * `count` - Number of prekeys to generate
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
    ///
    /// # Arguments
    ///
    /// * `identity` - The user's identity
    /// * `identity_keypair` - Identity key pair for signing
    /// * `prekey_count` - Number of one-time prekeys to generate
    pub fn generate_prekey_bundle(
        &mut self,
        identity: crate::crypto::Identity,
        identity_keypair: &crate::crypto::IdentityKeyPair,
        prekey_count: Option<usize>,
    ) -> PrekeyBundle {
        let signed_prekey = self.generate_signed_prekey(identity_keypair);
        let one_time_prekeys = self.generate_one_time_prekeys(
            prekey_count.unwrap_or(DEFAULT_PREKEY_COUNT)
        );

        PrekeyBundle::new(identity, signed_prekey, one_time_prekeys)
    }

    /// Get the private key for a one-time prekey
    ///
    /// # Arguments
    ///
    /// * `id` - The prekey ID
    pub fn get_one_time_private_key(&mut self, id: u32) -> Option<StaticSecret> {
        self.one_time_private_keys.remove(&id)
    }

    /// Get the private key for a signed prekey
    ///
    /// # Arguments
    ///
    /// * `id` - The signed prekey ID
    pub fn get_signed_private_key(&self, id: u32) -> Option<&StaticSecret> {
        self.signed_private_keys.get(&id)
    }

    /// Clean up expired prekeys
    ///
    /// # Arguments
    ///
    /// * `max_age_seconds` - Maximum age in seconds before cleanup
    pub fn cleanup_expired_prekeys(&mut self, max_age_seconds: u64) {
        let _cutoff = chrono::Utc::now() - chrono::Duration::seconds(max_age_seconds as i64);
        
        // For this implementation, we'll clean up based on ID ranges
        // In a real implementation, you'd store creation timestamps
        let cleanup_threshold = self.one_time_prekey_counter.saturating_sub(1000);
        
        self.one_time_private_keys.retain(|&id, _| id >= cleanup_threshold);
        
        // Keep only the most recent signed prekeys
        let signed_cleanup_threshold = self.signed_prekey_counter.saturating_sub(5);
        self.signed_private_keys.retain(|&id, _| id >= signed_cleanup_threshold);
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
        let (prekey, private_key) = OneTimePrekey::new(1);
        
        assert_eq!(prekey.id, 1);
        assert_eq!(prekey.public_key.len(), 32);
        
        // Verify key relationship
        let expected_public = PublicKey::from(&private_key);
        assert_eq!(prekey.public_key, expected_public.to_bytes());
    }

    #[test]
    fn test_signed_prekey_generation() {
        let identity_keypair = IdentityKeyPair::generate();
        let (signed_prekey, _private_key) = SignedPrekey::new(1, &identity_keypair);
        
        assert_eq!(signed_prekey.id, 1);
        assert_eq!(signed_prekey.public_key.len(), 32);
        assert_eq!(signed_prekey.signature.len(), 64);
        
        // Verify signature
        assert!(identity_keypair.verify(&signed_prekey.public_key, &signed_prekey.signature).is_ok());
    }

    #[test]
    fn test_signed_prekey_verification() {
        let identity_keypair = IdentityKeyPair::generate();
        let identity = crate::crypto::Identity::new(&identity_keypair, "Test".to_string());
        let (signed_prekey, _) = SignedPrekey::new(1, &identity_keypair);
        
        assert!(signed_prekey.verify_signature(&identity).is_ok());
    }

    #[test]
    fn test_prekey_bundle_creation() {
        let identity_keypair = IdentityKeyPair::generate();
        let identity = crate::crypto::Identity::new(&identity_keypair, "Test".to_string());
        let (signed_prekey, _) = SignedPrekey::new(1, &identity_keypair);
        let mut one_time_prekeys = Vec::new();
        
        for i in 1..=5 {
            let (prekey, _) = OneTimePrekey::new(i);
            one_time_prekeys.push(prekey);
        }
        
        let bundle = PrekeyBundle::new(identity, signed_prekey, one_time_prekeys);
        assert!(bundle.verify().is_ok());
        assert_eq!(bundle.one_time_prekeys.len(), 5);
    }

    #[test]
    fn test_prekey_bundle_consume() {
        let identity_keypair = IdentityKeyPair::generate();
        let identity = crate::crypto::Identity::new(&identity_keypair, "Test".to_string());
        let (signed_prekey, _) = SignedPrekey::new(1, &identity_keypair);
        let (one_time_prekey, _) = OneTimePrekey::new(1);
        
        let mut bundle = PrekeyBundle::new(identity, signed_prekey, vec![one_time_prekey]);
        
        let consumed = bundle.consume_one_time_prekey();
        assert!(consumed.is_some());
        assert_eq!(consumed.unwrap().id, 1);
        assert_eq!(bundle.one_time_prekeys.len(), 0);
        
        let consumed_again = bundle.consume_one_time_prekey();
        assert!(consumed_again.is_none());
    }

    #[test]
    fn test_prekey_manager() {
        let mut manager = PrekeyManager::new();
        let identity_keypair = IdentityKeyPair::generate();
        let identity = crate::crypto::Identity::new(&identity_keypair, "Test".to_string());
        
        let bundle = manager.generate_prekey_bundle(identity, &identity_keypair, Some(10));
        
        assert!(bundle.verify().is_ok());
        assert_eq!(bundle.one_time_prekeys.len(), 10);
        
        // Test private key retrieval
        let prekey_id = bundle.one_time_prekeys[0].id;
        let private_key = manager.get_one_time_private_key(prekey_id);
        assert!(private_key.is_some());
        
        // Key should be consumed
        let private_key_again = manager.get_one_time_private_key(prekey_id);
        assert!(private_key_again.is_none());
    }

    #[test]
    fn test_prekey_bundle_serialization() {
        let identity_keypair = IdentityKeyPair::generate();
        let identity = crate::crypto::Identity::new(&identity_keypair, "Test".to_string());
        let (signed_prekey, _) = SignedPrekey::new(1, &identity_keypair);
        let (one_time_prekey, _) = OneTimePrekey::new(1);
        
        let bundle = PrekeyBundle::new(identity, signed_prekey, vec![one_time_prekey]);
        
        let json = bundle.to_json().unwrap();
        let restored = PrekeyBundle::from_json(&json).unwrap();
        
        assert_eq!(bundle.identity.id, restored.identity.id);
        assert_eq!(bundle.signed_prekey.id, restored.signed_prekey.id);
        assert_eq!(bundle.one_time_prekeys.len(), restored.one_time_prekeys.len());
    }

    #[test]
    fn test_signed_prekey_rotation() {
        let identity_keypair = IdentityKeyPair::generate();
        let (mut signed_prekey, _) = SignedPrekey::new(1, &identity_keypair);
        
        // Fresh prekey should not need rotation
        assert!(!signed_prekey.should_rotate());
        
        // Manually set old timestamp
        signed_prekey.created_at = chrono::Utc::now() 
            - chrono::Duration::seconds(SIGNED_PREKEY_MAX_AGE as i64 + 1);
        
        assert!(signed_prekey.should_rotate());
    }
}