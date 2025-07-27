//! Identity management and Ed25519 cryptographic operations.
//!
//! This module provides functionality for creating, managing, and using
//! cryptographic identities based on Ed25519 digital signatures. Each identity
//! represents a unique user in the P2P messenger system.

use crate::utils::{CryptoError, Result};
use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Ed25519 key pair for cryptographic identity operations
#[derive(Debug, Clone)]
pub struct IdentityKeyPair {
    /// The secret signing key
    signing_key: SigningKey,
    /// The public verifying key
    verifying_key: VerifyingKey,
}

impl IdentityKeyPair {
    /// Generate a new random identity key pair
    ///
    /// # Example
    ///
    /// ```rust
    /// use secure_p2p_messenger::crypto::IdentityKeyPair;
    ///
    /// let keypair = IdentityKeyPair::generate();
    /// ```
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Create an identity key pair from a secret key
    ///
    /// # Arguments
    ///
    /// * `secret_bytes` - 32-byte secret key
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` if the secret key is invalid
    pub fn from_secret_bytes(secret_bytes: &[u8]) -> Result<Self> {
        if secret_bytes.len() != SECRET_KEY_LENGTH {
            return Err(CryptoError::InvalidKey {
                reason: format!(
                    "Invalid secret key length: expected {}, got {}",
                    SECRET_KEY_LENGTH,
                    secret_bytes.len()
                ),
            }
            .into());
        }

        let signing_key = SigningKey::from_bytes(
            secret_bytes
                .try_into()
                .map_err(|_| CryptoError::InvalidKey {
                    reason: "Failed to convert secret bytes".to_string(),
                })?,
        );
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Get the public verifying key
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Get the public key as bytes
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.verifying_key.to_bytes()
    }

    /// Get the secret key as bytes
    pub fn secret_key_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.signing_key.to_bytes()
    }

    /// Sign a message with this identity
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// The signature as bytes
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Verify a signature against this identity's public key
    ///
    /// # Arguments
    ///
    /// * `message` - The original message
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, `Err` otherwise
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() != SIGNATURE_LENGTH {
            return Err(CryptoError::SignatureVerification.into());
        }

        let sig = Signature::from_bytes(
            signature
                .try_into()
                .map_err(|_| CryptoError::SignatureVerification)?,
        );

        self.verifying_key
            .verify(message, &sig)
            .map_err(|_| CryptoError::SignatureVerification.into())
    }
}

/// Public identity information for a user
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    /// Unique identifier for this identity
    pub id: Uuid,
    /// Display name for the user
    pub display_name: String,
    /// Ed25519 public key for signature verification
    #[serde(with = "serde_bytes")]
    pub public_key: [u8; PUBLIC_KEY_LENGTH],
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Identity {
    /// Create a new identity from a key pair and display name
    ///
    /// # Arguments
    ///
    /// * `keypair` - The identity key pair
    /// * `display_name` - Human-readable name for this identity
    pub fn new(keypair: &IdentityKeyPair, display_name: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            display_name,
            public_key: keypair.public_key_bytes(),
            created_at: chrono::Utc::now(),
        }
    }

    /// Create an identity from existing components
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier
    /// * `display_name` - Human-readable name
    /// * `public_key` - Ed25519 public key bytes
    /// * `created_at` - Creation timestamp
    pub fn from_components(
        id: Uuid,
        display_name: String,
        public_key: [u8; PUBLIC_KEY_LENGTH],
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            id,
            display_name,
            public_key,
            created_at,
        }
    }

    /// Get the verifying key for this identity
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` if the public key is malformed
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| CryptoError::InvalidKey {
                reason: "Invalid public key in identity".to_string(),
            }.into())
    }

    /// Verify a signature against this identity's public key
    ///
    /// # Arguments
    ///
    /// * `message` - The original message
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, `Err` otherwise
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() != SIGNATURE_LENGTH {
            return Err(CryptoError::SignatureVerification.into());
        }

        let verifying_key = self.verifying_key()?;
        let sig = Signature::from_bytes(
            signature
                .try_into()
                .map_err(|_| CryptoError::SignatureVerification)?,
        );

        verifying_key
            .verify(message, &sig)
            .map_err(|_| CryptoError::SignatureVerification.into())
    }

    /// Get a short identifier for this identity (first 8 chars of UUID)
    pub fn short_id(&self) -> String {
        self.id.to_string()[..8].to_string()
    }

    /// Convert this identity to a JSON string for serialization
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(Into::into)
    }

    /// Create an identity from a JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(Into::into)
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.display_name, self.short_id())
    }
}

/// Complete user profile including both public identity and private key material
#[derive(Debug, Clone)]
pub struct UserProfile {
    /// The public identity information
    pub identity: Identity,
    /// The private key pair for this user
    pub keypair: IdentityKeyPair,
}

impl UserProfile {
    /// Create a new user profile with a generated key pair
    ///
    /// # Arguments
    ///
    /// * `display_name` - Human-readable name for this user
    pub fn new(display_name: String) -> Self {
        let keypair = IdentityKeyPair::generate();
        let identity = Identity::new(&keypair, display_name);

        Self { identity, keypair }
    }

    /// Create a user profile from existing key material
    ///
    /// # Arguments
    ///
    /// * `keypair` - The identity key pair
    /// * `identity` - The public identity information
    ///
    /// # Errors
    ///
    /// Returns error if the keypair and identity don't match
    pub fn from_keypair_and_identity(
        keypair: IdentityKeyPair,
        identity: Identity,
    ) -> Result<Self> {
        // Verify that the keypair matches the identity
        if keypair.public_key_bytes() != identity.public_key {
            return Err(CryptoError::InvalidKey {
                reason: "Keypair and identity public keys don't match".to_string(),
            }
            .into());
        }

        Ok(Self { identity, keypair })
    }

    /// Sign a message with this user's private key
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        self.keypair.sign(message)
    }

    /// Verify a signature against this user's public key
    ///
    /// # Arguments
    ///
    /// * `message` - The original message
    /// * `signature` - The signature to verify
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        self.identity.verify_signature(message, signature)
    }

    /// Export the public identity (safe to share)
    pub fn public_identity(&self) -> &Identity {
        &self.identity
    }

    /// Export the private key material for backup/storage
    pub fn export_private_key(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.keypair.secret_key_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = IdentityKeyPair::generate();
        let public_key = keypair.public_key_bytes();
        let secret_key = keypair.secret_key_bytes();

        assert_eq!(public_key.len(), PUBLIC_KEY_LENGTH);
        assert_eq!(secret_key.len(), SECRET_KEY_LENGTH);
    }

    #[test]
    fn test_keypair_from_secret() {
        let original = IdentityKeyPair::generate();
        let secret_bytes = original.secret_key_bytes();
        
        let restored = IdentityKeyPair::from_secret_bytes(&secret_bytes).unwrap();
        
        assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn test_signature_verification() {
        let keypair = IdentityKeyPair::generate();
        let message = b"Hello, world!";
        
        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature).is_ok());
        
        // Test with wrong message
        let wrong_message = b"Hello, universe!";
        assert!(keypair.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_identity_creation() {
        let keypair = IdentityKeyPair::generate();
        let identity = Identity::new(&keypair, "Alice".to_string());
        
        assert_eq!(identity.display_name, "Alice");
        assert_eq!(identity.public_key, keypair.public_key_bytes());
    }

    #[test]
    fn test_identity_serialization() {
        let keypair = IdentityKeyPair::generate();
        let identity = Identity::new(&keypair, "Bob".to_string());
        
        let json = identity.to_json().unwrap();
        let restored = Identity::from_json(&json).unwrap();
        
        assert_eq!(identity, restored);
    }

    #[test]
    fn test_user_profile() {
        let profile = UserProfile::new("Charlie".to_string());
        let message = b"Test message";
        
        let signature = profile.sign(message);
        assert!(profile.verify(message, &signature).is_ok());
        
        // Verify with the public identity
        assert!(profile.identity.verify_signature(message, &signature).is_ok());
    }

    #[test]
    fn test_user_profile_key_mismatch() {
        let keypair1 = IdentityKeyPair::generate();
        let keypair2 = IdentityKeyPair::generate();
        let identity = Identity::new(&keypair1, "Mismatch".to_string());
        
        let result = UserProfile::from_keypair_and_identity(keypair2, identity);
        assert!(result.is_err());
    }

    #[test]
    fn test_short_id() {
        let profile = UserProfile::new("Test".to_string());
        let short_id = profile.identity.short_id();
        
        assert_eq!(short_id.len(), 8);
        assert!(profile.identity.id.to_string().starts_with(&short_id));
    }
}