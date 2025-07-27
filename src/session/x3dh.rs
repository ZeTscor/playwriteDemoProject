//! X3DH (Extended Triple Diffie-Hellman) key agreement protocol implementation.
//!
//! This module implements the X3DH key agreement protocol as specified in the Signal
//! protocol documentation. X3DH allows two parties that have never communicated before
//! to establish a shared secret key through an asynchronous key agreement protocol.

use crate::crypto::{Identity, IdentityKeyPair, PrekeyBundle};
use crate::utils::{CryptoError, Result, SessionError};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Size of the derived shared secret
const SHARED_SECRET_SIZE: usize = 32;

/// X3DH protocol information string for HKDF
const X3DH_INFO: &[u8] = b"X3DH";

/// Initial X3DH message from initiator to recipient
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X3DHInitialMessage {
    /// Initiator's identity key
    pub identity_key: [u8; 32],
    /// Initiator's ephemeral key
    pub ephemeral_key: [u8; 32],
    /// ID of the used one-time prekey (if any)
    pub used_one_time_prekey_id: Option<u32>,
    /// Encrypted initial message payload
    pub encrypted_payload: Vec<u8>,
}

/// X3DH key agreement initiator
pub struct X3DHInitiator {
    /// Initiator's identity key pair
    identity_keypair: IdentityKeyPair,
    /// Initiator's ephemeral key pair
    ephemeral_keypair: (StaticSecret, PublicKey),
}

impl X3DHInitiator {
    /// Create a new X3DH initiator
    ///
    /// # Arguments
    ///
    /// * `identity_keypair` - The initiator's identity key pair
    pub fn new(identity_keypair: IdentityKeyPair) -> Self {
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        Self {
            identity_keypair,
            ephemeral_keypair: (ephemeral_secret, ephemeral_public),
        }
    }

    /// Perform X3DH key agreement and create initial message
    ///
    /// # Arguments
    ///
    /// * `recipient_bundle` - The recipient's prekey bundle
    /// * `initial_payload` - Initial message to encrypt
    ///
    /// # Returns
    ///
    /// Tuple of (X3DH initial message, shared secret)
    pub fn initiate(
        &self,
        mut recipient_bundle: PrekeyBundle,
        initial_payload: &[u8],
    ) -> Result<(X3DHInitialMessage, [u8; SHARED_SECRET_SIZE])> {
        // Verify the recipient's prekey bundle
        recipient_bundle.verify()?;

        // Convert identity keys to X25519 keys
        let initiator_identity_x25519 = self.ed25519_to_x25519_private(&self.identity_keypair)?;
        let recipient_identity_x25519 = self.ed25519_to_x25519_public(&recipient_bundle.identity)?;
        let recipient_signed_prekey = recipient_bundle.signed_prekey.public_key();

        // Get one-time prekey if available
        let one_time_prekey = recipient_bundle.consume_one_time_prekey();
        let used_one_time_prekey_id = one_time_prekey.as_ref().map(|pk| pk.id);

        // Perform the X3DH calculation: DH1, DH2, DH3, DH4 (if one-time prekey exists)
        // DH1 = DH(IK_A, SPK_B)
        let dh1 = initiator_identity_x25519.diffie_hellman(&recipient_signed_prekey);
        
        // DH2 = DH(EK_A, IK_B)
        let dh2 = self
            .ephemeral_keypair
            .0
            .diffie_hellman(&recipient_identity_x25519);
        
        // DH3 = DH(EK_A, SPK_B)
        let dh3 = self
            .ephemeral_keypair
            .0
            .diffie_hellman(&recipient_signed_prekey);

        // Collect DH outputs as byte slices
        let mut shared_secrets: Vec<&[u8]> = vec![
            dh1.as_bytes(),
            dh2.as_bytes(),
            dh3.as_bytes(),
        ];

        // DH4 = DH(EK_A, OPK_B) - only if one-time prekey exists
        let dh4_option = if let Some(ref otpk) = one_time_prekey {
            let dh4 = self
                .ephemeral_keypair
                .0
                .diffie_hellman(&otpk.public_key());
            Some(dh4)
        } else {
            None
        };

        if let Some(ref dh4) = dh4_option {
            shared_secrets.push(dh4.as_bytes());
        }

        // Derive the shared secret using HKDF
        let shared_secret = self.derive_shared_secret(&shared_secrets)?;

        // Encrypt the initial payload
        let encrypted_payload = self.encrypt_initial_payload(&shared_secret, initial_payload)?;

        let initial_message = X3DHInitialMessage {
            identity_key: PublicKey::from(&initiator_identity_x25519).to_bytes(),
            ephemeral_key: self.ephemeral_keypair.1.to_bytes(),
            used_one_time_prekey_id,
            encrypted_payload,
        };

        Ok((initial_message, shared_secret))
    }

    /// Derive shared secret from DH outputs using HKDF
    fn derive_shared_secret(&self, dh_outputs: &[&[u8]]) -> Result<[u8; SHARED_SECRET_SIZE]> {
        // Concatenate all DH outputs
        let input_key_material: Vec<u8> = dh_outputs.iter().flat_map(|&dh| dh.iter()).cloned().collect();

        // Use HKDF to derive the shared secret
        let hkdf = Hkdf::<Sha256>::new(None, &input_key_material);
        let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
        hkdf.expand(X3DH_INFO, &mut shared_secret)
            .map_err(|_| CryptoError::KeyDerivation {
                reason: "HKDF expansion failed".to_string(),
            })?;

        Ok(shared_secret)
    }

    /// Encrypt initial payload using derived shared secret
    fn encrypt_initial_payload(
        &self,
        shared_secret: &[u8; SHARED_SECRET_SIZE],
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        use chacha20poly1305::{
            aead::{Aead, AeadCore, KeyInit},
            ChaCha20Poly1305,
        };

        let cipher = ChaCha20Poly1305::new(shared_secret.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        let mut ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|_| CryptoError::Encryption {
                reason: "Failed to encrypt initial payload".to_string(),
            })?;

        // Prepend nonce to ciphertext
        let mut result = nonce.to_vec();
        result.append(&mut ciphertext);
        Ok(result)
    }

    /// Convert Ed25519 private key to X25519 private key
    fn ed25519_to_x25519_private(&self, identity_keypair: &IdentityKeyPair) -> Result<StaticSecret> {
        // In a real implementation, you'd need proper key conversion
        // For now, we'll derive from the Ed25519 private key bytes
        let ed25519_private = identity_keypair.secret_key_bytes();
        
        // Use HKDF to derive X25519 key from Ed25519 key
        let hkdf = Hkdf::<Sha256>::new(None, &ed25519_private);
        let mut x25519_key = [0u8; 32];
        hkdf.expand(b"Ed25519_to_X25519_private", &mut x25519_key)
            .map_err(|_| CryptoError::KeyDerivation {
                reason: "Failed to convert Ed25519 to X25519 private key".to_string(),
            })?;

        Ok(StaticSecret::from(x25519_key))
    }

    /// Convert Ed25519 public key to X25519 public key
    fn ed25519_to_x25519_public(&self, identity: &Identity) -> Result<PublicKey> {
        // In a real implementation, you'd need proper key conversion
        // For now, we'll derive from the Ed25519 public key bytes
        let ed25519_public = identity.public_key;
        
        // Use HKDF to derive X25519 key from Ed25519 key
        let hkdf = Hkdf::<Sha256>::new(None, &ed25519_public);
        let mut x25519_key = [0u8; 32];
        hkdf.expand(b"Ed25519_to_X25519_public", &mut x25519_key)
            .map_err(|_| CryptoError::KeyDerivation {
                reason: "Failed to convert Ed25519 to X25519 public key".to_string(),
            })?;

        Ok(PublicKey::from(x25519_key))
    }
}

/// X3DH key agreement recipient
pub struct X3DHRecipient {
    /// Recipient's identity key pair
    identity_keypair: IdentityKeyPair,
    /// Recipient's signed prekey private key
    signed_prekey_private: StaticSecret,
    /// Recipient's one-time prekey private key (if used)
    one_time_prekey_private: Option<StaticSecret>,
}

impl X3DHRecipient {
    /// Create a new X3DH recipient
    ///
    /// # Arguments
    ///
    /// * `identity_keypair` - The recipient's identity key pair
    /// * `signed_prekey_private` - Private key for the signed prekey
    /// * `one_time_prekey_private` - Private key for one-time prekey (if used)
    pub fn new(
        identity_keypair: IdentityKeyPair,
        signed_prekey_private: StaticSecret,
        one_time_prekey_private: Option<StaticSecret>,
    ) -> Self {
        Self {
            identity_keypair,
            signed_prekey_private,
            one_time_prekey_private,
        }
    }

    /// Process X3DH initial message and derive shared secret
    ///
    /// # Arguments
    ///
    /// * `initial_message` - The X3DH initial message from initiator
    ///
    /// # Returns
    ///
    /// Tuple of (decrypted payload, shared secret)
    pub fn receive(
        &self,
        initial_message: &X3DHInitialMessage,
    ) -> Result<(Vec<u8>, [u8; SHARED_SECRET_SIZE])> {
        // Convert keys
        let recipient_identity_x25519 = self.ed25519_to_x25519_private(&self.identity_keypair)?;
        let initiator_identity_x25519 = PublicKey::from(initial_message.identity_key);
        let initiator_ephemeral = PublicKey::from(initial_message.ephemeral_key);

        // Perform the X3DH calculation (reverse of initiator)
        // DH1 = DH(SPK_B, IK_A)
        let dh1 = self.signed_prekey_private.diffie_hellman(&initiator_identity_x25519);
        
        // DH2 = DH(IK_B, EK_A)
        let dh2 = recipient_identity_x25519.diffie_hellman(&initiator_ephemeral);
        
        // DH3 = DH(SPK_B, EK_A)
        let dh3 = self.signed_prekey_private.diffie_hellman(&initiator_ephemeral);

        // Collect DH outputs as byte slices
        let mut shared_secrets: Vec<&[u8]> = vec![
            dh1.as_bytes(),
            dh2.as_bytes(),
            dh3.as_bytes(),
        ];

        // DH4 = DH(OPK_B, EK_A) - only if one-time prekey was used
        let dh4_option = if initial_message.used_one_time_prekey_id.is_some() {
            if let Some(ref otpk_private) = self.one_time_prekey_private {
                Some(otpk_private.diffie_hellman(&initiator_ephemeral))
            } else {
                return Err(SessionError::X3DHFailure {
                    reason: "One-time prekey was used but private key not available".to_string(),
                }
                .into());
            }
        } else {
            None
        };

        if let Some(ref dh4) = dh4_option {
            shared_secrets.push(dh4.as_bytes());
        }

        // Derive the shared secret
        let shared_secret = self.derive_shared_secret(&shared_secrets)?;

        // Decrypt the initial payload
        let decrypted_payload = self.decrypt_initial_payload(
            &shared_secret,
            &initial_message.encrypted_payload,
        )?;

        Ok((decrypted_payload, shared_secret))
    }

    /// Derive shared secret from DH outputs using HKDF
    fn derive_shared_secret(&self, dh_outputs: &[&[u8]]) -> Result<[u8; SHARED_SECRET_SIZE]> {
        let input_key_material: Vec<u8> = dh_outputs.iter().flat_map(|&dh| dh.iter()).cloned().collect();

        let hkdf = Hkdf::<Sha256>::new(None, &input_key_material);
        let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
        hkdf.expand(X3DH_INFO, &mut shared_secret)
            .map_err(|_| CryptoError::KeyDerivation {
                reason: "HKDF expansion failed".to_string(),
            })?;

        Ok(shared_secret)
    }

    /// Decrypt initial payload using derived shared secret
    fn decrypt_initial_payload(
        &self,
        shared_secret: &[u8; SHARED_SECRET_SIZE],
        encrypted_payload: &[u8],
    ) -> Result<Vec<u8>> {
        use chacha20poly1305::{
            aead::{Aead, KeyInit},
            ChaCha20Poly1305, Nonce,
        };

        if encrypted_payload.len() < 12 {
            return Err(CryptoError::Decryption {
                reason: "Encrypted payload too short".to_string(),
            }
            .into());
        }

        let cipher = ChaCha20Poly1305::new(shared_secret.into());
        
        // Extract nonce and ciphertext
        let nonce = Nonce::from_slice(&encrypted_payload[..12]);
        let ciphertext = &encrypted_payload[12..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::Decryption {
                reason: "Failed to decrypt initial payload".to_string(),
            }.into())
    }

    /// Convert Ed25519 private key to X25519 private key
    fn ed25519_to_x25519_private(&self, identity_keypair: &IdentityKeyPair) -> Result<StaticSecret> {
        let ed25519_private = identity_keypair.secret_key_bytes();
        
        let hkdf = Hkdf::<Sha256>::new(None, &ed25519_private);
        let mut x25519_key = [0u8; 32];
        hkdf.expand(b"Ed25519_to_X25519_private", &mut x25519_key)
            .map_err(|_| CryptoError::KeyDerivation {
                reason: "Failed to convert Ed25519 to X25519 private key".to_string(),
            })?;

        Ok(StaticSecret::from(x25519_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{IdentityKeyPair, PrekeyManager, UserProfile};

    #[test]
    fn test_x3dh_key_agreement() {
        // Create two users
        let alice_profile = UserProfile::new("Alice".to_string());
        let bob_profile = UserProfile::new("Bob".to_string());

        // Bob generates prekey bundle
        let mut bob_prekey_manager = PrekeyManager::new();
        let bob_bundle = bob_prekey_manager.generate_prekey_bundle(
            bob_profile.identity.clone(),
            &bob_profile.keypair,
            Some(1),
        );

        // Alice initiates X3DH
        let alice_initiator = X3DHInitiator::new(alice_profile.keypair.clone());
        let initial_payload = b"Hello Bob!";
        
        let (initial_message, alice_shared_secret) = alice_initiator
            .initiate(bob_bundle.clone(), initial_payload)
            .unwrap();

        // Bob receives X3DH
        let bob_signed_prekey_private = bob_prekey_manager
            .get_signed_private_key(bob_bundle.signed_prekey.id)
            .unwrap()
            .clone();
        
        let bob_one_time_prekey_private = initial_message.used_one_time_prekey_id
            .and_then(|id| bob_prekey_manager.get_one_time_private_key(id));

        let bob_recipient = X3DHRecipient::new(
            bob_profile.keypair,
            bob_signed_prekey_private,
            bob_one_time_prekey_private,
        );

        let (decrypted_payload, bob_shared_secret) = bob_recipient
            .receive(&initial_message)
            .unwrap();

        // Verify shared secrets match
        assert_eq!(alice_shared_secret, bob_shared_secret);
        assert_eq!(decrypted_payload, initial_payload);
    }

    #[test]
    fn test_x3dh_without_one_time_prekey() {
        let alice_profile = UserProfile::new("Alice".to_string());
        let bob_profile = UserProfile::new("Bob".to_string());

        // Bob generates prekey bundle without one-time prekeys
        let mut bob_prekey_manager = PrekeyManager::new();
        let mut bob_bundle = bob_prekey_manager.generate_prekey_bundle(
            bob_profile.identity.clone(),
            &bob_profile.keypair,
            Some(0), // No one-time prekeys
        );

        // Ensure no one-time prekeys
        bob_bundle.one_time_prekeys.clear();

        let alice_initiator = X3DHInitiator::new(alice_profile.keypair.clone());
        let initial_payload = b"Hello Bob without OTK!";
        
        let (initial_message, alice_shared_secret) = alice_initiator
            .initiate(bob_bundle.clone(), initial_payload)
            .unwrap();

        // Verify no one-time prekey was used
        assert!(initial_message.used_one_time_prekey_id.is_none());

        // Bob receives X3DH
        let bob_signed_prekey_private = bob_prekey_manager
            .get_signed_private_key(bob_bundle.signed_prekey.id)
            .unwrap()
            .clone();

        let bob_recipient = X3DHRecipient::new(
            bob_profile.keypair,
            bob_signed_prekey_private,
            None, // No one-time prekey
        );

        let (decrypted_payload, bob_shared_secret) = bob_recipient
            .receive(&initial_message)
            .unwrap();

        assert_eq!(alice_shared_secret, bob_shared_secret);
        assert_eq!(decrypted_payload, initial_payload);
    }

    #[test]
    fn test_x3dh_invalid_bundle() {
        let alice_profile = UserProfile::new("Alice".to_string());
        let bob_profile = UserProfile::new("Bob".to_string());
        let charlie_profile = UserProfile::new("Charlie".to_string());

        // Create bundle with mismatched signature
        let mut bob_prekey_manager = PrekeyManager::new();
        let signed_prekey = bob_prekey_manager.generate_signed_prekey(&charlie_profile.keypair);
        
        let bundle = PrekeyBundle::new(
            bob_profile.identity.clone(),
            signed_prekey,
            vec![],
        );

        let alice_initiator = X3DHInitiator::new(alice_profile.keypair);
        let result = alice_initiator.initiate(bundle, b"test");
        
        assert!(result.is_err());
    }
}