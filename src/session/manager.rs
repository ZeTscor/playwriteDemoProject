//! Session management and Double Ratchet implementation.
//!
//! This module implements the Double Ratchet algorithm for forward-secure
//! messaging with automatic key rotation and message ordering guarantees.

use crate::utils::{Result, SessionError, CryptoError};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

/// Size of symmetric encryption keys
const KEY_SIZE: usize = 32;

/// HKDF info for root key derivation
const ROOT_KEY_INFO: &[u8] = b"DoubleRatchet-RootKey";

/// HKDF info for chain key derivation  
const CHAIN_KEY_INFO: &[u8] = b"DoubleRatchet-ChainKey";

/// HKDF info for message key derivation
const MESSAGE_KEY_INFO: &[u8] = b"DoubleRatchet-MessageKey";

/// Maximum number of skipped message keys to store
const MAX_SKIP: usize = 1000;

/// A Double Ratchet session state
#[derive(Serialize, Deserialize)]
pub struct SessionState {
    /// Session identifier
    pub session_id: Uuid,
    /// Root key for key derivation
    root_key: [u8; KEY_SIZE],
    /// Current sending chain key
    sending_chain_key: Option<[u8; KEY_SIZE]>,
    /// Current receiving chain key
    receiving_chain_key: Option<[u8; KEY_SIZE]>,
    /// Our current DH key pair
    dh_keypair: Option<(StaticSecret, PublicKey)>,
    /// Remote DH public key
    remote_dh_public: Option<PublicKey>,
    /// Previous sending chain length
    previous_sending_chain_length: u32,
    /// Current sending message number
    sending_message_number: u32,
    /// Current receiving message number  
    receiving_message_number: u32,
    /// Skipped message keys for out-of-order delivery
    skipped_message_keys: HashMap<(PublicKey, u32), [u8; KEY_SIZE]>,
    /// Session creation timestamp
    created_at: chrono::DateTime<chrono::Utc>,
    /// Last activity timestamp
    last_activity: chrono::DateTime<chrono::Utc>,
}

/// Encrypted message with Double Ratchet metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetMessage {
    /// DH public key for this message
    pub dh_public_key: Option<[u8; 32]>,
    /// Previous chain length
    pub previous_chain_length: u32,
    /// Message number in current chain
    pub message_number: u32,
    /// Encrypted message content
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionState")
            .field("session_id", &self.session_id)
            .field("root_key", &"[REDACTED]")
            .field("sending_chain_key", &"[REDACTED]")
            .field("receiving_chain_key", &"[REDACTED]")
            .field("dh_keypair", &"[REDACTED]")
            .field("remote_dh_public", &self.remote_dh_public)
            .field("previous_sending_chain_length", &self.previous_sending_chain_length)
            .field("sending_message_number", &self.sending_message_number)
            .field("receiving_message_number", &self.receiving_message_number)
            .field("created_at", &self.created_at)
            .field("last_activity", &self.last_activity)
            .finish()
    }
}

impl SessionState {
    /// Initialize a new session as the initiator (Alice)
    ///
    /// # Arguments
    ///
    /// * `shared_secret` - Shared secret from X3DH key agreement
    /// * `remote_dh_public` - Bob's DH public key
    pub fn new_initiator(
        shared_secret: [u8; KEY_SIZE],
        remote_dh_public: PublicKey,
    ) -> Result<Self> {
        let session_id = Uuid::new_v4();
        let now = chrono::Utc::now();

        // Generate initial DH key pair
        let dh_private = StaticSecret::random_from_rng(OsRng);
        let dh_public = PublicKey::from(&dh_private);

        // Derive root key from shared secret
        let root_key = Self::kdf_root_key(&shared_secret, &[0u8; KEY_SIZE])?;

        // Perform initial DH ratchet step
        let (new_root_key, sending_chain_key) = Self::kdf_rk(&root_key, &dh_private, &remote_dh_public)?;

        Ok(Self {
            session_id,
            root_key: new_root_key,
            sending_chain_key: Some(sending_chain_key),
            receiving_chain_key: None,
            dh_keypair: Some((dh_private, dh_public)),
            remote_dh_public: Some(remote_dh_public),
            previous_sending_chain_length: 0,
            sending_message_number: 0,
            receiving_message_number: 0,
            skipped_message_keys: HashMap::new(),
            created_at: now,
            last_activity: now,
        })
    }

    /// Initialize a new session as the recipient (Bob)
    ///
    /// # Arguments
    ///
    /// * `shared_secret` - Shared secret from X3DH key agreement
    /// * `dh_keypair` - Bob's DH key pair
    pub fn new_recipient(
        shared_secret: [u8; KEY_SIZE],
        dh_keypair: (StaticSecret, PublicKey),
    ) -> Result<Self> {
        let session_id = Uuid::new_v4();
        let now = chrono::Utc::now();

        // Derive root key from shared secret
        let root_key = Self::kdf_root_key(&shared_secret, &[0u8; KEY_SIZE])?;

        Ok(Self {
            session_id,
            root_key,
            sending_chain_key: None,
            receiving_chain_key: None,
            dh_keypair: Some(dh_keypair),
            remote_dh_public: None,
            previous_sending_chain_length: 0,
            sending_message_number: 0,
            receiving_message_number: 0,
            skipped_message_keys: HashMap::new(),
            created_at: now,
            last_activity: now,
        })
    }

    /// Encrypt a message using the Double Ratchet
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The message to encrypt
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage> {
        // Ensure we have a sending chain key
        if self.sending_chain_key.is_none() {
            return Err(SessionError::InvalidState {
                state: "No sending chain key available".to_string(),
            }
            .into());
        }

        let dh_public_key = self.dh_keypair.as_ref().map(|(_, public)| public.to_bytes());

        // Derive message key and update chain key
        let chain_key = self.sending_chain_key.as_ref().unwrap();
        let (new_chain_key, message_key) = Self::kdf_ck(chain_key)?;
        self.sending_chain_key = Some(new_chain_key);

        // Encrypt the message
        let ciphertext = Self::encrypt_message(&message_key, plaintext)?;

        let message = RatchetMessage {
            dh_public_key,
            previous_chain_length: self.previous_sending_chain_length,
            message_number: self.sending_message_number,
            ciphertext,
        };

        self.sending_message_number += 1;
        self.last_activity = chrono::Utc::now();

        Ok(message)
    }

    /// Decrypt a message using the Double Ratchet
    ///
    /// # Arguments
    ///
    /// * `message` - The encrypted message to decrypt
    pub fn decrypt(&mut self, message: &RatchetMessage) -> Result<Vec<u8>> {
        // Check if this is a new DH ratchet step
        if let Some(remote_dh_bytes) = message.dh_public_key {
            let remote_dh_public = PublicKey::from(remote_dh_bytes);
            
            if self.remote_dh_public.as_ref() != Some(&remote_dh_public) {
                self.dh_ratchet_receive(&remote_dh_public)?;
            }
        }

        // Try to decrypt with current receiving chain
        if let Some(ref receiving_chain_key) = self.receiving_chain_key.clone() {
            // Skip messages if necessary
            self.skip_message_keys(receiving_chain_key, message.message_number)?;

            // Derive message key
            let (new_chain_key, message_key) = Self::kdf_ck(receiving_chain_key)?;
            self.receiving_chain_key = Some(new_chain_key);

            let plaintext = Self::decrypt_message(&message_key, &message.ciphertext)?;
            self.receiving_message_number = message.message_number + 1;
            self.last_activity = chrono::Utc::now();

            return Ok(plaintext);
        }

        // Try skipped message keys
        if let Some(remote_dh_public) = message.dh_public_key.map(PublicKey::from) {
            let key = (remote_dh_public, message.message_number);
            if let Some(message_key) = self.skipped_message_keys.remove(&key) {
                let plaintext = Self::decrypt_message(&message_key, &message.ciphertext)?;
                self.last_activity = chrono::Utc::now();
                return Ok(plaintext);
            }
        }

        Err(SessionError::DoubleRatchetFailure {
            reason: "Unable to decrypt message with available keys".to_string(),
        }
        .into())
    }

    /// Perform DH ratchet step when receiving a new DH public key
    fn dh_ratchet_receive(&mut self, remote_dh_public: &PublicKey) -> Result<()> {
        // Store previous chain length
        self.previous_sending_chain_length = self.sending_message_number;
        self.sending_message_number = 0;
        self.receiving_message_number = 0;

        // Update remote DH public key
        self.remote_dh_public = Some(*remote_dh_public);

        // Derive new receiving chain key
        if let Some((ref dh_private, _)) = self.dh_keypair {
            let (new_root_key, receiving_chain_key) = 
                Self::kdf_rk(&self.root_key, dh_private, remote_dh_public)?;
            self.root_key = new_root_key;
            self.receiving_chain_key = Some(receiving_chain_key);
        }

        // Generate new DH key pair for sending
        let new_dh_private = StaticSecret::random_from_rng(OsRng);
        let new_dh_public = PublicKey::from(&new_dh_private);
        
        // Derive new sending chain key
        let (new_root_key, sending_chain_key) = 
            Self::kdf_rk(&self.root_key, &new_dh_private, remote_dh_public)?;
        self.root_key = new_root_key;
        self.sending_chain_key = Some(sending_chain_key);

        self.dh_keypair = Some((new_dh_private, new_dh_public));

        Ok(())
    }

    /// Skip message keys for out-of-order delivery
    fn skip_message_keys(&mut self, chain_key: &[u8; KEY_SIZE], until: u32) -> Result<()> {
        if self.receiving_message_number + (MAX_SKIP as u32) < until {
            return Err(SessionError::MessageOrdering {
                expected: self.receiving_message_number,
                actual: until,
            }
            .into());
        }

        let mut current_chain_key = *chain_key;
        let remote_dh_public = self.remote_dh_public.ok_or_else(|| SessionError::InvalidState {
            state: "No remote DH public key".to_string(),
        })?;

        for i in self.receiving_message_number..until {
            let (new_chain_key, message_key) = Self::kdf_ck(&current_chain_key)?;
            current_chain_key = new_chain_key;
            
            self.skipped_message_keys.insert((remote_dh_public, i), message_key);
        }

        Ok(())
    }

    /// Root key derivation function
    fn kdf_root_key(shared_secret: &[u8], salt: &[u8]) -> Result<[u8; KEY_SIZE]> {
        let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);
        let mut root_key = [0u8; KEY_SIZE];
        hkdf.expand(ROOT_KEY_INFO, &mut root_key)
            .map_err(|_| CryptoError::KeyDerivation {
                reason: "Root key derivation failed".to_string(),
            })?;
        Ok(root_key)
    }

    /// Root key and chain key derivation from DH output
    fn kdf_rk(
        root_key: &[u8; KEY_SIZE],
        dh_private: &StaticSecret,
        dh_public: &PublicKey,
    ) -> Result<([u8; KEY_SIZE], [u8; KEY_SIZE])> {
        let dh_output = dh_private.diffie_hellman(dh_public);
        let hkdf = Hkdf::<Sha256>::new(Some(root_key), dh_output.as_bytes());
        
        let mut output = [0u8; KEY_SIZE * 2];
        hkdf.expand(ROOT_KEY_INFO, &mut output)
            .map_err(|_| CryptoError::KeyDerivation {
                reason: "Root and chain key derivation failed".to_string(),
            })?;

        let mut new_root_key = [0u8; KEY_SIZE];
        let mut chain_key = [0u8; KEY_SIZE];
        new_root_key.copy_from_slice(&output[..KEY_SIZE]);
        chain_key.copy_from_slice(&output[KEY_SIZE..]);

        Ok((new_root_key, chain_key))
    }

    /// Chain key derivation function
    fn kdf_ck(chain_key: &[u8; KEY_SIZE]) -> Result<([u8; KEY_SIZE], [u8; KEY_SIZE])> {
        let hkdf = Hkdf::<Sha256>::new(None, chain_key);
        
        let mut output = [0u8; KEY_SIZE * 2];
        hkdf.expand(CHAIN_KEY_INFO, &mut output)
            .map_err(|_| CryptoError::KeyDerivation {
                reason: "Chain key derivation failed".to_string(),
            })?;

        let mut new_chain_key = [0u8; KEY_SIZE];
        let mut message_key = [0u8; KEY_SIZE];
        new_chain_key.copy_from_slice(&output[..KEY_SIZE]);
        message_key.copy_from_slice(&output[KEY_SIZE..]);

        Ok((new_chain_key, message_key))
    }

    /// Encrypt message with message key
    fn encrypt_message(message_key: &[u8; KEY_SIZE], plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(message_key.into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        let mut ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::Encryption {
                reason: "Message encryption failed".to_string(),
            })?;

        let mut result = nonce.to_vec();
        result.append(&mut ciphertext);
        Ok(result)
    }

    /// Decrypt message with message key
    fn decrypt_message(message_key: &[u8; KEY_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(CryptoError::Decryption {
                reason: "Ciphertext too short".to_string(),
            }
            .into());
        }

        let cipher = ChaCha20Poly1305::new(message_key.into());
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let actual_ciphertext = &ciphertext[12..];

        cipher
            .decrypt(nonce, actual_ciphertext)
            .map_err(|_| CryptoError::Decryption {
                reason: "Message decryption failed".to_string(),
            }.into())
    }

    /// Get session statistics
    pub fn stats(&self) -> SessionStats {
        SessionStats {
            session_id: self.session_id,
            messages_sent: self.sending_message_number,
            messages_received: self.receiving_message_number,
            skipped_keys_count: self.skipped_message_keys.len(),
            created_at: self.created_at,
            last_activity: self.last_activity,
        }
    }

    /// Clean up old skipped message keys
    pub fn cleanup_skipped_keys(&mut self, max_age_seconds: u64) {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(max_age_seconds as i64);
        
        if self.last_activity < cutoff {
            self.skipped_message_keys.clear();
        }
        
        // In a more sophisticated implementation, you'd track per-key timestamps
        if self.skipped_message_keys.len() > MAX_SKIP {
            self.skipped_message_keys.clear();
        }
    }
}

/// Session statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    /// Session identifier
    pub session_id: Uuid,
    /// Number of messages sent
    pub messages_sent: u32,
    /// Number of messages received
    pub messages_received: u32,
    /// Number of skipped message keys stored
    pub skipped_keys_count: usize,
    /// Session creation time
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last activity time
    pub last_activity: chrono::DateTime<chrono::Utc>,
}

/// Session manager for handling multiple Double Ratchet sessions
#[derive(Debug)]
pub struct SessionManager {
    /// Active sessions indexed by session ID
    sessions: HashMap<Uuid, SessionState>,
    /// Maximum number of concurrent sessions
    max_sessions: usize,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            max_sessions,
        }
    }

    /// Add a new session
    pub fn add_session(&mut self, session: SessionState) -> Result<()> {
        if self.sessions.len() >= self.max_sessions {
            return Err(SessionError::InvalidState {
                state: "Maximum number of sessions reached".to_string(),
            }
            .into());
        }

        self.sessions.insert(session.session_id, session);
        Ok(())
    }

    /// Get a mutable reference to a session
    pub fn get_session_mut(&mut self, session_id: &Uuid) -> Result<&mut SessionState> {
        self.sessions.get_mut(session_id).ok_or_else(|| {
            SessionError::NotFound {
                session_id: session_id.to_string(),
            }
            .into()
        })
    }

    /// Get a session reference
    pub fn get_session(&self, session_id: &Uuid) -> Result<&SessionState> {
        self.sessions.get(session_id).ok_or_else(|| {
            SessionError::NotFound {
                session_id: session_id.to_string(),
            }
            .into()
        })
    }

    /// Remove a session
    pub fn remove_session(&mut self, session_id: &Uuid) -> Option<SessionState> {
        self.sessions.remove(session_id)
    }

    /// Get all session IDs
    pub fn session_ids(&self) -> Vec<Uuid> {
        self.sessions.keys().cloned().collect()
    }

    /// Clean up expired sessions and skipped keys
    pub fn cleanup(&mut self, max_age_seconds: u64) {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(max_age_seconds as i64);
        
        // Remove expired sessions
        self.sessions.retain(|_, session| session.last_activity >= cutoff);
        
        // Clean up skipped keys in remaining sessions
        for session in self.sessions.values_mut() {
            session.cleanup_skipped_keys(max_age_seconds);
        }
    }

    /// Get session statistics
    pub fn stats(&self) -> Vec<SessionStats> {
        self.sessions.values().map(|s| s.stats()).collect()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret;

    #[test]
    fn test_session_encryption_decryption() {
        let shared_secret = [1u8; 32];
        let bob_private = StaticSecret::random_from_rng(OsRng);
        let bob_public = PublicKey::from(&bob_private);

        let mut alice_session = SessionState::new_initiator(shared_secret, bob_public).unwrap();
        let mut bob_session = SessionState::new_recipient(shared_secret, (bob_private, bob_public)).unwrap();

        let message = b"Hello, Bob!";
        let encrypted = alice_session.encrypt(message).unwrap();
        let decrypted = bob_session.decrypt(&encrypted).unwrap();

        assert_eq!(message.to_vec(), decrypted);
    }

    #[test]
    fn test_session_manager() {
        let mut manager = SessionManager::new(10);
        let shared_secret = [1u8; 32];
        let bob_private = StaticSecret::random_from_rng(OsRng);
        let bob_public = PublicKey::from(&bob_private);

        let session = SessionState::new_initiator(shared_secret, bob_public).unwrap();
        let session_id = session.session_id;

        manager.add_session(session).unwrap();
        assert!(manager.get_session(&session_id).is_ok());

        let removed = manager.remove_session(&session_id);
        assert!(removed.is_some());
        assert!(manager.get_session(&session_id).is_err());
    }

    #[test]
    fn test_multiple_messages() {
        let shared_secret = [1u8; 32];
        let bob_private = StaticSecret::random_from_rng(OsRng);
        let bob_public = PublicKey::from(&bob_private);

        let mut alice_session = SessionState::new_initiator(shared_secret, bob_public).unwrap();
        let mut bob_session = SessionState::new_recipient(shared_secret, (bob_private, bob_public)).unwrap();

        let messages = vec!["First message", "Second message", "Third message"];
        let mut encrypted_messages = Vec::new();

        // Alice encrypts messages
        for msg in &messages {
            encrypted_messages.push(alice_session.encrypt(msg.as_bytes()).unwrap());
        }

        // Bob decrypts messages
        for (i, encrypted) in encrypted_messages.iter().enumerate() {
            let decrypted = bob_session.decrypt(encrypted).unwrap();
            assert_eq!(messages[i].as_bytes().to_vec(), decrypted);
        }
    }
}