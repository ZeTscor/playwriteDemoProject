//! Message protocol definitions and serialization.
//!
//! This module defines the wire protocol for P2P messaging, including message
//! types, serialization format, and acknowledgment handling.

use crate::crypto::Identity;
use crate::session::RatchetMessage;
use crate::utils::{ProtocolError, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Protocol version for compatibility checking
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum message payload size (1MB)
pub const MAX_PAYLOAD_SIZE: usize = 1024 * 1024;

/// P2P message envelope containing all message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PMessage {
    /// Protocol version
    pub version: u32,
    /// Unique message identifier
    pub message_id: Uuid,
    /// Sender's identity (for routing)
    pub sender_id: Uuid,
    /// Recipient's identity (for routing)
    pub recipient_id: Uuid,
    /// Message timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Message type and payload
    pub message_type: MessageType,
    /// Digital signature over the entire message
    pub signature: Option<Vec<u8>>,
}

/// Different types of messages in the protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum MessageType {
    /// Encrypted chat message
    Chat {
        /// Session ID for this conversation
        session_id: Uuid,
        /// Double Ratchet encrypted message
        ratchet_message: RatchetMessage,
    },
    /// Key exchange initiation (X3DH)
    KeyExchange {
        /// X3DH initial message
        x3dh_message: crate::session::X3DHInitialMessage,
    },
    /// Prekey bundle request
    PrekeyRequest {
        /// Requested user's identity
        user_id: Uuid,
    },
    /// Prekey bundle response
    PrekeyResponse {
        /// The prekey bundle
        bundle: crate::crypto::PrekeyBundle,
    },
    /// Message acknowledgment
    Acknowledgment {
        /// ID of the acknowledged message
        ack_message_id: Uuid,
        /// Acknowledgment status
        status: AckStatus,
    },
    /// Presence/status update
    Presence {
        /// User's current status
        status: PresenceStatus,
        /// Optional status message
        message: Option<String>,
    },
    /// Typing indicator
    Typing {
        /// Session ID
        session_id: Uuid,
        /// Whether user is typing
        is_typing: bool,
    },
    /// File transfer initiation
    FileTransfer {
        /// Session ID
        session_id: Uuid,
        /// File metadata
        file_info: FileInfo,
        /// Encrypted file data
        encrypted_data: Vec<u8>,
    },
    /// Ping for connectivity testing
    Ping {
        /// Ping timestamp
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    /// Pong response to ping
    Pong {
        /// Original ping timestamp
        ping_timestamp: chrono::DateTime<chrono::Utc>,
        /// Pong timestamp
        pong_timestamp: chrono::DateTime<chrono::Utc>,
    },
}

/// Acknowledgment status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AckStatus {
    /// Message received successfully
    Delivered,
    /// Message read by recipient
    Read,
    /// Message processing failed
    Failed { reason: String },
}

/// User presence status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PresenceStatus {
    /// User is online and available
    Online,
    /// User is away
    Away,
    /// User is busy/do not disturb
    Busy,
    /// User is offline
    Offline,
}

/// File transfer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    /// Original filename
    pub filename: String,
    /// MIME type
    pub mime_type: String,
    /// File size in bytes
    pub size: u64,
    /// SHA-256 hash of file content
    pub hash: [u8; 32],
}

impl P2PMessage {
    /// Create a new chat message
    pub fn new_chat(
        sender_id: Uuid,
        recipient_id: Uuid,
        session_id: Uuid,
        ratchet_message: RatchetMessage,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_id: Uuid::new_v4(),
            sender_id,
            recipient_id,
            timestamp: chrono::Utc::now(),
            message_type: MessageType::Chat {
                session_id,
                ratchet_message,
            },
            signature: None,
        }
    }

    /// Create a new key exchange message
    pub fn new_key_exchange(
        sender_id: Uuid,
        recipient_id: Uuid,
        x3dh_message: crate::session::X3DHInitialMessage,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_id: Uuid::new_v4(),
            sender_id,
            recipient_id,
            timestamp: chrono::Utc::now(),
            message_type: MessageType::KeyExchange { x3dh_message },
            signature: None,
        }
    }

    /// Create a prekey request
    pub fn new_prekey_request(sender_id: Uuid, user_id: Uuid) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_id: Uuid::new_v4(),
            sender_id,
            recipient_id: user_id,
            timestamp: chrono::Utc::now(),
            message_type: MessageType::PrekeyRequest { user_id },
            signature: None,
        }
    }

    /// Create a prekey response
    pub fn new_prekey_response(
        sender_id: Uuid,
        recipient_id: Uuid,
        bundle: crate::crypto::PrekeyBundle,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_id: Uuid::new_v4(),
            sender_id,
            recipient_id,
            timestamp: chrono::Utc::now(),
            message_type: MessageType::PrekeyResponse { bundle },
            signature: None,
        }
    }

    /// Create an acknowledgment message
    pub fn new_acknowledgment(
        sender_id: Uuid,
        recipient_id: Uuid,
        ack_message_id: Uuid,
        status: AckStatus,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_id: Uuid::new_v4(),
            sender_id,
            recipient_id,
            timestamp: chrono::Utc::now(),
            message_type: MessageType::Acknowledgment {
                ack_message_id,
                status,
            },
            signature: None,
        }
    }

    /// Create a ping message
    pub fn new_ping(sender_id: Uuid, recipient_id: Uuid) -> Self {
        let timestamp = chrono::Utc::now();
        Self {
            version: PROTOCOL_VERSION,
            message_id: Uuid::new_v4(),
            sender_id,
            recipient_id,
            timestamp,
            message_type: MessageType::Ping { timestamp },
            signature: None,
        }
    }

    /// Create a pong response
    pub fn new_pong(
        sender_id: Uuid,
        recipient_id: Uuid,
        ping_timestamp: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_id: Uuid::new_v4(),
            sender_id,
            recipient_id,
            timestamp: chrono::Utc::now(),
            message_type: MessageType::Pong {
                ping_timestamp,
                pong_timestamp: chrono::Utc::now(),
            },
            signature: None,
        }
    }

    /// Sign the message with the sender's identity key
    pub fn sign(&mut self, identity_keypair: &crate::crypto::IdentityKeyPair) -> Result<()> {
        let message_bytes = self.serialize_for_signing()?;
        let signature = identity_keypair.sign(&message_bytes);
        self.signature = Some(signature.to_vec());
        Ok(())
    }

    /// Verify the message signature
    pub fn verify_signature(&self, sender_identity: &Identity) -> Result<()> {
        let signature = self.signature.as_ref().ok_or_else(|| ProtocolError::MissingField {
            field: "signature".to_string(),
        })?;

        let message_bytes = self.serialize_for_signing()?;
        sender_identity.verify_signature(&message_bytes, signature)?;
        Ok(())
    }

    /// Serialize message for signing (without signature field)
    fn serialize_for_signing(&self) -> Result<Vec<u8>> {
        let mut msg_without_sig = self.clone();
        msg_without_sig.signature = None;
        bincode::serialize(&msg_without_sig).map_err(Into::into)
    }

    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let serialized = bincode::serialize(self)?;
        
        if serialized.len() > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::MessageTooLarge {
                size: serialized.len(),
                max: MAX_PAYLOAD_SIZE,
            }
            .into());
        }

        Ok(serialized)
    }

    /// Deserialize message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::MessageTooLarge {
                size: bytes.len(),
                max: MAX_PAYLOAD_SIZE,
            }
            .into());
        }

        let message: Self = bincode::deserialize(bytes)?;
        
        // Validate protocol version
        if message.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion {
                version: message.version.to_string(),
            }
            .into());
        }

        Ok(message)
    }

    /// Validate message fields
    pub fn validate(&self) -> Result<()> {
        // Check timestamp is not too far in the future
        let now = chrono::Utc::now();
        let max_future = now + chrono::Duration::minutes(5);
        
        if self.timestamp > max_future {
            return Err(ProtocolError::InvalidMessage {
                reason: "Message timestamp too far in future".to_string(),
            }
            .into());
        }

        // Check message is not too old (24 hours)
        let max_past = now - chrono::Duration::hours(24);
        if self.timestamp < max_past {
            return Err(ProtocolError::InvalidMessage {
                reason: "Message timestamp too old".to_string(),
            }
            .into());
        }

        // Validate message type specific fields
        match &self.message_type {
            MessageType::Chat { session_id, .. } => {
                if session_id.is_nil() {
                    return Err(ProtocolError::InvalidMessage {
                        reason: "Chat message missing session ID".to_string(),
                    }
                    .into());
                }
            }
            MessageType::FileTransfer { file_info, encrypted_data, .. } => {
                if encrypted_data.len() as u64 != file_info.size {
                    return Err(ProtocolError::InvalidMessage {
                        reason: "File size mismatch".to_string(),
                    }
                    .into());
                }
            }
            _ => {} // Other message types don't need additional validation
        }

        Ok(())
    }

    /// Get message type as string
    pub fn message_type_name(&self) -> &'static str {
        match self.message_type {
            MessageType::Chat { .. } => "Chat",
            MessageType::KeyExchange { .. } => "KeyExchange",
            MessageType::PrekeyRequest { .. } => "PrekeyRequest",
            MessageType::PrekeyResponse { .. } => "PrekeyResponse",
            MessageType::Acknowledgment { .. } => "Acknowledgment",
            MessageType::Presence { .. } => "Presence",
            MessageType::Typing { .. } => "Typing",
            MessageType::FileTransfer { .. } => "FileTransfer",
            MessageType::Ping { .. } => "Ping",
            MessageType::Pong { .. } => "Pong",
        }
    }

    /// Check if this message requires acknowledgment
    pub fn requires_ack(&self) -> bool {
        matches!(
            self.message_type,
            MessageType::Chat { .. } | MessageType::KeyExchange { .. } | MessageType::FileTransfer { .. }
        )
    }

    /// Calculate round-trip time from ping/pong
    pub fn calculate_rtt(&self) -> Option<chrono::Duration> {
        if let MessageType::Pong { ping_timestamp, pong_timestamp } = &self.message_type {
            Some(*pong_timestamp - *ping_timestamp)
        } else {
            None
        }
    }
}

impl FileInfo {
    /// Create new file info with hash calculation
    pub fn new(filename: String, mime_type: String, data: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash_result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_result);

        Self {
            filename,
            mime_type,
            size: data.len() as u64,
            hash,
        }
    }

    /// Verify file data against stored hash
    pub fn verify_hash(&self, data: &[u8]) -> bool {
        use sha2::{Digest, Sha256};
        
        if data.len() as u64 != self.size {
            return false;
        }

        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash_result = hasher.finalize();
        
        hash_result.as_slice() == &self.hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{IdentityKeyPair, UserProfile};
    use crate::session::RatchetMessage;

    #[test]
    fn test_message_serialization() {
        let sender_id = Uuid::new_v4();
        let recipient_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        
        let ratchet_message = RatchetMessage {
            dh_public_key: Some([1u8; 32]),
            previous_chain_length: 0,
            message_number: 1,
            ciphertext: b"encrypted content".to_vec(),
        };

        let message = P2PMessage::new_chat(sender_id, recipient_id, session_id, ratchet_message);
        
        let bytes = message.to_bytes().unwrap();
        let deserialized = P2PMessage::from_bytes(&bytes).unwrap();
        
        assert_eq!(message.message_id, deserialized.message_id);
        assert_eq!(message.sender_id, deserialized.sender_id);
        assert_eq!(message.recipient_id, deserialized.recipient_id);
    }

    #[test]
    fn test_message_signing() {
        let profile = UserProfile::new("Test User".to_string());
        let recipient_id = Uuid::new_v4();
        
        let mut message = P2PMessage::new_ping(profile.identity.id, recipient_id);
        
        // Sign the message
        message.sign(&profile.keypair).unwrap();
        assert!(message.signature.is_some());
        
        // Verify the signature
        assert!(message.verify_signature(&profile.identity).is_ok());
    }

    #[test]
    fn test_message_validation() {
        let sender_id = Uuid::new_v4();
        let recipient_id = Uuid::new_v4();
        
        let message = P2PMessage::new_ping(sender_id, recipient_id);
        assert!(message.validate().is_ok());
        
        // Test invalid timestamp (too far in future)
        let mut future_message = message.clone();
        future_message.timestamp = chrono::Utc::now() + chrono::Duration::hours(1);
        assert!(future_message.validate().is_err());
    }

    #[test]
    fn test_file_info() {
        let data = b"test file content";
        let file_info = FileInfo::new(
            "test.txt".to_string(),
            "text/plain".to_string(),
            data,
        );
        
        assert_eq!(file_info.size, data.len() as u64);
        assert!(file_info.verify_hash(data));
        assert!(!file_info.verify_hash(b"different content"));
    }

    #[test]
    fn test_rtt_calculation() {
        let sender_id = Uuid::new_v4();
        let recipient_id = Uuid::new_v4();
        let ping_time = chrono::Utc::now();
        
        let pong_message = P2PMessage::new_pong(sender_id, recipient_id, ping_time);
        
        let rtt = pong_message.calculate_rtt();
        assert!(rtt.is_some());
        assert!(rtt.unwrap() >= chrono::Duration::zero());
    }

    #[test]
    fn test_message_size_limit() {
        let large_data = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let result = bincode::serialize(&large_data);
        
        if let Ok(bytes) = result {
            let msg_result = P2PMessage::from_bytes(&bytes);
            assert!(msg_result.is_err());
        }
    }
}