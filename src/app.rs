//! Main application lifecycle and coordination.
//!
//! This module provides the main application structure that coordinates all
//! components of the secure P2P messenger, including network transport,
//! session management, and message processing.

use crate::{
    crypto::{PrekeyManager, UserProfile},
    network::DiscoveryManager,
    session::SessionManager,
    transport::{P2PTransport, P2PMessage, MessageType, AckStatus},
    utils::{MessengerConfig, MessengerError, Result},
};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

/// Main application structure
pub struct App {
    /// Application configuration
    config: MessengerConfig,
    /// User profile (identity and keys)
    user_profile: UserProfile,
    /// P2P transport layer
    transport: P2PTransport,
    /// Session manager for Double Ratchet sessions
    session_manager: Arc<RwLock<SessionManager>>,
    /// Prekey manager for X3DH
    prekey_manager: Arc<RwLock<PrekeyManager>>,
    /// Peer discovery manager
    discovery_manager: Arc<RwLock<DiscoveryManager>>,
    /// Message processor
    message_processor: MessageProcessor,
    /// Application event channels
    event_sender: mpsc::UnboundedSender<AppEvent>,
    event_receiver: mpsc::UnboundedReceiver<AppEvent>,
}

/// Application events
#[derive(Debug, Clone)]
pub enum AppEvent {
    /// New message received
    MessageReceived {
        sender_id: Uuid,
        session_id: Uuid,
        content: Vec<u8>,
    },
    /// Message sent successfully
    MessageSent {
        recipient_id: Uuid,
        message_id: Uuid,
    },
    /// New peer discovered
    PeerDiscovered {
        peer_id: String,
        addresses: Vec<String>,
    },
    /// Peer connected
    PeerConnected {
        peer_id: String,
    },
    /// Peer disconnected
    PeerDisconnected {
        peer_id: String,
    },
    /// Key exchange completed
    KeyExchangeCompleted {
        peer_id: Uuid,
        session_id: Uuid,
    },
    /// Error occurred
    Error {
        error: MessengerError,
    },
}

/// Message processor for handling different message types
pub struct MessageProcessor {
    /// User profile reference
    user_profile: UserProfile,
    /// Event sender
    event_sender: mpsc::UnboundedSender<AppEvent>,
}

impl App {
    /// Create a new application instance
    pub async fn new(config: MessengerConfig) -> Result<Self> {
        // Load or create user profile
        let user_profile = Self::load_or_create_profile(&config)?;
        
        // Create transport
        let transport = P2PTransport::new(config.clone()).await?;
        
        // Create managers
        let session_manager = Arc::new(RwLock::new(SessionManager::default()));
        let prekey_manager = Arc::new(RwLock::new(PrekeyManager::new()));
        let discovery_manager = Arc::new(RwLock::new(DiscoveryManager::new(config.clone())));
        
        // Create event channels
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        // Create message processor
        let message_processor = MessageProcessor::new(user_profile.clone(), event_sender.clone());
        
        Ok(Self {
            config,
            user_profile,
            transport,
            session_manager,
            prekey_manager,
            discovery_manager,
            message_processor,
            event_sender,
            event_receiver,
        })
    }

    /// Load existing user profile or create a new one
    fn load_or_create_profile(config: &MessengerConfig) -> Result<UserProfile> {
        let profile_path = config.storage.keys_dir.join("profile.json");
        let private_key_path = config.storage.keys_dir.join("private_key");

        if profile_path.exists() && private_key_path.exists() {
            // Load existing profile
            let identity_json = std::fs::read_to_string(&profile_path)?;
            let identity: crate::crypto::Identity = serde_json::from_str(&identity_json)?;
            
            let private_key_bytes = std::fs::read(&private_key_path)?;
            let keypair = crate::crypto::IdentityKeyPair::from_secret_bytes(&private_key_bytes)?;
            
            UserProfile::from_keypair_and_identity(keypair, identity)
        } else {
            // Create new profile
            let profile = UserProfile::new("Default User".to_string());
            
            // Save profile
            std::fs::create_dir_all(&config.storage.keys_dir)?;
            
            let profile_json = serde_json::to_string_pretty(&profile.identity)?;
            std::fs::write(&profile_path, profile_json)?;
            std::fs::write(&private_key_path, profile.export_private_key())?;
            
            Ok(profile)
        }
    }

    /// Run the application
    pub async fn run(mut self) -> Result<()> {
        log::info!("Starting secure P2P messenger");
        log::info!("User: {}", self.user_profile.identity);
        log::info!("Peer ID: {}", self.transport.local_peer_id());

        // Start discovery
        {
            let mut discovery = self.discovery_manager.write().await;
            for bootstrap in &self.config.network.bootstrap_nodes {
                if let Ok(addr) = bootstrap.parse() {
                    discovery.add_bootstrap_node(addr);
                }
            }
        }

        // Generate initial prekey bundle
        {
            let mut prekey_manager = self.prekey_manager.write().await;
            let _bundle = prekey_manager.generate_prekey_bundle(
                self.user_profile.identity.clone(),
                &self.user_profile.keypair,
                Some(self.config.crypto.prekey_count),
            );
        }

        // Main application loop
        loop {
            tokio::select! {
                // Handle application events
                event = self.event_receiver.recv() => {
                    if let Some(event) = event {
                        self.handle_app_event(event).await?;
                    }
                }
                
                // Run transport (this would be the main network loop)
                result = self.transport.run() => {
                    if let Err(e) = result {
                        log::error!("Transport error: {}", e);
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Handle application events
    async fn handle_app_event(&mut self, event: AppEvent) -> Result<()> {
        match event {
            AppEvent::MessageReceived { sender_id, session_id, content } => {
                log::info!("Received message from {} in session {}", sender_id, session_id);
                // In a real application, you'd display the message to the user
                println!("Message: {}", String::from_utf8_lossy(&content));
            }
            AppEvent::MessageSent { recipient_id, message_id } => {
                log::info!("Message {} sent to {}", message_id, recipient_id);
            }
            AppEvent::PeerDiscovered { peer_id, addresses } => {
                log::info!("Discovered peer: {} at {:?}", peer_id, addresses);
            }
            AppEvent::PeerConnected { peer_id } => {
                log::info!("Connected to peer: {}", peer_id);
            }
            AppEvent::PeerDisconnected { peer_id } => {
                log::info!("Disconnected from peer: {}", peer_id);
            }
            AppEvent::KeyExchangeCompleted { peer_id, session_id } => {
                log::info!("Key exchange completed with {} (session: {})", peer_id, session_id);
            }
            AppEvent::Error { error } => {
                log::error!("Application error: {}", error);
                if error.is_security_violation() {
                    log::warn!("Security violation detected - taking defensive action");
                }
            }
        }
        Ok(())
    }

    /// Send a message to a user
    pub async fn send_message(&mut self, recipient_id: Uuid, content: &str) -> Result<Uuid> {
        let content_bytes = content.as_bytes();
        
        // Check if we have an active session
        let session_id = {
            let session_manager = self.session_manager.read().await;
            session_manager.session_ids().first().copied()
        };
        
        // For simplicity, use the first available session or start key exchange
        if let Some(session_id) = session_id {
            let mut session_manager = self.session_manager.write().await;
            let session = session_manager.get_session_mut(&session_id)?;
            
            let ratchet_message = session.encrypt(content_bytes)?;
            let p2p_message = P2PMessage::new_chat(
                self.user_profile.identity.id,
                recipient_id,
                session_id,
                ratchet_message,
            );
            
            // Sign the message
            let mut signed_message = p2p_message;
            signed_message.sign(&self.user_profile.keypair)?;
            
            // Send via transport (this is simplified)
            let message_id = signed_message.message_id;
            // self.transport.send_message(&peer_id, signed_message).await?;
            
            Ok(message_id)
        } else {
            // Start key exchange
            self.initiate_key_exchange(recipient_id).await
        }
    }

    /// Initiate key exchange with a user
    async fn initiate_key_exchange(&mut self, recipient_id: Uuid) -> Result<Uuid> {
        // In a real implementation, you'd:
        // 1. Request the recipient's prekey bundle
        // 2. Perform X3DH key agreement
        // 3. Establish a Double Ratchet session
        // 4. Send the initial message
        
        log::info!("Initiating key exchange with {}", recipient_id);
        
        // For now, return a placeholder message ID
        Ok(Uuid::new_v4())
    }

    /// Get application statistics
    pub async fn stats(&self) -> AppStats {
        let session_manager = self.session_manager.read().await;
        let discovery_manager = self.discovery_manager.read().await;
        
        AppStats {
            user_id: self.user_profile.identity.id,
            peer_id: self.transport.local_peer_id().to_string(),
            active_sessions: session_manager.session_ids().len(),
            discovered_peers: discovery_manager.discovered_peers().len(),
            connected_peers: self.transport.connected_peers().len(),
            uptime: chrono::Utc::now()
                .signed_duration_since(self.user_profile.identity.created_at),
        }
    }

    /// Shutdown the application gracefully
    pub async fn shutdown(self) -> Result<()> {
        log::info!("Shutting down application");
        
        // In a real implementation, you'd:
        // - Close all network connections
        // - Save session state
        // - Clean up resources
        
        Ok(())
    }
}

impl MessageProcessor {
    /// Create a new message processor
    pub fn new(user_profile: UserProfile, event_sender: mpsc::UnboundedSender<AppEvent>) -> Self {
        Self {
            user_profile,
            event_sender,
        }
    }

    /// Process an incoming P2P message
    pub async fn process_message(&mut self, message: P2PMessage) -> Result<()> {
        // Verify message signature if present
        if message.signature.is_some() {
            // In a real implementation, you'd look up the sender's identity
            // For now, we'll skip verification
        }

        match message.message_type {
            MessageType::Chat { session_id, ratchet_message: _ } => {
                // Decrypt and process chat message
                // In a real implementation, you'd decrypt using the session
                let content = b"Decrypted message content".to_vec(); // Placeholder
                
                let _ = self.event_sender.send(AppEvent::MessageReceived {
                    sender_id: message.sender_id,
                    session_id,
                    content,
                });
            }
            MessageType::KeyExchange { x3dh_message: _ } => {
                // Process X3DH key exchange
                log::info!("Processing key exchange from {}", message.sender_id);
                
                // In a real implementation, you'd complete the X3DH protocol
                let session_id = Uuid::new_v4();
                let _ = self.event_sender.send(AppEvent::KeyExchangeCompleted {
                    peer_id: message.sender_id,
                    session_id,
                });
            }
            MessageType::PrekeyRequest { user_id: _ } => {
                // Send prekey bundle response
                log::info!("Prekey request from {}", message.sender_id);
                // In a real implementation, you'd send your prekey bundle
            }
            MessageType::PrekeyResponse { bundle: _ } => {
                // Process prekey bundle
                log::info!("Received prekey bundle from {}", message.sender_id);
                // In a real implementation, you'd use this to initiate X3DH
            }
            MessageType::Acknowledgment { ack_message_id, status } => {
                match status {
                    AckStatus::Delivered => {
                        log::debug!("Message {} delivered", ack_message_id);
                    }
                    AckStatus::Read => {
                        log::debug!("Message {} read", ack_message_id);
                    }
                    AckStatus::Failed { reason } => {
                        log::warn!("Message {} failed: {}", ack_message_id, reason);
                    }
                }
            }
            MessageType::Ping { timestamp: _ } => {
                // Respond with pong
                log::debug!("Ping from {}", message.sender_id);
                // In a real implementation, you'd send a pong response
            }
            MessageType::Pong { ping_timestamp: _, pong_timestamp: _ } => {
                // Calculate RTT
                if let Some(rtt) = message.calculate_rtt() {
                    log::debug!("RTT to {}: {:?}", message.sender_id, rtt);
                }
            }
            _ => {
                log::debug!("Unhandled message type: {}", message.message_type_name());
            }
        }

        Ok(())
    }
}

/// Application statistics
#[derive(Debug, Clone)]
pub struct AppStats {
    /// User ID
    pub user_id: Uuid,
    /// Network peer ID
    pub peer_id: String,
    /// Number of active sessions
    pub active_sessions: usize,
    /// Number of discovered peers
    pub discovered_peers: usize,
    /// Number of connected peers
    pub connected_peers: usize,
    /// Application uptime
    pub uptime: chrono::Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_app() -> (App, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let mut config = MessengerConfig::default();
        config.storage.data_dir = temp_dir.path().to_path_buf();
        config.storage.keys_dir = temp_dir.path().join("keys");
        config.storage.messages_dir = temp_dir.path().join("messages");
        config.storage.sessions_dir = temp_dir.path().join("sessions");
        
        let app = App::new(config).await.unwrap();
        (app, temp_dir)
    }

    #[tokio::test]
    async fn test_app_creation() {
        let (_app, _temp_dir) = create_test_app().await;
        // App created successfully
    }

    #[tokio::test]
    async fn test_app_stats() {
        let (app, _temp_dir) = create_test_app().await;
        let stats = app.stats().await;
        
        assert_eq!(stats.active_sessions, 0);
        assert_eq!(stats.discovered_peers, 0);
        assert_eq!(stats.connected_peers, 0);
    }

    #[tokio::test]
    async fn test_message_processor() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = MessengerConfig::default();
        config.storage.keys_dir = temp_dir.path().join("keys");
        
        let profile = App::load_or_create_profile(&config).unwrap();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let mut processor = MessageProcessor::new(profile, sender);
        
        let ping_message = P2PMessage::new_ping(Uuid::new_v4(), Uuid::new_v4());
        
        tokio::spawn(async move {
            processor.process_message(ping_message).await.unwrap();
        });
        
        // The ping processing doesn't generate events in this simplified implementation
        // In a real implementation, you'd test event generation
    }
}