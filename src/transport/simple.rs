//! Simplified transport layer for testing and development.
//!
//! This provides a basic transport implementation without complex libp2p
//! networking, suitable for local testing and development.

use crate::transport::{P2PMessage, MessageType};
use crate::utils::{MessengerConfig, NetworkError, Result};
use std::collections::HashMap;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Simple transport for local testing
pub struct SimpleTransport {
    /// Local node identifier
    local_id: String,
    /// Configuration
    config: MessengerConfig,
    /// Message channels
    message_sender: mpsc::UnboundedSender<P2PMessage>,
    message_receiver: mpsc::UnboundedReceiver<P2PMessage>,
    /// Connected peers (simplified)
    connected_peers: HashMap<String, SimplePeerInfo>,
}

/// Simple peer information
#[derive(Debug, Clone)]
pub struct SimplePeerInfo {
    /// Peer identifier
    pub peer_id: String,
    /// Connection timestamp
    pub connected_at: chrono::DateTime<chrono::Utc>,
    /// Last activity timestamp
    pub last_activity: chrono::DateTime<chrono::Utc>,
}

impl SimpleTransport {
    /// Create a new simple transport
    pub async fn new(config: MessengerConfig) -> Result<Self> {
        let local_id = format!("peer-{}", uuid::Uuid::new_v4().to_string()[..8].to_string());
        let (message_sender, message_receiver) = mpsc::unbounded_channel();

        Ok(Self {
            local_id,
            config,
            message_sender,
            message_receiver,
            connected_peers: HashMap::new(),
        })
    }

    /// Get the local peer ID
    pub fn local_peer_id(&self) -> &str {
        &self.local_id
    }

    /// Get connected peers
    pub fn connected_peers(&self) -> &HashMap<String, SimplePeerInfo> {
        &self.connected_peers
    }

    /// Send a message (simplified - just logs for now)
    pub async fn send_message(&mut self, _peer_id: &str, message: P2PMessage) -> Result<()> {
        log::info!("Sending {} message: {}", message.message_type_name(), message.message_id);
        
        // In a real implementation, this would send over the network
        // For now, just validate and log
        message.validate()?;
        
        Ok(())
    }

    /// Broadcast a message (simplified)
    pub async fn broadcast_message(&mut self, message: P2PMessage) -> Result<()> {
        log::info!("Broadcasting {} message: {}", message.message_type_name(), message.message_id);
        
        message.validate()?;
        
        Ok(())
    }

    /// Add a bootstrap node (simplified)
    pub fn add_bootstrap_node(&mut self, addr: String) -> Result<()> {
        log::info!("Adding bootstrap node: {}", addr);
        Ok(())
    }

    /// Start discovery (simplified)
    pub fn start_discovery(&mut self) -> Result<()> {
        log::info!("Starting peer discovery");
        Ok(())
    }

    /// Run the transport (simplified event loop)
    pub async fn run(&mut self) -> Result<()> {
        log::info!("Starting simple transport on local ID: {}", self.local_id);
        
        // Simulate some basic transport activity
        let mut counter = 0;
        loop {
            tokio::select! {
                // Handle incoming messages
                message = self.message_receiver.recv() => {
                    if let Some(msg) = message {
                        log::debug!("Received message: {}", msg.message_id);
                    }
                }
                
                // Periodic keep-alive
                _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                    counter += 1;
                    log::debug!("Transport heartbeat #{}", counter);
                    
                    // Exit after a few iterations for testing
                    if counter >= 3 {
                        log::info!("Simple transport completed test run");
                        break;
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Get transport statistics
    pub fn stats(&self) -> SimpleTransportStats {
        SimpleTransportStats {
            local_id: self.local_id.clone(),
            connected_peers: self.connected_peers.len(),
            uptime: chrono::Duration::seconds(0), // Simplified
        }
    }
}

/// Simple transport statistics
#[derive(Debug, Clone)]
pub struct SimpleTransportStats {
    /// Local identifier
    pub local_id: String,
    /// Number of connected peers
    pub connected_peers: usize,
    /// Transport uptime
    pub uptime: chrono::Duration,
}