//! Peer discovery implementation for the secure P2P messenger.
//!
//! This module provides various peer discovery mechanisms including mDNS for
//! local network discovery, Kademlia DHT for global discovery, and relay nodes
//! for NAT traversal.

use crate::utils::{MessengerConfig, NetworkError, Result};
use libp2p::{Multiaddr, PeerId};
use std::collections::HashSet;
use std::time::Duration;
use tokio::time::{interval, Instant};

/// Peer discovery manager
pub struct DiscoveryManager {
    /// Configuration
    config: MessengerConfig,
    /// Known bootstrap nodes
    bootstrap_nodes: Vec<Multiaddr>,
    /// Discovered peers
    discovered_peers: HashSet<PeerId>,
    /// Last discovery attempt
    last_discovery: Option<Instant>,
    /// Discovery interval
    discovery_interval: Duration,
}

/// Discovery result containing peer information
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    /// Discovered peer ID
    pub peer_id: PeerId,
    /// Peer's addresses
    pub addresses: Vec<Multiaddr>,
    /// Discovery method used
    pub discovery_method: DiscoveryMethod,
    /// Discovery timestamp
    pub discovered_at: chrono::DateTime<chrono::Utc>,
}

/// Discovery methods
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryMethod {
    /// mDNS local network discovery
    Mdns,
    /// Kademlia DHT discovery
    Kademlia,
    /// Bootstrap node
    Bootstrap,
    /// Relay discovery
    Relay,
    /// Manual peer addition
    Manual,
}

impl DiscoveryManager {
    /// Create a new discovery manager
    pub fn new(config: MessengerConfig) -> Self {
        let bootstrap_nodes = config
            .network
            .bootstrap_nodes
            .iter()
            .filter_map(|addr| addr.parse().ok())
            .collect();

        Self {
            config,
            bootstrap_nodes,
            discovered_peers: HashSet::new(),
            last_discovery: None,
            discovery_interval: Duration::from_secs(30),
        }
    }

    /// Add a bootstrap node
    pub fn add_bootstrap_node(&mut self, addr: Multiaddr) {
        self.bootstrap_nodes.push(addr);
    }

    /// Get bootstrap nodes
    pub fn bootstrap_nodes(&self) -> &[Multiaddr] {
        &self.bootstrap_nodes
    }

    /// Start periodic discovery
    pub async fn start_periodic_discovery(&mut self) -> Result<()> {
        let mut discovery_timer = interval(self.discovery_interval);

        loop {
            discovery_timer.tick().await;
            
            if let Err(e) = self.perform_discovery().await {
                log::warn!("Discovery failed: {}", e);
            }
        }
    }

    /// Perform a single discovery round
    pub async fn perform_discovery(&mut self) -> Result<Vec<DiscoveryResult>> {
        let mut results = Vec::new();
        self.last_discovery = Some(Instant::now());

        // Bootstrap discovery
        if self.config.network.bootstrap_nodes.len() > 0 {
            for addr in &self.bootstrap_nodes.clone() {
                if let Some(peer_id) = self.extract_peer_id_from_addr(addr) {
                    if !self.discovered_peers.contains(&peer_id) {
                        self.discovered_peers.insert(peer_id);
                        results.push(DiscoveryResult {
                            peer_id,
                            addresses: vec![addr.clone()],
                            discovery_method: DiscoveryMethod::Bootstrap,
                            discovered_at: chrono::Utc::now(),
                        });
                    }
                }
            }
        }

        // mDNS discovery (would be handled by libp2p in real implementation)
        if self.config.network.enable_mdns {
            // In a real implementation, this would interface with libp2p's mDNS
            log::debug!("mDNS discovery enabled but not implemented in this example");
        }

        // DHT discovery
        if self.config.network.enable_dht {
            // In a real implementation, this would interface with libp2p's Kademlia
            log::debug!("DHT discovery enabled but not implemented in this example");
        }

        // Relay discovery
        if self.config.network.enable_relay {
            for relay_addr in &self.config.network.relay_addresses {
                if let Ok(addr) = relay_addr.parse::<Multiaddr>() {
                    if let Some(peer_id) = self.extract_peer_id_from_addr(&addr) {
                        if !self.discovered_peers.contains(&peer_id) {
                            self.discovered_peers.insert(peer_id);
                            results.push(DiscoveryResult {
                                peer_id,
                                addresses: vec![addr],
                                discovery_method: DiscoveryMethod::Relay,
                                discovered_at: chrono::Utc::now(),
                            });
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    /// Extract peer ID from multiaddress
    fn extract_peer_id_from_addr(&self, addr: &Multiaddr) -> Option<PeerId> {
        addr.iter().find_map(|protocol| {
            if let libp2p::multiaddr::Protocol::P2p(multihash) = protocol {
                PeerId::from_multihash(multihash.into()).ok()
            } else {
                None
            }
        })
    }

    /// Manually add a discovered peer
    pub fn add_discovered_peer(&mut self, result: DiscoveryResult) {
        self.discovered_peers.insert(result.peer_id);
    }

    /// Get all discovered peers
    pub fn discovered_peers(&self) -> &HashSet<PeerId> {
        &self.discovered_peers
    }

    /// Remove a peer from discovered set
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.discovered_peers.remove(peer_id);
    }

    /// Check if discovery should be performed
    pub fn should_discover(&self) -> bool {
        match self.last_discovery {
            Some(last) => last.elapsed() >= self.discovery_interval,
            None => true,
        }
    }

    /// Get discovery statistics
    pub fn stats(&self) -> DiscoveryStats {
        DiscoveryStats {
            bootstrap_nodes: self.bootstrap_nodes.len(),
            discovered_peers: self.discovered_peers.len(),
            last_discovery: self.last_discovery.map(|i| {
                chrono::Utc::now() - chrono::Duration::from_std(i.elapsed()).unwrap_or_default()
            }),
            discovery_interval: self.discovery_interval,
            mdns_enabled: self.config.network.enable_mdns,
            dht_enabled: self.config.network.enable_dht,
            relay_enabled: self.config.network.enable_relay,
        }
    }
}

/// Discovery statistics
#[derive(Debug, Clone)]
pub struct DiscoveryStats {
    /// Number of bootstrap nodes
    pub bootstrap_nodes: usize,
    /// Number of discovered peers
    pub discovered_peers: usize,
    /// Last discovery timestamp
    pub last_discovery: Option<chrono::DateTime<chrono::Utc>>,
    /// Discovery interval
    pub discovery_interval: Duration,
    /// Whether mDNS is enabled
    pub mdns_enabled: bool,
    /// Whether DHT is enabled
    pub dht_enabled: bool,
    /// Whether relay is enabled
    pub relay_enabled: bool,
}

/// NAT traversal helper
pub struct NatTraversal {
    /// Whether UPnP is enabled
    upnp_enabled: bool,
    /// Whether relay is enabled
    relay_enabled: bool,
    /// Known relay addresses
    relay_addresses: Vec<Multiaddr>,
}

impl NatTraversal {
    /// Create a new NAT traversal helper
    pub fn new(config: &MessengerConfig) -> Self {
        let relay_addresses = config
            .network
            .relay_addresses
            .iter()
            .filter_map(|addr| addr.parse().ok())
            .collect();

        Self {
            upnp_enabled: config.network.enable_upnp,
            relay_enabled: config.network.enable_relay,
            relay_addresses,
        }
    }

    /// Attempt NAT traversal
    pub async fn traverse_nat(&self) -> Result<Vec<Multiaddr>> {
        let mut external_addresses = Vec::new();

        // UPnP port mapping
        if self.upnp_enabled {
            // In a real implementation, this would use UPnP libraries
            log::debug!("UPnP NAT traversal not implemented in this example");
        }

        // Relay traversal
        if self.relay_enabled {
            for relay_addr in &self.relay_addresses {
                // In a real implementation, this would establish relay connections
                external_addresses.push(relay_addr.clone());
            }
        }

        Ok(external_addresses)
    }

    /// Check if NAT traversal is needed
    pub fn needs_traversal(&self, local_addresses: &[Multiaddr]) -> bool {
        // Check if all addresses are private/local
        local_addresses.iter().all(|addr| {
            addr.iter().any(|protocol| {
                matches!(
                    protocol,
                    libp2p::multiaddr::Protocol::Ip4(ip) if ip.is_private() || ip.is_loopback()
                )
            })
        })
    }
}

/// Peer connectivity tester
pub struct ConnectivityTester;

impl ConnectivityTester {
    /// Test connectivity to a peer
    pub async fn test_peer_connectivity(
        peer_id: &PeerId,
        addresses: &[Multiaddr],
    ) -> Result<ConnectivityResult> {
        let start_time = Instant::now();

        // In a real implementation, this would attempt to connect to the peer
        // For now, we'll simulate a connectivity test
        tokio::time::sleep(Duration::from_millis(100)).await;

        let latency = start_time.elapsed();
        let success = !addresses.is_empty(); // Simple success criteria

        Ok(ConnectivityResult {
            peer_id: *peer_id,
            success,
            latency: if success { Some(latency) } else { None },
            tested_addresses: addresses.to_vec(),
            error: if success {
                None
            } else {
                Some("No addresses to test".to_string())
            },
        })
    }

    /// Test connectivity to multiple peers
    pub async fn test_multiple_peers(
        peers: &[(PeerId, Vec<Multiaddr>)],
    ) -> Vec<ConnectivityResult> {
        let mut results = Vec::new();

        for (peer_id, addresses) in peers {
            match Self::test_peer_connectivity(peer_id, addresses).await {
                Ok(result) => results.push(result),
                Err(e) => results.push(ConnectivityResult {
                    peer_id: *peer_id,
                    success: false,
                    latency: None,
                    tested_addresses: addresses.clone(),
                    error: Some(e.to_string()),
                }),
            }
        }

        results
    }
}

/// Connectivity test result
#[derive(Debug, Clone)]
pub struct ConnectivityResult {
    /// Tested peer ID
    pub peer_id: PeerId,
    /// Whether the test succeeded
    pub success: bool,
    /// Connection latency (if successful)
    pub latency: Option<Duration>,
    /// Addresses that were tested
    pub tested_addresses: Vec<Multiaddr>,
    /// Error message (if failed)
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_manager_creation() {
        let config = MessengerConfig::default();
        let manager = DiscoveryManager::new(config);
        assert_eq!(manager.bootstrap_nodes().len(), 0);
        assert_eq!(manager.discovered_peers().len(), 0);
    }

    #[test]
    fn test_discovery_manager_bootstrap() {
        let mut config = MessengerConfig::default();
        let peer_id = PeerId::random();
        config.network.bootstrap_nodes = vec![
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", peer_id)
        ];
        
        let manager = DiscoveryManager::new(config);
        assert!(manager.bootstrap_nodes().len() > 0);
    }

    #[test]
    fn test_nat_traversal_creation() {
        let config = MessengerConfig::default();
        let nat_traversal = NatTraversal::new(&config);
        assert_eq!(nat_traversal.upnp_enabled, config.network.enable_upnp);
        assert_eq!(nat_traversal.relay_enabled, config.network.enable_relay);
    }

    #[tokio::test]
    async fn test_connectivity_tester() {
        let peer_id = PeerId::random();
        let addresses = vec![];
        
        let result = ConnectivityTester::test_peer_connectivity(&peer_id, &addresses).await;
        assert!(result.is_ok());
        
        let connectivity_result = result.unwrap();
        assert_eq!(connectivity_result.peer_id, peer_id);
    }

    #[test]
    fn test_discovery_stats() {
        let config = MessengerConfig::default();
        let manager = DiscoveryManager::new(config.clone());
        let stats = manager.stats();
        
        assert_eq!(stats.bootstrap_nodes, 0);
        assert_eq!(stats.discovered_peers, 0);
        assert_eq!(stats.mdns_enabled, config.network.enable_mdns);
        assert_eq!(stats.dht_enabled, config.network.enable_dht);
        assert_eq!(stats.relay_enabled, config.network.enable_relay);
    }
}