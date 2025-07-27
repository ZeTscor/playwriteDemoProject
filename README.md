# Secure P2P Messenger

A secure peer-to-peer messaging application built in Rust, implementing the Double Ratchet algorithm and X3DH key agreement protocol for end-to-end encrypted communication.

## Features

- **🔐 End-to-End Encryption**: Uses Double Ratchet algorithm for forward secrecy
- **🤝 Key Agreement**: X3DH protocol for secure key establishment
- **🌐 P2P Networking**: Built on libp2p with DHT discovery and NAT traversal
- **👤 Identity Management**: Ed25519-based cryptographic identities
- **📱 Modular Design**: Clean separation of concerns across modules
- **⚡ High Performance**: Optimized for both security and performance
- **🛡️ Security First**: No unsafe code, comprehensive error handling

## Architecture

The project is organized into several key modules:

- **`crypto/`**: Cryptographic primitives and identity management
  - `identity.rs`: Ed25519-based user identities
  - `prekeys.rs`: Signal-compatible prekey generation
- **`session/`**: Session management and key agreement protocols
  - `x3dh.rs`: X3DH key agreement protocol
  - `manager.rs`: Double Ratchet session management
- **`network/`**: P2P networking and peer discovery
  - `discovery.rs`: Kademlia DHT, mDNS, DCUtR, libp2p relay
- **`transport/`**: Low-level transport protocols and message handling
  - `p2p.rs`: Low-level P2P transport over TCP/libp2p
  - `protocol.rs`: Message formats, serialization, ACK handling
- **`utils/`**: Configuration, error handling, and utilities
  - `config.rs`: TOML-based configuration system
  - `errors.rs`: Unified error handling

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/secure-p2p-messenger
cd secure-p2p-messenger

# Build the project
cargo build --release
```

### Basic Usage

```bash
# Generate a new identity
cargo run --bin messenger keys generate --name "Your Name"

# Start the messenger
cargo run --bin messenger run

# Show your profile
cargo run --bin messenger profile

# Generate configuration file
cargo run --bin messenger config generate --output messenger.toml
```

### Library Usage

```rust
use secure_p2p_messenger::{App, MessengerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = MessengerConfig::default();
    let mut app = App::new(config).await?;
    app.run().await?;
    Ok(())
}
```

## CLI Commands

### Key Management

```bash
# Generate new identity
messenger keys generate --name "Alice"

# Show public key
messenger keys show --format hex

# Export keys for backup
messenger keys export --output backup.json --include-private

# Import keys from backup
messenger keys import --input backup.json

# Generate prekey bundle
messenger keys prekeys --count 100
```

### Configuration

```bash
# Generate default configuration
messenger config generate

# Validate configuration
messenger config validate

# Show current configuration
messenger config show
```

### Network Operations

```bash
# Test network connectivity
messenger network test

# Discover peers
messenger network discover --timeout 30

# Show network statistics
messenger network stats
```

### Running the Messenger

```bash
# Run with default settings
messenger run

# Run on specific port with bootstrap nodes
messenger run --port 4001 --bootstrap "/ip4/127.0.0.1/tcp/4002/p2p/..."

# Run in interactive mode
messenger run --interactive
```

## Configuration

The messenger uses TOML configuration files. See the `config/` directory for examples:

- `config/messenger.toml` - Default configuration
- `config/local.toml` - Development settings
- `config/production.toml` - Production settings

Key configuration sections:

### Network Configuration

```toml
[network]
listen_port = 4001
max_connections = 50
enable_mdns = true
enable_dht = true
enable_upnp = true
enable_relay = true
bootstrap_nodes = [
    "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ"
]
```

### Crypto Configuration

```toml
[crypto]
key_rotation_interval = 86400  # 24 hours
prekey_count = 100
enable_pfs = true
```

### Storage Configuration

```toml
[storage]
data_dir = "~/.secure-p2p-messenger"
enable_compression = true
backup_interval = 3600  # 1 hour
```

## Examples

Run the simple chat example:

```bash
cargo run --example simple_chat
```

This example demonstrates:
- Creating user identities
- Generating prekey bundles
- X3DH key agreement
- Double Ratchet messaging
- Basic cryptographic operations

## Security Features

### Cryptographic Protocols

- **Ed25519**: Digital signatures for identity verification
- **X25519**: Elliptic Curve Diffie-Hellman for key agreement
- **ChaCha20Poly1305**: Authenticated encryption for messages
- **HKDF**: Key derivation using HMAC-based extraction and expansion
- **X3DH**: Extended Triple Diffie-Hellman key agreement
- **Double Ratchet**: Forward-secure messaging with automatic key rotation

### Security Properties

- **Forward Secrecy**: Past messages remain secure even if current keys are compromised
- **Post-Compromise Security**: Security is restored after key compromise
- **Message Authentication**: All messages are cryptographically authenticated
- **Replay Protection**: Messages cannot be replayed by attackers
- **Metadata Protection**: Minimal metadata exposure in message routing

## Development

### Prerequisites

- Rust 1.70 or later
- libp2p dependencies for your platform

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Run benchmarks
cargo bench

# Check formatting
cargo fmt --check

# Run clippy
cargo clippy -- -D warnings
```

### Project Structure

```
src/
├── lib.rs                      # Central export point for all components
├── main.rs                     # CLI entry point
├── app.rs                      # Main application lifecycle and coordination
├── crypto/
│   ├── identity.rs             # Ed25519-based user identities
│   ├── prekeys.rs              # Signal-compatible prekey generation
│   └── mod.rs                  # Crypto module exports
├── session/
│   ├── manager.rs              # Double Ratchet session management
│   ├── x3dh.rs                 # X3DH key agreement protocol
│   └── mod.rs                  # Session module exports
├── network/
│   ├── discovery.rs            # Kademlia DHT, mDNS, DCUtR, libp2p relay
│   └── mod.rs                  # Network module exports
├── transport/
│   ├── p2p.rs                  # Low-level P2P transport over TCP/libp2p
│   ├── protocol.rs             # Message formats, serialization, ACK handling
│   └── mod.rs                  # Transport module exports
├── utils/
│   ├── config.rs               # TOML-based configuration system
│   ├── errors.rs               # Unified error handling
│   └── mod.rs                  # Utility functions and exports
└── examples/
    └── simple_chat.rs         # Example messenger instantiation
```

## Contributing

Contributions are welcome! Please read our contributing guidelines and make sure to:

1. Follow the existing code style
2. Add tests for new functionality
3. Update documentation as needed
4. Run the full test suite before submitting

## License

This project is licensed under the MIT OR Apache-2.0 license.

## Acknowledgments

- [Signal Protocol](https://signal.org/docs/) for the X3DH and Double Ratchet specifications
- [libp2p](https://libp2p.io/) for the networking stack
- [Ring](https://github.com/briansmith/ring) and [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek) for cryptographic primitives

## Security Disclaimer

This is a demonstration project implementing cryptographic protocols. While it follows best practices and established protocols, it has not undergone professional security auditing. Do not use this for production applications requiring strong security guarantees without proper security review.

## Roadmap

- [ ] Complete libp2p integration
- [ ] Implement file transfer
- [ ] Add group messaging support
- [ ] Mobile client support
- [ ] Web interface
- [ ] Professional security audit
- [ ] Performance optimizations
- [ ] Plugin system for extensions#   p l a y w r i t e D e m o P r o j e c t  
 