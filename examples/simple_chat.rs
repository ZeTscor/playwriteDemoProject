//! Simple chat example demonstrating basic messenger functionality.
//!
//! This example shows how to:
//! - Initialize the messenger application
//! - Generate cryptographic identities
//! - Send and receive messages
//! - Handle basic peer discovery

use secure_p2p_messenger::{
    crypto::UserProfile,
    utils::MessengerConfig,
    App,
};
use base64::Engine;
use std::io::{self, Write};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    println!("🔐 Secure P2P Messenger - Simple Chat Example");
    println!("==============================================");

    // Create configuration
    let mut config = MessengerConfig::default();
    config.storage.data_dir = std::env::current_dir()?.join("example-data");
    config.storage.keys_dir = config.storage.data_dir.join("keys");
    config.storage.messages_dir = config.storage.data_dir.join("messages");
    config.storage.sessions_dir = config.storage.data_dir.join("sessions");
    config.network.listen_port = 4003; // Use different port for example

    // Ensure directories exist
    config.ensure_directories()?;

    // Create and start the application
    println!("🚀 Starting messenger application...");
    let mut app = App::new(config).await?;

    println!("✅ Application started successfully!");
    
    // Show application stats
    let stats = app.stats().await;
    println!("📊 Application Stats:");
    println!("   User ID: {}", stats.user_id);
    println!("   Peer ID: {}", stats.peer_id);
    println!("   Active Sessions: {}", stats.active_sessions);
    println!("   Connected Peers: {}", stats.connected_peers);

    // Simulate some basic operations
    demo_basic_operations().await?;

    // In a real interactive application, you would:
    // app.run().await?;

    println!("🛑 Shutting down...");
    app.shutdown().await?;
    println!("✅ Shutdown complete");

    Ok(())
}

/// Demonstrate basic messenger operations
async fn demo_basic_operations() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔧 Demonstrating basic operations:");

    // 1. Create user profiles
    println!("👤 Creating user profiles...");
    let alice = UserProfile::new("Alice".to_string());
    let bob = UserProfile::new("Bob".to_string());

    println!("   Alice: {}", alice.identity);
    println!("   Bob: {}", bob.identity);

    // 2. Demonstrate cryptographic operations
    println!("\n🔐 Demonstrating cryptographic operations...");
    
    let message = b"Hello, this is a test message!";
    let signature = alice.sign(message);
    
    match alice.verify(message, &signature) {
        Ok(()) => println!("   ✅ Signature verification successful"),
        Err(e) => println!("   ❌ Signature verification failed: {}", e),
    }

    // 3. Demonstrate key exchange (simplified)
    println!("\n🤝 Demonstrating key exchange concepts...");
    
    // Generate prekey bundles
    use secure_p2p_messenger::crypto::PrekeyManager;
    let mut alice_prekey_manager = PrekeyManager::new();
    let mut bob_prekey_manager = PrekeyManager::new();

    let alice_bundle = alice_prekey_manager.generate_prekey_bundle(
        alice.identity.clone(),
        &alice.keypair,
        Some(5),
    );

    let bob_bundle = bob_prekey_manager.generate_prekey_bundle(
        bob.identity.clone(),
        &bob.keypair,
        Some(5),
    );

    println!("   ✅ Alice prekey bundle: {} one-time keys", alice_bundle.one_time_prekeys.len());
    println!("   ✅ Bob prekey bundle: {} one-time keys", bob_bundle.one_time_prekeys.len());

    // 4. Demonstrate X3DH key agreement
    println!("\n🔑 Demonstrating X3DH key agreement...");
    
    use secure_p2p_messenger::session::X3DHInitiator;
    
    let alice_initiator = X3DHInitiator::new(alice.keypair.clone());
    let initial_message = b"Hello Bob, this is Alice!";
    
    match alice_initiator.initiate(bob_bundle, initial_message) {
        Ok((x3dh_message, shared_secret)) => {
            println!("   ✅ X3DH key agreement successful");
            println!("   📝 X3DH message created (size: {} bytes)", 
                serde_json::to_string(&x3dh_message)?.len());
            println!("   🔐 Shared secret derived (32 bytes)");
        }
        Err(e) => {
            println!("   ❌ X3DH key agreement failed: {}", e);
        }
    }

    // 5. Demonstrate Double Ratchet messaging
    println!("\n💬 Demonstrating Double Ratchet messaging...");
    
    use secure_p2p_messenger::session::SessionState;
    use x25519_dalek::{StaticSecret, PublicKey};
    use rand::rngs::OsRng;

    let shared_secret = [1u8; 32]; // Simulated shared secret from X3DH
    let bob_private = StaticSecret::random_from_rng(OsRng);
    let bob_public = PublicKey::from(&bob_private);

    let mut alice_session = SessionState::new_initiator(shared_secret, bob_public)?;
    let mut bob_session = SessionState::new_recipient(shared_secret, (bob_private, bob_public))?;

    // Alice sends a message
    let message1 = b"Hello Bob, how are you?";
    let encrypted1 = alice_session.encrypt(message1)?;
    println!("   📤 Alice sent: '{}'", String::from_utf8_lossy(message1));

    // Bob receives and decrypts
    let decrypted1 = bob_session.decrypt(&encrypted1)?;
    println!("   📥 Bob received: '{}'", String::from_utf8_lossy(&decrypted1));

    // Bob replies
    let message2 = b"Hi Alice! I'm doing great, thanks for asking!";
    let encrypted2 = bob_session.encrypt(message2)?;
    println!("   📤 Bob sent: '{}'", String::from_utf8_lossy(message2));

    // Alice receives Bob's reply
    let decrypted2 = alice_session.decrypt(&encrypted2)?;
    println!("   📥 Alice received: '{}'", String::from_utf8_lossy(&decrypted2));

    println!("   ✅ Double Ratchet messaging successful!");

    // 6. Show session statistics
    let alice_stats = alice_session.stats();
    let bob_stats = bob_session.stats();
    
    println!("\n📊 Session Statistics:");
    println!("   Alice - Sent: {}, Received: {}", 
        alice_stats.messages_sent, alice_stats.messages_received);
    println!("   Bob - Sent: {}, Received: {}", 
        bob_stats.messages_sent, bob_stats.messages_received);

    println!("\n🎉 Demo completed successfully!");
    Ok(())
}

/// Interactive chat function (placeholder for real implementation)
#[allow(dead_code)]
async fn interactive_chat() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n💬 Interactive Chat Mode");
    println!("Type 'quit' to exit, 'help' for commands");

    loop {
        print!("> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        match input {
            "quit" => break,
            "help" => {
                println!("Available commands:");
                println!("  quit - Exit the chat");
                println!("  help - Show this help");
                println!("  stats - Show application statistics");
            }
            "stats" => {
                println!("Application statistics would be shown here");
            }
            _ => {
                println!("Message would be sent: '{}'", input);
                // In a real implementation, you'd send the message
            }
        }

        // Small delay to prevent busy looping
        sleep(Duration::from_millis(10)).await;
    }

    Ok(())
}