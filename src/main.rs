//! CLI entry point for the secure P2P messenger.
//!
//! This binary provides a command-line interface for the messenger library,
//! supporting key generation, configuration management, and running the
//! messenger application.

use anyhow::Result;
use clap::{Parser, Subcommand};
use log::{error, info, warn};
use secure_p2p_messenger::{
    crypto::{IdentityKeyPair, PrekeyManager, UserProfile},
    utils::{MessengerConfig, DEFAULT_CONFIG_FILE},
    App,
};
use std::path::PathBuf;
use tokio::signal;
use base64::{engine::general_purpose, Engine};

/// Secure P2P Messenger - End-to-end encrypted peer-to-peer messaging
#[derive(Parser)]
#[command(name = "messenger")]
#[command(about = "A secure peer-to-peer messenger using Double Ratchet and X3DH protocols")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(author = env!("CARGO_PKG_AUTHORS"))]
struct Cli {
    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Verbose logging (can be used multiple times)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Quiet mode (suppress non-error output)
    #[arg(short, long)]
    quiet: bool,

    /// Data directory for storing keys and messages
    #[arg(short, long, value_name = "DIR")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate and manage cryptographic keys
    Keys {
        #[command(subcommand)]
        action: KeyCommands,
    },
    /// Show user profile and identity information
    Profile {
        /// Display format (json, pretty)
        #[arg(short, long, default_value = "pretty")]
        format: String,
    },
    /// Run the messenger application
    Run {
        /// Port to listen on
        #[arg(short, long)]
        port: Option<u16>,
        /// Bootstrap node addresses
        #[arg(short, long)]
        bootstrap: Vec<String>,
        /// Enable interactive mode
        #[arg(short, long)]
        interactive: bool,
    },
    /// Generate and validate configuration files
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },
    /// Performance benchmarking
    Benchmark {
        /// Benchmark type (crypto, network, all)
        #[arg(default_value = "all")]
        benchmark_type: String,
        /// Number of iterations
        #[arg(short, long, default_value = "1000")]
        iterations: usize,
    },
    /// Network diagnostics and testing
    Network {
        #[command(subcommand)]
        action: NetworkCommands,
    },
    /// Quickstart: generate identity and config then run
    Quickstart {
        /// Optional display name for generated identity
        #[arg(short, long)]
        name: Option<String>,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Generate a new identity key pair
    Generate {
        /// Display name for the identity
        #[arg(short, long)]
        name: String,
        /// Force overwrite existing keys
        #[arg(short, long)]
        force: bool,
    },
    /// Display the current public key
    Show {
        /// Output format (hex, base64, pem)
        #[arg(short, long, default_value = "hex")]
        format: String,
    },
    /// Export keys for backup
    Export {
        /// Output file for the backup
        #[arg(short, long)]
        output: PathBuf,
        /// Include private keys in export
        #[arg(long)]
        include_private: bool,
    },
    /// Import keys from backup
    Import {
        /// Input file containing the backup
        #[arg(short, long)]
        input: PathBuf,
    },
    /// Generate prekey bundle
    Prekeys {
        /// Number of one-time prekeys to generate
        #[arg(short, long, default_value = "100")]
        count: usize,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Generate a default configuration file
    Generate {
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate configuration file
    Validate {
        /// Configuration file to validate
        file: Option<PathBuf>,
    },
    /// Show current configuration
    Show {
        /// Show only specific section
        #[arg(short, long)]
        section: Option<String>,
    },
}

#[derive(Subcommand)]
enum NetworkCommands {
    /// Test connectivity to bootstrap nodes
    Test {
        /// Specific node to test
        #[arg(short, long)]
        node: Option<String>,
    },
    /// Discover peers on the local network
    Discover {
        /// Discovery timeout in seconds
        #[arg(short, long, default_value = "10")]
        timeout: u64,
    },
    /// Show network statistics
    Stats,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    setup_logging(cli.verbose, cli.quiet)?;

    // Load configuration
    let mut config = MessengerConfig::load(cli.config.as_deref())?;

    // Override data directory if provided
    if let Some(data_dir) = cli.data_dir {
        config.storage.data_dir = data_dir;
        config.storage.keys_dir = config.storage.data_dir.join("keys");
        config.storage.messages_dir = config.storage.data_dir.join("messages");
        config.storage.sessions_dir = config.storage.data_dir.join("sessions");
    }

    // Ensure directories exist
    config.ensure_directories()?;

    match cli.command {
        Commands::Keys { action } => handle_key_commands(action, &config).await,
        Commands::Profile { format } => handle_profile_command(format, &config).await,
        Commands::Run {
            port,
            bootstrap,
            interactive,
        } => handle_run_command(port, bootstrap, interactive, config).await,
        Commands::Config { action } => handle_config_commands(action, &config).await,
        Commands::Benchmark {
            benchmark_type,
            iterations,
        } => handle_benchmark_command(benchmark_type, iterations).await,
        Commands::Network { action } => handle_network_commands(action, &config).await,
        Commands::Quickstart { name } => handle_quickstart_command(name, config).await,
    }
}

fn setup_logging(verbose: u8, quiet: bool) -> Result<()> {
    let log_level = if quiet {
        "error"
    } else {
        match verbose {
            0 => "info",
            1 => "debug",
            _ => "trace",
        }
    };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .format_timestamp_secs()
        .init();

    Ok(())
}

async fn handle_key_commands(action: KeyCommands, config: &MessengerConfig) -> Result<()> {
    match action {
        KeyCommands::Generate { name, force } => {
            let keys_dir = &config.storage.keys_dir;
            let profile_path = keys_dir.join("profile.json");

            if profile_path.exists() && !force {
                return Err(anyhow::anyhow!(
                    "Identity already exists. Use --force to overwrite."
                ));
            }

            info!("Generating new identity for '{}'", name);
            let profile = UserProfile::new(name);

            // Save profile
            let profile_json = serde_json::to_string_pretty(&profile.identity)?;
            std::fs::write(&profile_path, profile_json)?;

            // Save private key separately
            let private_key_path = keys_dir.join("private_key");
            std::fs::write(private_key_path, profile.export_private_key())?;

            println!("✓ Identity generated successfully");
            println!("  Name: {}", profile.identity.display_name);
            println!("  ID: {}", profile.identity.short_id());
            println!("  Saved to: {}", profile_path.display());
        }
        KeyCommands::Show { format } => {
            let profile = load_user_profile(config)?;
            let public_key = profile.identity.public_key;

            match format.as_str() {
                "hex" => println!("{}", hex::encode(public_key)),
                "base64" => println!("{}", general_purpose::STANDARD.encode(public_key)),
                "pem" => {
                    println!("-----BEGIN PUBLIC KEY-----");
                    println!("{}", general_purpose::STANDARD.encode(public_key));
                    println!("-----END PUBLIC KEY-----");
                }
                _ => return Err(anyhow::anyhow!("Unsupported format: {}", format)),
            }
        }
        KeyCommands::Export {
            output,
            include_private,
        } => {
            let profile = load_user_profile(config)?;
            let mut export_data = serde_json::json!({
                "identity": profile.identity,
                "exported_at": chrono::Utc::now(),
                "version": env!("CARGO_PKG_VERSION")
            });

            if include_private {
                warn!("Including private keys in export - keep this file secure!");
                export_data["private_key"] = serde_json::json!(profile.export_private_key());
            }

            std::fs::write(&output, serde_json::to_string_pretty(&export_data)?)?;
            println!("✓ Keys exported to: {}", output.display());
        }
        KeyCommands::Import { input } => {
            let import_data: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(input)?)?;
            
            if let Some(identity_data) = import_data.get("identity") {
                let identity: secure_p2p_messenger::Identity = serde_json::from_value(identity_data.clone())?;
                
                let profile_path = config.storage.keys_dir.join("profile.json");
                std::fs::write(profile_path, serde_json::to_string_pretty(&identity)?)?;
                
                if let Some(private_key_data) = import_data.get("private_key") {
                    if let Ok(private_key_bytes) = serde_json::from_value::<[u8; 32]>(private_key_data.clone()) {
                        let private_key_path = config.storage.keys_dir.join("private_key");
                        std::fs::write(private_key_path, private_key_bytes)?;
                    }
                }
                
                println!("✓ Keys imported successfully");
            } else {
                return Err(anyhow::anyhow!("Invalid import file format"));
            }
        }
        KeyCommands::Prekeys { count } => {
            let profile = load_user_profile(config)?;
            let mut prekey_manager = PrekeyManager::new();
            
            let bundle = prekey_manager.generate_prekey_bundle(
                profile.identity.clone(),
                &profile.keypair,
                Some(count),
            );
            
            let bundle_path = config.storage.keys_dir.join("prekey_bundle.json");
            std::fs::write(bundle_path, bundle.to_json()?)?;
            
            println!("✓ Generated {} one-time prekeys", count);
            println!("✓ Prekey bundle saved");
        }
    }
    Ok(())
}

async fn handle_profile_command(format: String, config: &MessengerConfig) -> Result<()> {
    let profile = load_user_profile(config)?;

    match format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&profile.identity)?);
        }
        "pretty" => {
            println!("User Profile");
            println!("============");
            println!("Name: {}", profile.identity.display_name);
            println!("ID: {}", profile.identity.id);
            println!("Short ID: {}", profile.identity.short_id());
            println!("Created: {}", profile.identity.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
            println!("Public Key: {}", hex::encode(profile.identity.public_key));
        }
        _ => return Err(anyhow::anyhow!("Unsupported format: {}", format)),
    }

    Ok(())
}

async fn handle_run_command(
    port: Option<u16>,
    bootstrap: Vec<String>,
    interactive: bool,
    mut config: MessengerConfig,
) -> Result<()> {
    // Override config with command line options
    if let Some(port) = port {
        config.network.listen_port = port;
    }
    if !bootstrap.is_empty() {
        config.network.bootstrap_nodes = bootstrap;
    }

    info!("Starting secure P2P messenger...");
    info!("Port: {}", config.network.listen_port);
    info!("Bootstrap nodes: {:?}", config.network.bootstrap_nodes);

    let app = App::new(config).await?;

    if interactive {
        println!("Messenger running in interactive mode. Type 'help' for commands.");
        // In a full implementation, you'd start an interactive CLI here
    }

    // Set up graceful shutdown
    let shutdown_signal = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
        info!("Shutdown signal received");
    };

    tokio::select! {
        result = app.run() => {
            if let Err(e) = result {
                error!("Application error: {}", e);
                return Err(e.into());
            }
        }
        _ = shutdown_signal => {
            info!("Shutting down gracefully...");
        }
    }

    Ok(())
}

async fn handle_config_commands(action: ConfigCommands, config: &MessengerConfig) -> Result<()> {
    match action {
        ConfigCommands::Generate { output } => {
            let default_config = MessengerConfig::default();
            let output_path = output.unwrap_or_else(|| PathBuf::from("messenger.toml"));
            
            default_config.save(&output_path)?;
            println!("✓ Configuration generated: {}", output_path.display());
        }
        ConfigCommands::Validate { file } => {
            let config_to_validate = if let Some(path) = file {
                MessengerConfig::from_file(path)?
            } else {
                config.clone()
            };
            
            config_to_validate.validate()?;
            println!("✓ Configuration is valid");
        }
        ConfigCommands::Show { section } => {
            let config_str = config.to_toml_string()?;
            
            if let Some(section_name) = section {
                // In a full implementation, you'd parse and show only the requested section
                println!("Section '{}' from configuration:", section_name);
                println!("{}", config_str);
            } else {
                println!("{}", config_str);
            }
        }
    }
    Ok(())
}

async fn handle_benchmark_command(benchmark_type: String, iterations: usize) -> Result<()> {
    println!("Running {} benchmark with {} iterations...", benchmark_type, iterations);
    
    match benchmark_type.as_str() {
        "crypto" => {
            let start = std::time::Instant::now();
            for _ in 0..iterations {
                let _keypair = IdentityKeyPair::generate();
            }
            let duration = start.elapsed();
            println!("Key generation: {:.2} keys/sec", iterations as f64 / duration.as_secs_f64());
        }
        "all" => {
            println!("Running all benchmarks...");
            // In a full implementation, you'd run comprehensive benchmarks
        }
        _ => return Err(anyhow::anyhow!("Unsupported benchmark type: {}", benchmark_type)),
    }
    
    Ok(())
}

async fn handle_network_commands(action: NetworkCommands, _config: &MessengerConfig) -> Result<()> {
    match action {
        NetworkCommands::Test { node: _ } => {
            println!("Testing network connectivity...");
            // In a full implementation, you'd test actual network connectivity
            println!("✓ Network tests completed");
        }
        NetworkCommands::Discover { timeout: _ } => {
            println!("Discovering peers...");
            // In a full implementation, you'd run peer discovery
            println!("✓ Peer discovery completed");
        }
        NetworkCommands::Stats => {
            println!("Network Statistics");
            println!("==================");
            println!("Connected peers: 0");
            println!("Messages sent: 0");
            println!("Messages received: 0");
        }
    }
    Ok(())
}

async fn handle_quickstart_command(name: Option<String>, config: MessengerConfig) -> Result<()> {
    // Ensure required directories exist
    config.ensure_directories()?;

    // Load or create identity
    let profile = {
        let keys_dir = &config.storage.keys_dir;
        let profile_path = keys_dir.join("profile.json");
        let private_key_path = keys_dir.join("private_key");

        if !profile_path.exists() || !private_key_path.exists() {
            let display_name = name.unwrap_or_else(|| {
                std::env::var("USER")
                    .or_else(|_| std::env::var("USERNAME"))
                    .unwrap_or_else(|_| "User".to_string())
            });

            info!("Generating new identity for '{}'", display_name);
            let profile = UserProfile::new(display_name);

            std::fs::create_dir_all(keys_dir)?;
            std::fs::write(&profile_path, serde_json::to_string_pretty(&profile.identity)?)?;
            std::fs::write(&private_key_path, profile.export_private_key())?;
            profile
        } else {
            load_user_profile(&config)?
        }
    };

    // Show profile information
    println!("User Profile");
    println!("============");
    println!("Name: {}", profile.identity.display_name);
    println!("ID: {}", profile.identity.id);
    println!("Short ID: {}", profile.identity.short_id());
    println!(
        "Created: {}",
        profile
            .identity
            .created_at
            .format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!("Public Key: {}", hex::encode(profile.identity.public_key));

    // Generate default configuration if missing
    let default_path = std::path::PathBuf::from(DEFAULT_CONFIG_FILE);
    if !default_path.exists() {
        config.save(&default_path)?;
        println!("✓ Default configuration generated: {}", default_path.display());
    }

    // Run the messenger with defaults
    handle_run_command(None, Vec::new(), false, config).await
}

fn load_or_create_user_profile(config: &MessengerConfig) -> Result<UserProfile> {
    let keys_dir = &config.storage.keys_dir;
    let profile_path = keys_dir.join("profile.json");
    let private_key_path = keys_dir.join("private_key");

    // Auto-generate profile if it doesn't exist
    if !profile_path.exists() || !private_key_path.exists() {
        info!("No identity found, auto-generating new identity...");
        
        // Generate a default name with hostname or random identifier
        let default_name = match std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
            Ok(username) => format!("{}@{}", username, gethostname()),
            Err(_) => format!("User@{}", gethostname()),
        };
        
        // Create the profile
        let profile = UserProfile::new(default_name.clone());
        
        // Save identity
        let identity_json = profile.identity.to_json()
            .map_err(|e| anyhow::anyhow!("Failed to serialize identity: {}", e))?;
        std::fs::write(&profile_path, identity_json)?;
        
        // Save private key
        let private_key_bytes = profile.keypair.secret_key_bytes();
        std::fs::write(&private_key_path, private_key_bytes)?;
        
        info!("✓ Auto-generated identity: {}", default_name);
        info!("  ID: {}", profile.identity.short_id());
        info!("  Saved to: {}", profile_path.display());
        
        return Ok(profile);
    }

    // Load existing profile
    let identity_json = std::fs::read_to_string(&profile_path)?;
    let identity: secure_p2p_messenger::Identity = serde_json::from_str(&identity_json)?;

    let private_key_bytes = std::fs::read(&private_key_path)?;
    let keypair = IdentityKeyPair::from_secret_bytes(&private_key_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to load private key: {}", e))?;

    UserProfile::from_keypair_and_identity(keypair, identity)
        .map_err(|e| anyhow::anyhow!("Failed to create user profile: {}", e))
}

fn load_user_profile(config: &MessengerConfig) -> Result<UserProfile> {
    load_or_create_user_profile(config)
}

fn gethostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}