use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Commands};
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;

mod cli;
mod config;
mod crypto;

use config::{ClientConfig, ServerConfig, WireGuardConfig};

fn main() -> Result<()> {
    // Parse CLI arguments
    let cli = Cli::parse();
    match cli.command {
        Commands::Init {
            endpoint,
            port,
            network,
            interface,
        } => init_server(
            &cli.output,
            &endpoint,
            port,
            &network,
            &interface,
            cli.verbose,
        ),
        Commands::Client {
            name,
            ip,
            full_tunnel,
            #[cfg(feature = "qr")]
            qr,
        } => add_client(
            &cli.output,
            &name,
            ip,
            full_tunnel,
            #[cfg(feature = "qr")]
            qr,
            cli.verbose,
        ),
        Commands::List => list_clients(&cli.output),
        Commands::Revoke { name } => revoke_client(&cli.output, &name, cli.verbose),
        Commands::Show => show_server(&cli.output),
    }
}

/// Initialize a new WireGuard server
fn init_server(
    output_dir: &PathBuf,
    endpoint: &str,
    port: u16,
    network: &str,
    interface: &str,
    verbose: bool,
) -> Result<()> {
    // Check if server is already initialized
    let config_path = output_dir.join("wg-server.json");
    if config_path.exists() {
        anyhow::bail!("Server already initialized. Use 'rusty-wire show' to view configuration.");
    }

    // Generate server keypair and configuration
    let server_keys = crypto::generate_keypair()?;
    let server_config = ServerConfig::new(
        endpoint.to_string(),
        port,
        network.to_string(),
        interface.to_string(),
        server_keys,
    )?;

    // Save server config as JSON for state management
    let json = serde_json::to_string_pretty(&server_config)?;
    fs::write(&config_path, json)
        .with_context(|| format!("Failed to write server config to {:?}", config_path))?;

    // Generate the actual WireGuard config file
    let wg_config = server_config.to_wireguard_config()?;
    let wg_config_path = output_dir.join("wg0.conf");
    fs::write(&wg_config_path, wg_config)
        .with_context(|| format!("Failed to write WireGuard config to {:?}", wg_config_path))?;

    if verbose {
        println!("Server initialized:");
        println!("  Endpoint: {}:{}", endpoint, port);
        println!("  Network: {}", network);
        println!("  Interface: {}", interface);
        println!("  Config: {:?}", wg_config_path);
    } else {
        println!("✓ Server initialized at {:?}", wg_config_path);
    }

    Ok(())
}

/// Add a new client
fn add_client(
    output_dir: &PathBuf,
    name: &str,
    custom_ip: Option<IpAddr>,
    full_tunnel: bool,
    #[cfg(feature = "qr")] qr: bool,
    verbose: bool,
) -> Result<()> {
    // Load server config
    let config_path = output_dir.join("wg-server.json");
    if !config_path.exists() {
        anyhow::bail!("No server configuration found. Run 'rusty-wire init' first.");
    }
    let config_data = fs::read_to_string(&config_path)?;
    let mut server_config: ServerConfig = serde_json::from_str(&config_data)?;

    // Check if client already exists
    if server_config.clients.iter().any(|c| c.name == name) {
        anyhow::bail!("Client '{}' already exists", name);
    }

    // Generate client keypair
    let client_keys = crypto::generate_keypair()?;
    let client_ip = custom_ip.unwrap_or_else(|| server_config.next_client_ip());

    // Generate client config
    let allowed_ips = if full_tunnel {
        "0.0.0.0/0".to_string()
    } else {
        server_config.network.clone()
    };

    let client_config = ClientConfig::new(
        name.to_string(),
        client_ip,
        client_keys,
        server_config.endpoint.clone(),
        server_config.port,
        server_config.keys.public.clone(),
        allowed_ips,
    );

    // Add client to server config
    server_config.add_client(&client_config)?;

    // Save updated server config
    let json = serde_json::to_string_pretty(&server_config)?;
    fs::write(&config_path, json)?;

    // Regenerate server WireGuard config
    let wg_config = server_config.to_wireguard_config()?;
    fs::write(output_dir.join("wg0.conf"), wg_config)?;

    // Generate client config file
    let client_wg_config = client_config.to_wireguard_config()?;
    let client_config_path = output_dir.join(format!("{}.conf", name));
    fs::write(&client_config_path, &client_wg_config)?;

    if verbose {
        println!("Client '{}' added:", name);
        println!("  IP: {}", client_ip);
        println!("  Config: {:?}", client_config_path);
        if full_tunnel {
            println!("  Mode: Full tunnel (all traffic)");
        }
    } else {
        println!("✓ Client '{}' added at {:?}", name, client_config_path);
    }

    #[cfg(feature = "qr")]
    if qr {
        println!("\nQR Code for mobile import:");
        if let Err(e) = qr2term::print_qr(&client_wg_config) {
            eprintln!("Failed to generate QR code: {}", e);
        }
    }

    Ok(())
}

/// List configured clients
fn list_clients(output_dir: &PathBuf) -> Result<()> {
    // Load server config
    let config_path = output_dir.join("wg-server.json");
    if !config_path.exists() {
        anyhow::bail!("No server configuration found. Run 'rusty-wire init' first.");
    }
    let config_data = fs::read_to_string(&config_path)?;
    let server_config: ServerConfig = serde_json::from_str(&config_data)?;
    if server_config.clients.is_empty() {
        println!("No clients configured.");
        return Ok(());
    }

    // List configured clients
    println!("Configured clients:");
    for client in &server_config.clients {
        println!("  {} - {}", client.name, client.ip);
    }

    Ok(())
}

/// Revoke a client and remove their configuration
fn revoke_client(output_dir: &PathBuf, name: &str, verbose: bool) -> Result<()> {
    // Load server config
    let config_path = output_dir.join("wg-server.json");
    if !config_path.exists() {
        anyhow::bail!("No server configuration found. Run 'rusty-wire init' first.");
    }
    let config_data = fs::read_to_string(&config_path)?;
    let mut server_config: ServerConfig = serde_json::from_str(&config_data)?;

    // Remove client from server config if found
    if server_config.remove_client(name)? {
        // Save updated server config
        let json = serde_json::to_string_pretty(&server_config)?;
        fs::write(&config_path, json)?;

        // Regenerate server WireGuard config
        let wg_config = server_config.to_wireguard_config()?;
        fs::write(output_dir.join("wg0.conf"), wg_config)?;

        // Remove client config file
        let client_config_path = output_dir.join(format!("{}.conf", name));
        if client_config_path.exists() {
            fs::remove_file(&client_config_path)?;
            if verbose {
                println!("Removed client config: {:?}", client_config_path);
            }
        }

        println!("✓ Client '{}' revoked", name);
    } else {
        anyhow::bail!("Client '{}' not found", name);
    }

    Ok(())
}

/// Show server configuration
fn show_server(output_dir: &PathBuf) -> Result<()> {
    // Load server config
    let config_path = output_dir.join("wg-server.json");
    if !config_path.exists() {
        anyhow::bail!("No server configuration found. Run 'rusty-wire init' first.");
    }
    let config_data = fs::read_to_string(&config_path)?;
    let server_config: ServerConfig = serde_json::from_str(&config_data)?;

    // Print server config
    println!("Server Configuration:");
    println!(
        "  Endpoint: {}:{}",
        server_config.endpoint, server_config.port
    );
    println!("  Network: {}", server_config.network);
    println!("  Interface: {}", server_config.interface);
    println!("  Public Key: {}", server_config.keys.public);
    println!("  Clients: {}", server_config.clients.len());

    let wg_config_path = output_dir.join("wg0.conf");
    if wg_config_path.exists() {
        println!("  WireGuard Config: {:?}", wg_config_path);
    }

    Ok(())
}
