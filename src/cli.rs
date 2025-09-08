use clap::{Parser, Subcommand};
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rusty-wire")]
#[command(about = "A WireGuard configuration generator")]
#[command(long_about = "Generate WireGuard server and client configurations with proper key management")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    
    /// Output directory for configurations
    #[arg(short, long, default_value = ".")]
    pub output: PathBuf,
    
    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new WireGuard server
    Init {
        /// Server endpoint (public IP or domain)
        #[arg(short, long)]
        endpoint: String,
        
        /// Server listen port
        #[arg(short, long, default_value = "51820")]
        port: u16,
        
        /// Network subnet (e.g., 10.0.0.0/24)
        #[arg(short, long, default_value = "10.0.0.0/24")]
        network: String,
        
        /// Network interface for NAT (e.g., eth0)
        #[arg(short, long, default_value = "eth0")]
        interface: String,
    },
    
    /// Add a new client configuration
    Client {
        /// Client name
        name: String,
        
        /// Custom client IP (auto-assigned if not specified)
        #[arg(short, long)]
        ip: Option<IpAddr>,
        
        /// Generate QR code for mobile clients
        #[cfg(feature = "qr")]
        #[arg(short, long)]
        qr: bool,
        
        /// Allow all traffic through VPN (0.0.0.0/0)
        #[arg(short, long)]
        full_tunnel: bool,
    },
    
    /// List all clients
    List,
    
    /// Revoke a client
    Revoke {
        /// Client name to revoke
        name: String,
    },
    
    /// Show server configuration
    Show,
}
