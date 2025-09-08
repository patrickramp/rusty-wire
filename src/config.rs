use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use crate::crypto::KeyPair;

pub trait WireGuardConfig {
    fn to_wireguard_config(&self) -> Result<String>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub endpoint: String,
    pub port: u16,
    pub network: String,
    pub interface: String,
    pub keys: KeyPair,
    pub clients: Vec<ClientConfig>,
    next_ip: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub name: String,
    pub ip: IpAddr,
    pub keys: KeyPair,
    pub server_endpoint: String,
    pub server_port: u16,
    pub server_public_key: String,
    pub allowed_ips: String,
}

impl ServerConfig {
    pub fn new(
        endpoint: String,
        port: u16,
        network: String,
        interface: String,
        keys: KeyPair,
    ) -> Result<Self> {
        // Parse network to get base IP for client assignment
        let base_ip = Self::parse_network_base(&network)?;
        
        Ok(Self {
            endpoint,
            port,
            network,
            interface,
            keys,
            clients: Vec::new(),
            next_ip: u32::from(base_ip) + 2, // Start from .2 (server is typically .1)
        })
    }
    
    pub fn add_client(&mut self, client: &ClientConfig) -> Result<()> {
        if self.clients.iter().any(|c| c.name == client.name) {
            anyhow::bail!("Client '{}' already exists", client.name);
        }
        self.clients.push(client.clone());
        Ok(())
    }
    
    pub fn remove_client(&mut self, name: &str) -> Result<bool> {
        let initial_len = self.clients.len();
        self.clients.retain(|c| c.name != name);
        Ok(self.clients.len() < initial_len)
    }
    
    pub fn next_client_ip(&mut self) -> IpAddr {
        let ip = Ipv4Addr::from(self.next_ip);
        self.next_ip += 1;
        IpAddr::V4(ip)
    }
    
    fn parse_network_base(network: &str) -> Result<Ipv4Addr> {
        let parts: Vec<&str> = network.split('/').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid network format. Expected CIDR notation (e.g., 10.0.0.0/24)");
        }
        
        Ipv4Addr::from_str(parts[0])
            .with_context(|| format!("Invalid IP address in network: {}", parts[0]))
    }
    
    fn server_ip_with_cidr(&self) -> Result<String> {
        let parts: Vec<&str> = self.network.split('/').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid network format. Expected CIDR notation (e.g., 10.0.0.0/24)");
        }
        
        let base_ip = Self::parse_network_base(&self.network)?;
        let server_ip = Ipv4Addr::from(u32::from(base_ip) + 1);
        Ok(format!("{}/{}", server_ip, parts[1]))
    }
}

impl WireGuardConfig for ServerConfig {
    fn to_wireguard_config(&self) -> Result<String> {
        let server_address = self.server_ip_with_cidr()?;
        
        let mut config = format!(
            "[Interface]\n\
             PrivateKey = {}\n\
             Address = {}\n\
             ListenPort = {}\n\n\
             PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -j MASQUERADE\n\n\
             PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -j MASQUERADE\n",
            self.keys.private,
            server_address,
            self.port,
            //self.interface,
            //self.interface
        );
        
        for client in &self.clients {
            config.push_str(&format!(
                "\n[Peer]\n\
                 PublicKey = {}\n\
                 AllowedIPs = {}/32\n",
                client.keys.public,
                client.ip
            ));
        }
        
        Ok(config)
    }
}

impl ClientConfig {
    pub fn new(
        name: String,
        ip: IpAddr,
        keys: KeyPair,
        server_endpoint: String,
        server_port: u16,
        server_public_key: String,
        allowed_ips: String,
    ) -> Self {
        Self {
            name,
            ip,
            keys,
            server_endpoint,
            server_port,
            server_public_key,
            allowed_ips,
        }
    }
}

impl WireGuardConfig for ClientConfig {
    fn to_wireguard_config(&self) -> Result<String> {
        Ok(format!(
            "[Interface]\n\
             PrivateKey = {}\n\
             Address = {}/32\n\
             DNS = 1.1.1.1, 9.9.9.9\n\
             \n\
             [Peer]\n\
             PublicKey = {}\n\
             Endpoint = {}:{}\n\
             AllowedIPs = {}\n\
             PersistentKeepalive = 25\n",
            self.keys.private,
            self.ip,
            self.server_public_key,
            self.server_endpoint,
            self.server_port,
            self.allowed_ips
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;
    
    #[test]
    fn test_server_config_creation() {
        let keys = generate_keypair().unwrap();
        let server = ServerConfig::new(
            "example.com".to_string(),
            51820,
            "10.0.0.0/24".to_string(),
            "eth0".to_string(),
            keys,
        ).unwrap();
        
        assert_eq!(server.endpoint, "example.com");
        assert_eq!(server.port, 51820);
        assert_eq!(server.network, "10.0.0.0/24");
        assert!(server.clients.is_empty());
    }
    
    #[test]
    fn test_next_client_ip() {
        let keys = generate_keypair().unwrap();
        let mut server = ServerConfig::new(
            "example.com".to_string(),
            51820,
            "10.0.0.0/24".to_string(),
            "eth0".to_string(),
            keys,
        ).unwrap();
        
        let ip1 = server.next_client_ip();
        let ip2 = server.next_client_ip();
        
        assert_eq!(ip1.to_string(), "10.0.0.2");
        assert_eq!(ip2.to_string(), "10.0.0.3");
    }
    
    #[test]
    fn test_wireguard_config_generation() {
        let keys = generate_keypair().unwrap();
        let server = ServerConfig::new(
            "example.com".to_string(),
            51820,
            "10.0.0.0/24".to_string(),
            "eth0".to_string(),
            keys,
        ).unwrap();
        
        let config = server.to_wireguard_config().unwrap();
        
        assert!(config.contains("[Interface]"));
        assert!(config.contains("PrivateKey ="));
        assert!(config.contains("Address = 10.0.0.1/24"));  // Should have CIDR notation
        assert!(config.contains("ListenPort = 51820"));
        assert!(config.contains("iptables"));
    }
    
    #[test]
    fn test_server_ip_with_cidr() {
        let keys = generate_keypair().unwrap();
        let server = ServerConfig::new(
            "example.com".to_string(),
            51820,
            "10.0.0.0/24".to_string(),
            "eth0".to_string(),
            keys,
        ).unwrap();
        
        let server_ip = server.server_ip_with_cidr().unwrap();
        assert_eq!(server_ip, "10.0.0.1/24");
    }
}