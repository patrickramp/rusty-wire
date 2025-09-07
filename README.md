# rusty-wire

Simple Rust application for creating Wireguard configs with QR code support.

## Installation

```bash
# Build from source
git clone <repo>
cd rusty-wire
cargo build --release

# Install globally
cargo install --path .

# With QR code support
cargo install --path . --features qr
```

## Initial Setup

```bash
# Initialize WireGuard server
rusty-wire init --endpoint your.server.ip.com --port 51820 --network 10.0.0.0/24 --interface eth0

# Custom network/port
rusty-wire init -e example.com -p 51821 -n 192.168.100.0/24 -i enp0s3

# Output to specific directory
rusty-wire init -e your.server.ip -o /etc/wireguard
```

**Generated files:**
- `wg0.conf` - Server WireGuard config
- `wg-server.json` - State file (don't delete!)

## Client Management

### Add Clients

```bash
# Basic client (auto-assigned IP)
rusty-wire client homelab

# Client with custom IP
rusty-wire client laptop --ip 10.0.0.100

# Full tunnel client (routes ALL traffic through VPN)
rusty-wire client phone --full-tunnel

# With QR code for mobile import
rusty-wire client phone --qr --full-tunnel

# Output to specific directory
rusty-wire client homelab -o /etc/wireguard
```

### Manage Clients

```bash
# List all clients
rusty-wire list

# Show server configuration
rusty-wire show

# Revoke a client
rusty-wire revoke phone

# Revoke with verbose output
rusty-wire revoke laptop --verbose
```

## File Structure

```
./
├── wg0.conf           # Server config (copy to server)
├── wg-server.json     # State file (keep safe!)
├── homelab.conf       # Client configs
├── phone.conf
└── laptop.conf
```

## Deployment Workflow

### 1. Server Setup (One-time)

```bash
# On your local machine
rusty-wire init --endpoint your.server.ip

# Copy server config to server
scp wg0.conf user@your.server.ip:/etc/wireguard/

# On server
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0

# Check status
sudo wg show
```

### 2. Add Home Lab

```bash
# Generate homelab client
rusty-wire client homelab

# Copy to homelab server
scp homelab.conf user@homelab:/etc/wireguard/wg0.conf

# On homelab
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0

# Verify connection
ping 10.0.0.1  # Should reach server
```

### 3. Add Mobile Device

```bash
# Generate with QR code
rusty-wire client phone --qr --full-tunnel

# Scan QR with WireGuard mobile app
# Or transfer phone.conf manually
```

## Common Patterns

### Quick Setup Script

```bash
#!/bin/bash
# setup-vpn.sh
server_IP="your.server.ip"

rusty-wire init --endpoint $SERVER_IP
rusty-wire client homelab
rusty-wire client phone --full-tunnel --qr

echo "✓ Configs generated!"
echo "Copy wg0.conf to server: scp wg0.conf user@$SERVER_IP:/etc/wireguard/"
echo "Copy homelab.conf to homelab: scp homelab.conf user@homelab:/etc/wireguard/wg0.conf"
```

### Batch Client Addition

```bash
# Add multiple clients
for client in homelab phone laptop desktop; do
    rusty-wire client $client
done
```

### Update Existing Setup

```bash
# Add new client to existing setup
rusty-wire client new-device --ip 10.0.0.50

# Copy updated server config to server
scp wg0.conf user@server:/etc/wireguard/
ssh user@server 'sudo systemctl reload wg-quick@wg0'
```

## Troubleshooting

### Check Generated Configs

```bash
# View server config
cat wg0.conf

# View client config
cat homelab.conf

# Check state
cat wg-server.json | jq '.'
```

### Common Issues

```bash
# "Server already initialized"
rm wg-server.json  # Only if you want to start over!

# "Client already exists"
rusty-wire revoke old-client
rusty-wire client new-client

# Wrong IP assignment
rusty-wire client device --ip 10.0.0.custom
```

### Verify Setup

```bash
# On server
sudo wg show
sudo ss -tulpn | grep 51820

# Test connectivity from client
ping 10.0.0.1  # server WireGuard IP
curl ifconfig.me  # Should show server IP if full-tunnel
```

## Advanced Usage

### Custom Networks

```bash
# Different network ranges
rusty-wire init -e server.com -n 172.16.0.0/24    # 172.16.0.x
rusty-wire init -e server.com -n 192.168.99.0/24  # 192.168.99.x
```

### Multiple Servers

```bash
# Organize by purpose
mkdir vpn-home && cd vpn-home
rusty-wire init -e home.server.ip -n 10.1.0.0/24

mkdir vpn-work && cd vpn-work  
rusty-wire init -e work.server.ip -n 10.2.0.0/24 -p 51821
```

### Integration with Systemd

```bash
# Auto-start on boot
sudo cp homelab.conf /etc/wireguard/wg0.conf
sudo systemctl enable wg-quick@wg0

# Custom service name
sudo cp homelab.conf /etc/wireguard/homelab.conf
sudo systemctl enable wg-quick@homelab
```

## Pro Tips

- **Keep `wg-server.json`** - It's your state file, back it up!
- **Use `--verbose`** for debugging
- **QR codes work great** for mobile devices
- **Full tunnel mode** routes all traffic (good for phones, careful with servers)
- **Custom IPs** useful for static assignments
- **Always test connectivity** after setup