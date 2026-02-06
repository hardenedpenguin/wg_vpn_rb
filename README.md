# wg-vpn.rb

A single-file **WireGuard VPN manager** in Ruby. Use it to set up a WireGuard server on Debian and manage clients (add, remove, list, monitor). **wg-vpn-client.rb** is a companion client-side script for Debian: it installs WireGuard, copies your config, and brings up the tunnel.

---

## Requirements

- **Root** (or `sudo`)
- **Debian** (or Debian-based) system
- Packages: **wireguard**, **firewalld**
- Optional: **qrencode** (for QR codes when adding clients, for mobile WireGuard apps)

---

## How It Works

### Paths and defaults

| Item        | Value                    |
|------------|---------------------------|
| Config dir | `/etc/wireguard`          |
| Client configs | `/etc/wireguard/clients/` |
| Server config | `/etc/wireguard/wg0.conf` |
| VPN subnet | `10.8.0.0/24`             |
| Server VPN IP | `10.8.0.1`             |
| Listen port | **51820** (UDP)         |

- Server keys are stored as `server.key` and `server.pub` under `/etc/wireguard`.
- Each client gets the next free IP in `10.8.0.0/24` (e.g. `10.8.0.2`, `10.8.0.3`, …).
- Client configs are written to `/etc/wireguard/clients/<name>.conf` and the corresponding `[Peer]` block is appended to `wg0.conf`.
- Config lines are normalized to WireGuard’s `Key = Value` format (spaces around `=`).
- After changes, the script reloads the server with `systemctl reload wg-quick@wg0` (or a fallback with `wg syncconf`).

### Setup (`setup`)

1. Installs **wireguard**, **firewalld**, **qrencode** via `apt`.
2. Enables IPv4 forwarding (`net.ipv4.ip_forward=1`) and persists it in `/etc/sysctl.d/99-wireguard.conf`.
3. Creates `/etc/wireguard` and `/etc/wireguard/clients`, generates server key pair if missing.
4. Writes or updates `wg0.conf` (keeps existing `[Peer]` blocks).
5. Opens UDP **51820** and enables masquerade in **firewalld**, then reloads firewalld.
6. Enables and starts `wg-quick@wg0`.

You must **forward UDP 51820** from your router to this host for clients to connect.

### Add client (`add-client`)

1. Ensures server keys and dirs exist; normalizes `wg0.conf` if needed.
2. Asks for server endpoint and client name (or uses arguments).
3. Generates a client key pair and assigns the next free IP in `10.8.0.0/24`.
4. Writes the client config to `/etc/wireguard/clients/<name>.conf` (Interface: PrivateKey, Address, DNS; Peer: server PublicKey, Endpoint, AllowedIPs).
5. Appends a `[Peer]` block for this client to `wg0.conf`.
6. Reloads WireGuard. If `qrencode` is installed, prints a QR code for the client config.

### Remove client (`remove-client`)

1. Finds the client config by name and reads the client’s VPN IP.
2. Removes the matching `[Peer]` block from `wg0.conf` and deletes the client config file.
3. Reloads WireGuard.

### Other commands

- **list-clients**: Lists clients (name + VPN IP) from `clients/*.conf` and runs `wg show wg0 latest-handshakes`.
- **show-connected**: Runs `wg show wg0`.
- **monitor**: Runs `watch -n 2 wg show wg0` (or `wg show wg0` if `watch` isn’t available).
- **show-key**: Prints the server public key.

---

## Usage

Run as **root** (e.g. `sudo ./wg-vpn.rb ...`).

### Interactive menu (no arguments)

```bash
sudo ./wg-vpn.rb
```

You get a menu: Add Client, Remove Client, List Clients, Show Connected, Live Monitor, Show Server Public Key, Exit.

### Subcommands

| Command | Description |
|--------|-------------|
| `setup` | Install packages, configure firewall, create server config, start WireGuard |
| `add-client [server_ip] [name] [full]` | Add a client; prompts for server IP and name if omitted. Use `full` (or `y`/`yes`/`1`) to route all traffic through VPN |
| `remove-client [name]` | Remove a client by name |
| `list-clients` | List clients and latest handshakes |
| `show-connected` | Show `wg show wg0` |
| `monitor` | Live view of `wg show wg0` (every 2 s) |
| `show-key` | Print server public key |

### Examples

**First-time server setup**

```bash
sudo ./wg-vpn.rb setup
```

Then on your router: forward **UDP 51820** to this machine’s LAN IP.

**Add a client (interactive)**

```bash
sudo ./wg-vpn.rb add-client
# Enter server public IP or hostname, then client name (e.g. work-laptop)
```

**Add a client (non-interactive)**

```bash
sudo ./wg-vpn.rb add-client 203.0.113.10 my-phone
# Uses server endpoint 203.0.113.10:51820 and client name "my-phone"
```

**Add a client with all traffic through VPN (non-interactive)**

```bash
sudo ./wg-vpn.rb add-client 203.0.113.10 my-phone full
```

**Remove a client**

```bash
sudo ./wg-vpn.rb remove-client my-phone
```

**List clients**

```bash
sudo ./wg-vpn.rb list-clients
```

**Show server public key (e.g. for documentation)**

```bash
sudo ./wg-vpn.rb show-key
```

---

## Client config and usage

- Config file: `/etc/wireguard/clients/<name>.conf`
- Copy it to the client (e.g. laptop, phone) and import into the WireGuard app.
- On add, if `qrencode` is installed, a QR code is printed; mobile apps can scan it.
- Client DNS in the generated config is set to `1.1.1.1`; edit the file if you want a different DNS.
- AllowedIPs in the generated client config are `10.8.0.0/24` only (VPN subnet); add your internal ranges (e.g. `10.10.2.0/24`) in the file if needed.

---

## Client script (Debian)

**wg-vpn-client.rb** is a client-side script for **Debian only**. It installs WireGuard, copies your client config into `/etc/wireguard`, brings up the tunnel, and optionally enables it on boot.

**Requirements:** root, Debian.

**Usage:**

| Command | Description |
|--------|-------------|
| `setup [config_path]` | Install wireguard, copy config to `/etc/wireguard`, bring up tunnel, optionally enable on boot |
| `up [interface]` | Bring up tunnel (default: wg0) |
| `down [interface]` | Bring down tunnel (default: wg0) |
| `status [interface]` | Show `wg show` (default: wg0) |

**Example (first-time setup on a Debian client):**

1. Copy the client `.conf` from the server (e.g. `scp user@10.8.0.1:/etc/wireguard/clients/work-laptop.conf .` once connected to the VPN, or from USB / download).
2. Run:

   ```bash
   sudo ./wg-vpn-client.rb setup ./work-laptop.conf
   ```

   Or run `sudo ./wg-vpn-client.rb setup` and enter the path when prompted.
3. Say **y** when asked to enable on boot if you want the tunnel to start automatically.

The interface name is taken from the config filename (e.g. `work-laptop.conf` → interface `work-laptop`). To bring it down later: `sudo ./wg-vpn-client.rb down work-laptop`.

---

## Port forward (wg-vpn-forward.rb)

**wg-vpn-forward.rb** forwards a port on the VPN server (or any host) to a port on a VPN client. Use it when a service runs on a client (e.g. 10.8.0.2:4569) and you want it reachable via the server (e.g. 10.10.2.3:4569).

On **Debian 13** the script is managed by **systemd**: install once, add forwards to the config, start/stop with `systemctl`. Forwards persist across reboots.

### One-time setup (as root)

```bash
sudo ./wg-vpn-forward.rb install
```

This creates `/etc/systemd/system/wg-vpn-forward.service`, `/etc/wg-vpn-forward.conf`, enables the service, and starts it if any forwards are configured.

### Commands

| Command | Description |
|--------|-------------|
| `install` | Install systemd service and config (run once as root). |
| `add [--bind ADDR] [--udp] PORT TARGET_IP [TARGET_PORT]` | Add a TCP or UDP forward and restart the service. |
| `remove [--udp] PORT TARGET_IP [TARGET_PORT]` | Remove a forward (use `--udp` to remove only the UDP entry). |
| `list` | Show configured forwards. |

### Config file

`/etc/wg-vpn-forward.conf` — one forward per line:

```text
[udp] PORT TARGET_IP [TARGET_PORT]
```

Optional: `--bind ADDR` at the start of a line to bind to a specific address; `udp` for UDP (default is TCP).

### Examples

```bash
# One-time install (as root)
sudo ./wg-vpn-forward.rb install

# Add forwards (as root)
sudo ./wg-vpn-forward.rb add 4569 10.8.0.2
sudo ./wg-vpn-forward.rb add --udp 4569 10.8.0.2
sudo ./wg-vpn-forward.rb add --bind 10.10.2.3 4569 10.8.0.2
sudo ./wg-vpn-forward.rb add 8080 10.8.0.2 80

# List forwards
./wg-vpn-forward.rb list

# Remove a forward (use --udp to remove only the UDP entry)
sudo ./wg-vpn-forward.rb remove 4569 10.8.0.2
sudo ./wg-vpn-forward.rb remove --udp 4569 10.8.0.2

# Manage service
sudo systemctl start|stop|restart|status wg-vpn-forward
```

### One-off run (no systemd)

For a quick test without installing the service:

```bash
./wg-vpn-forward.rb 4569 10.8.0.2
./wg-vpn-forward.rb --udp 4569 10.8.0.2
./wg-vpn-forward.rb --bind 10.10.2.3 4569 10.8.0.2
./wg-vpn-forward.rb 8080 10.8.0.2 80
```

Press Ctrl+C to stop. Root is only needed for ports &lt; 1024.

---

## Quick reference

```text
Usage: wg-vpn.rb [ setup | add-client [server_ip] [name] [full] | remove-client [name] | list-clients | show-connected | monitor | show-key ]
  No args: interactive menu.
```

- **Server**: Debian, root, wireguard + firewalld (+ qrencode for QR).
- **After setup**: Forward UDP 51820 to the server.
- **Clients**: Use the `.conf` (or QR) from `add-client` in the WireGuard app.
