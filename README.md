# wg-vpn.rb

A single-file **WireGuard VPN manager** in Ruby. Use it to set up a WireGuard server on Debian and manage clients. **wg-vpn-client.rb** is a companion client-side script for Debian: it installs WireGuard, copies your config, and brings up the tunnel.

---

## How It Works

### Paths and defaults

| Item           | Value                      |
|----------------|----------------------------|
| Config dir     | `/etc/wireguard`           |
| Client configs | `/etc/wireguard/clients/`  |
| Server config  | `/etc/wireguard/wg0.conf`  |
| VPN subnet     | `10.8.0.0/24`              |
| Server VPN IP  | `10.8.0.1`                 |
| Listen port    | **51820** (UDP)            |
| MTU            | **1420** (needed for IAX2) |

- Server keys are stored as `server.key` and `server.pub` under `/etc/wireguard`.
- Each client gets the next free IP in `10.8.0.0/24` (e.g. `10.8.0.2`, `10.8.0.3`, …).
- Client configs are written to `/etc/wireguard/clients/<name>.conf` and the corresponding `[Peer]` block is appended to `wg0.conf`.
- Clients include `PersistentKeepalive = 25` (required for CGNAT) and `MTU = 1420`.

### Setup (`setup`)

1. Installs **wireguard**, **firewalld**, **resolvconf**, **qrencode** via `apt`.
2. Enables IPv4 forwarding (`net.ipv4.ip_forward=1`) in `/etc/sysctl.d/99-wireguard.conf`.
3. Creates `/etc/wireguard` and `/etc/wireguard/clients`, generates server key pair if missing.
4. Writes initial `wg0.conf` with `MTU = 1420` if it does not exist.
5. Configures firewalld:
   - Uses the **default zone** (e.g. `public` or `allstarlink`).
   - Opens UDP **51820**.
   - Adds `wg0` to the zone.
   - **No zone masquerade** — port-forwards preserve source IP for ASL3.
   - Targeted masquerade: only VPN→internet traffic is SNAT'd.
   - FORWARD rules for wg0 ↔ WAN (physical→virtual forwarding allowed).
6. Enables and starts `wg-quick@wg0`.

You must **forward UDP 51820** from your router to this host for clients to connect.

### Add client (`add-client`)

1. Prompts for client name.
2. Generates a client key pair and assigns the next free IP in `10.8.0.0/24`.
3. Writes the client config: Address, DNS (`1.1.1.1`), MTU (1420), Peer with Endpoint (server public IP via `curl ifconfig.me`), AllowedIPs (`10.8.0.0/24`), PersistentKeepalive (25).
4. Appends a `[Peer]` block to `wg0.conf`.
5. Reloads WireGuard. If `qrencode` is installed, prints a QR code.

### Port forward (`forward`)

Forwards a port on the server’s WAN interface to a VPN client. **Preserves source IP** so services like AllStar Link (ASL3) see the real peer address.

1. Adds a forward-port (DNAT) to the default zone.
2. Adds a direct FORWARD rule so physical→virtual traffic is allowed.

---

## Usage

Run as **root** (e.g. `sudo ./wg-vpn.rb ...`).

### Interactive menu

Run with no arguments for a menu:

```bash
sudo ./wg-vpn.rb
```

The menu prompts for each action. For port forwarding, it lists existing clients and asks for port, internal IP (with default), and protocol.

### Commands (non-interactive)

| Command   | Description |
|-----------|-------------|
| `setup`   | Install packages, configure firewall, create server config, start WireGuard |
| `add-client` | Add a client; prompts for name |
| `forward [PORT] [INTERNAL_IP] [proto]` | Port forward. With args: direct. Without args: interactive prompts. |
| `status`  | Show `wg show` |

### Examples

**First-time server setup**

```bash
sudo ./wg-vpn.rb setup
```

Then on your router: forward **UDP 51820** to this machine’s LAN IP.

**Add a client**

```bash
sudo ./wg-vpn.rb add-client
# Enter client name (e.g., node1, portable2)
```

**Port forward for ASL3 (IAX2 on 4570)**

```bash
sudo ./wg-vpn.rb forward 4570 10.8.0.4 udp
# Forward UDP 4570 to VPN client 10.8.0.4
```

On your router, also forward **UDP 4570** to the server so external nodes can reach the AllStar node.

**Show status**

```bash
sudo ./wg-vpn.rb status
```

---

## Client config and usage

- Config file: `/etc/wireguard/clients/<name>.conf`
- Copy it to the client and import into the WireGuard app.
- On add, if `qrencode` is installed, a QR code is printed; mobile apps can scan it.
- Client DNS is `1.1.1.1`; edit the file to change it.
- AllowedIPs is `10.8.0.0/24` (VPN subnet).

---

## Client script (Debian)

**wg-vpn-client.rb** is a client-side script for **Debian**. It installs WireGuard, copies your client config into `/etc/wireguard`, removes the source file (so only the secured copy remains), brings up the tunnel, and optionally enables it on boot.

**Requirements:** root, Debian.

**Commands:**

| Command           | Description |
|-------------------|-------------|
| `setup [path]`    | Install WireGuard, copy config to `/etc/wireguard` (source removed), bring up tunnel, optionally enable on boot |
| `up [interface]`  | Bring up tunnel (auto-detect interface if single config) |
| `down [interface]`| Bring down tunnel |
| `status [interface]` | Show `wg show` |
| `enable-boot [interface]` | Enable tunnel on boot |
| `disable-boot [interface]` | Disable tunnel on boot |

**Example (first-time setup on a Debian client):**

1. Copy the client `.conf` from the server (e.g. `scp user@server:/etc/wireguard/clients/node1.conf .`).
2. Run:

   ```bash
   sudo ./wg-vpn-client.rb setup ./node1.conf
   ```

   Or run `sudo ./wg-vpn-client.rb setup` and enter the path when prompted. The source file is removed after copying; only the copy in `/etc/wireguard` is kept.
3. Say **y** when asked to enable on boot if you want the tunnel to start automatically.

The interface name is derived from the config filename (e.g. `node1.conf` → interface `node1`). With one config in `/etc/wireguard`, `up`, `down`, `status`, `enable-boot`, and `disable-boot` auto-detect the interface.

---

## Quick reference

**Server (wg-vpn.rb):**

```text
sudo ./wg-vpn.rb              # Menu
sudo ./wg-vpn.rb setup
sudo ./wg-vpn.rb add-client
sudo ./wg-vpn.rb forward      # Interactive
sudo ./wg-vpn.rb forward 4570 10.8.0.4 udp
sudo ./wg-vpn.rb status
```

**Client (wg-vpn-client.rb):**

```text
sudo ./wg-vpn-client.rb setup ./node1.conf
sudo ./wg-vpn-client.rb up
sudo ./wg-vpn-client.rb down
sudo ./wg-vpn-client.rb status
sudo ./wg-vpn-client.rb enable-boot
sudo ./wg-vpn-client.rb disable-boot
```

- **Server**: Debian, root, wireguard + firewalld + resolvconf (+ qrencode for QR).
- **After setup**: Forward UDP 51820 (and any forwarded ports like 4570) to the server.
- **Clients**: Use the `.conf` (or QR) from `add-client`. Run `wg-vpn-client.rb setup` on the client; the source config is removed after copying.
