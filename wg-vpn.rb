#!/usr/bin/env ruby
# frozen_string_literal: true

require 'fileutils'
require 'open3'
require 'tempfile'

# --- Configuration ---
WG_DIR = '/etc/wireguard'
WG_CLIENTS = File.join(WG_DIR, 'clients')
WG_CONF = File.join(WG_DIR, 'wg0.conf')
SERVER_KEY = File.join(WG_DIR, 'server.key')
SERVER_PUB = File.join(WG_DIR, 'server.pub')
VPN_SUBNET = '10.8.0.0/24'
VPN_SERVER_IP = '10.8.0.1'
WG_PORT = 51820
CLIENT_DNS = '1.1.1.1'
DEFAULT_MTU = 1420
# Use default zone (e.g. public or allstarlink) - wg0 gets added to it
def get_fw_zone
  capture('firewall-cmd', '--get-default-zone')
end

# --- Helper Methods ---

def run(*cmd)
  system(*cmd) || (raise "Command failed: #{cmd.join(' ')}")
end

def capture(*cmd)
  out, err, status = Open3.capture3(*cmd)
  raise "Command failed: #{cmd.join(' ')}: #{err}" unless status.success?
  out.strip
end

def get_wan_interface
  # Automatically finds the interface used for the default gateway
  capture("ip route show default | awk '/default/ {print $5}'").split("\n").first
end

def root_check
  return if Process.uid == 0
  abort 'Error: This script must be run as root (sudo).'
end

def apply_wg_config
  if capture('wg', 'show', 'interfaces').include?('wg0')
    puts "Syncing WireGuard configuration..."
    Tempfile.open('wg_sync') do |f|
      f.write(capture('wg-quick', 'strip', WG_CONF))
      f.flush
      run('wg', 'syncconf', 'wg0', f.path)
    end
  else
    run('systemctl', 'restart', 'wg-quick@wg0')
  end
end

# --- Core Logic ---

def setup_server
  root_check
  wan = get_wan_interface
  puts "Detected WAN Interface: #{wan}"

  puts 'Installing WireGuard and Firewalld...'
  run('apt-get', 'update')
  run('apt-get', 'install', '-y', 'wireguard', 'firewalld', 'qrencode')

  # Enable IP Forwarding
  File.open('/etc/sysctl.d/99-wireguard.conf', 'w') { |f| f.puts "net.ipv4.ip_forward=1" }
  run('sysctl', '-p', '/etc/sysctl.d/99-wireguard.conf')

  FileUtils.mkdir_p(WG_CLIENTS, mode: 0o700)
  
  # Keys
  unless File.file?(SERVER_KEY)
    priv = capture('wg', 'genkey')
    File.open(SERVER_KEY, 'w', 0o600) { |f| f.write(priv) }
    File.open(SERVER_PUB, 'w', 0o600) { |f| f.write(capture('wg', 'pubkey', stdin_data: priv)) }
  end

  # Initial Config
  unless File.file?(WG_CONF)
    conf = <<~CONF
      [Interface]
      Address = #{VPN_SERVER_IP}/24
      ListenPort = #{WG_PORT}
      PrivateKey = #{File.read(SERVER_KEY).strip}
      MTU = #{DEFAULT_MTU}
    CONF
    File.open(WG_CONF, 'w', 0o600) { |f| f.write(conf) }
  end

  # Firewalld Configuration for ASL3
  puts "Configuring Firewall..."
  run('systemctl', 'enable', '--now', 'firewalld')
  zone = get_fw_zone
  puts "Using zone: #{zone}"

  # 1. Allow WireGuard Port
  run('firewall-cmd', '--permanent', '--add-port', "#{WG_PORT}/udp")

  # 2. Put wg0 into the default zone
  run('firewall-cmd', '--permanent', "--zone=#{zone}", '--add-interface=wg0')

  # 3. NO zone masquerade - it would SNAT port-forwards (replace real IP with 10.8.0.1).
  #    Traffic to wg0: never SNAT (preserve source for Asterisk).
  run('firewall-cmd', '--permanent', '--direct', '--add-rule', 'ipv4', 'nat', 'POSTROUTING', '0',
      '-o', 'wg0', '-j', 'ACCEPT')
  #    Traffic from VPN clients to internet: SNAT.
  run('firewall-cmd', '--permanent', '--direct', '--add-rule', 'ipv4', 'nat', 'POSTROUTING', '0',
      '-s', VPN_SUBNET, '-o', wan, '-j', 'MASQUERADE')

  # 4. FORWARD chain: firewalld drops physical->virtual by default. Must explicitly allow.
  run('firewall-cmd', '--permanent', '--direct', '--add-rule', 'ipv4', 'filter', 'FORWARD', '0', '-i', 'wg0', '-o', wan, '-j', 'ACCEPT')
  run('firewall-cmd', '--permanent', '--direct', '--add-rule', 'ipv4', 'filter', 'FORWARD', '0', '-i', wan, '-o', 'wg0', '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT')
  # add_port_forward adds per-port rule for NEW connections (wan->wg0)

  run('firewall-cmd', '--reload')
  run('systemctl', 'enable', '--now', 'wg-quick@wg0')
  puts "Server Setup Complete."
end

def add_port_forward(ext_port, internal_ip, proto = 'udp')
  root_check
  wan = get_wan_interface
  zone = get_fw_zone
  proto = proto.downcase

  puts "Forwarding #{wan}:#{ext_port} -> #{internal_ip}:#{ext_port} (#{proto})"

  # DNAT via forward-port
  run('firewall-cmd', '--permanent', "--zone=#{zone}", '--add-forward-port',
      "port=#{ext_port}:proto=#{proto}:toport=#{ext_port}:toaddr=#{internal_ip}")
  
  # Crucial: Ensure the forward is allowed in the filter table
  run('firewall-cmd', '--permanent', '--direct', '--add-rule', 'ipv4', 'filter', 'FORWARD', '0', 
      '-d', internal_ip, '-p', proto, '--dport', ext_port.to_s, '-j', 'ACCEPT')
  
  run('firewall-cmd', '--reload')
  puts "Success. Note: ASL3 client MUST have 'PersistentKeepalive = 25' in its config."
end

def add_client
  root_check
  print "Client Name (e.g., node1): "
  name = gets.strip.gsub(/\s+/, '-')
  
  # Find next IP
  used_ips = File.read(WG_CONF).scan(/10\.8\.0\.(\d+)/).flatten.map(&:to_i)
  next_ip = "10.8.0.#{(2..254).find { |i| !used_ips.include?(i) }}"

  client_priv = capture('wg', 'genkey')
  client_pub = capture('wg', 'pubkey', stdin_data: client_priv)
  server_pub = File.read(SERVER_PUB).strip
  endpoint = "#{capture('curl', '-s', 'ifconfig.me')}:#{WG_PORT}"

  # Client File
  client_conf = <<~CONF
    [Interface]
    PrivateKey = #{client_priv}
    Address = #{next_ip}/24
    DNS = #{CLIENT_DNS}
    MTU = #{DEFAULT_MTU}

    [Peer]
    PublicKey = #{server_pub}
    Endpoint = #{endpoint}
    AllowedIPs = #{VPN_SUBNET}
    PersistentKeepalive = 25
  CONF

  conf_path = File.join(WG_CLIENTS, "#{name}.conf")
  File.open(conf_path, 'w', 0o600) { |f| f.write(client_conf) }

  # Add to Server
  peer_entry = "\n[Peer]\n# Name = #{name}\nPublicKey = #{client_pub}\nAllowedIPs = #{next_ip}/32\n"
  File.open(WG_CONF, 'a') { |f| f.write(peer_entry) }

  apply_wg_config
  
  puts "\n--- Client Config: #{conf_path} ---"
  run('qrencode', '-t', 'ansiutf8', '-r', conf_path) if system('which qrencode > /dev/null')
  puts "Assigned IP: #{next_ip}"
end

# --- Simple CLI Router ---
case ARGV[0]
when 'setup'       then setup_server
when 'add-client'  then add_client
when 'forward'     then add_port_forward(ARGV[1], ARGV[2], ARGV[3] || 'udp')
when 'status'      then run('wg', 'show')
else
  puts "Commands: setup, add-client, forward [port] [internal_ip], status"
end