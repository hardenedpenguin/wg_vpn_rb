#!/usr/bin/env ruby
# frozen_string_literal: true

# WireGuard VPN Manager (Ruby) - Optimized for ASL3 & CGNAT Bypass
# Requires: root, Debian/Ubuntu, wireguard, firewalld, qrencode.

require 'fileutils'
require 'open3'
require 'tempfile'

WG_DIR = '/etc/wireguard'
WG_CLIENTS = File.join(WG_DIR, 'clients')
WG_CONF = File.join(WG_DIR, 'wg0.conf')
SERVER_KEY = File.join(WG_DIR, 'server.key')
SERVER_PUB = File.join(WG_DIR, 'server.pub')
VPN_SUBNET = '10.8.0.0/24'
VPN_SERVER_IP = '10.8.0.1'
WG_PORT = 51820
CLIENT_DNS = '1.1.1.1'
# 1420 is the standard for WireGuard; safe for IAX2/ASL3 audio packets.
DEFAULT_MTU = 1420

def run(*cmd, **opts)
  system(*cmd, **opts) || (raise "Command failed: #{cmd.join(' ')}")
end

def capture(*cmd, **opts)
  out, err, status = Open3.capture3(*cmd, **opts)
  raise "Command failed: #{cmd.join(' ')}: #{err}" unless status.success?
  out.strip
end

# Format "Key=Value" to "Key = Value" for WireGuard standards
def normalize_wg_config(content)
  content.gsub(/\r/, '').each_line.map do |line|
    if line =~ /\A(\s*)([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*)\z/
      "#{$1}#{$2} = #{$3.strip}\n"
    else
      line
    end
  end.join
end

# Apply server config live without dropping connections
def apply_wg0_conf
  return unless File.file?(WG_CONF)
  return unless capture('wg', 'show', 'interfaces').include?('wg0')

  # wg syncconf updates peers live without affecting existing sessions.
  Tempfile.open('wg_sync') do |f|
    stripped = capture('wg-quick', 'strip', WG_CONF)
    f.write(stripped)
    f.flush
    run('wg', 'syncconf', 'wg0', f.path)
  end
rescue StandardError => e
  warn "Live sync failed, restarting service: #{e.message}"
  run('systemctl', 'restart', 'wg-quick@wg0')
end

def root_check
  return if Process.uid == 0
  warn 'This script must be run as root.'
  exit 1
end

def ensure_dirs
  FileUtils.mkdir_p(WG_CLIENTS, mode: 0o700)
  FileUtils.chmod(0o700, WG_DIR)
end

def genkey
  capture('wg', 'genkey')
end

def pubkey(private_key)
  IO.popen(['wg', 'pubkey'], 'r+') do |io|
    io.write(private_key)
    io.close_write
    io.read.strip
  end
end

def next_client_ip
  used = []
  if File.file?(WG_CONF)
    File.read(WG_CONF).scan(/AllowedIPs\s*=\s*10\.8\.0\.(\d+)/).each { |m| used << m[0].to_i }
  end
  n = (2..254).find { |i| !used.include?(i) } || (raise 'No free client IP in 10.8.0.0/24')
  "10.8.0.#{n}"
end

def ensure_server_keys
  return if File.file?(SERVER_KEY) && File.file?(SERVER_PUB)
  ensure_dirs
  priv = genkey
  pub = pubkey(priv)
  # Security: Write with 0600 mode immediately
  File.open(SERVER_KEY, 'w', 0o600) { |f| f.write(priv) }
  File.open(SERVER_PUB, 'w', 0o600) { |f| f.write(pub) }
  pub
end

def setup_server
  root_check
  puts 'Installing requirements...'
  run('apt-get', 'update')
  run('apt-get', 'install', '-y', 'wireguard', 'firewalld', 'qrencode')

  puts 'Enabling IP forwarding...'
  File.open('/etc/sysctl.d/99-wireguard.conf', 'w') { |f| f.puts "net.ipv4.ip_forward=1" }
  run('sysctl', '-p', '/etc/sysctl.d/99-wireguard.conf')

  ensure_dirs
  ensure_server_keys

  conf = <<~CONF
    [Interface]
    Address = #{VPN_SERVER_IP}/24
    ListenPort = #{WG_PORT}
    PrivateKey = #{File.read(SERVER_KEY).strip}
  CONF

  if File.file?(WG_CONF)
    peers = File.read(WG_CONF).split(/^\[Peer\]/).drop(1).map { |p| "[Peer]#{p}" }.join
    conf << peers
  end

  File.open(WG_CONF, 'w', 0o600) { |f| f.write(normalize_wg_config(conf)) }

  puts 'Configuring firewall...'
  run('firewall-cmd', '--permanent', '--add-port', "#{WG_PORT}/udp")
  run('firewall-cmd', '--permanent', '--add-masquerade')
  run('firewall-cmd', '--permanent', '--zone=trusted', '--add-interface=wg0')
  run('firewall-cmd', '--reload')

  run('systemctl', 'enable', '--now', 'wg-quick@wg0')
  puts "\nServer setup complete."
end

def add_client(server_endpoint = nil, client_name = nil, route_all_traffic = nil)
  root_check
  ensure_dirs
  ensure_server_keys

  server_endpoint ||= ask('VPN server public IP or hostname: ')
  client_name ||= ask('Client name (e.g. asl-node-1): ')
  client_name = client_name.strip.gsub(/\s+/, '-')
  
  client_conf_path = File.join(WG_CLIENTS, "#{client_name}.conf")
  
  if File.file?(client_conf_path)
    puts "Client #{client_name} exists. Overwriting entry..."
    remove_peer_from_server_config(client_name)
  end

  route_all = route_all_traffic.nil? ? (ask('Route all traffic through VPN? [y/N]: ').downcase == 'y') : route_all_traffic
  allowed_ips = route_all ? '0.0.0.0/0, ::/0' : VPN_SUBNET

  client_priv = genkey
  client_pub = pubkey(client_priv)
  client_ip = next_client_ip

  client_conf = <<~CLIENT
    [Interface]
    PrivateKey = #{client_priv}
    Address = #{client_ip}/24
    DNS = #{CLIENT_DNS}
    MTU = #{DEFAULT_MTU}

    [Peer]
    PublicKey = #{File.read(SERVER_PUB).strip}
    Endpoint = #{server_endpoint.include?(':') ? server_endpoint : "#{server_endpoint}:#{WG_PORT}"}
    AllowedIPs = #{allowed_ips}
    # Critical for CGNAT bypass:
    PersistentKeepalive = 25
  CLIENT

  File.open(client_conf_path, 'w', 0o600) { |f| f.write(client_conf) }

  peer_block = "\n[Peer]\n# Name = #{client_name}\nPublicKey = #{client_pub}\nAllowedIPs = #{client_ip}/32\n"
  File.open(WG_CONF, 'a') { |f| f.write(normalize_wg_config(peer_block)) }

  apply_wg0_conf

  puts "\nClient config saved to: #{client_conf_path}"
  if system('which qrencode > /dev/null')
    puts "QR Code for mobile/tablet:"
    run('qrencode', '-t', 'ansiutf8', '-r', client_conf_path)
  end
end

def remove_peer_from_server_config(name)
  return unless File.file?(WG_CONF)
  
  client_file = File.join(WG_CLIENTS, "#{name}.conf")
  client_ip = File.read(client_file)[/Address\s*=\s*(\d+\.\d+\.\d+\.\d+)/, 1] if File.file?(client_file)

  blocks = File.read(WG_CONF).split(/(?=\[Peer\])/)
  header = blocks.shift
  
  filtered_peers = blocks.reject do |b| 
    (client_ip && b.include?("AllowedIPs = #{client_ip}/32")) || b.include?("# Name = #{name}")
  end

  File.open(WG_CONF, 'w', 0o600) { |f| f.write(header + filtered_peers.join) }
end

def remove_client(name = nil)
  root_check
  name ||= ask('Client name to remove: ')
  remove_peer_from_server_config(name)
  
  client_file = File.join(WG_CLIENTS, "#{name}.conf")
  File.delete(client_file) if File.file?(client_file)
  
  apply_wg0_conf
  puts "Removed client: #{name}"
end

def port_forward_menu
  root_check
  puts "\n--- Port Forwarding (NAT) ---"
  
  ext_iface = ask('Public interface (e.g. eth0): ')
  ext_iface = 'eth0' if ext_iface.empty?
  
  dest_ip = ask('Internal Client VPN IP (e.g. 10.8.0.2): ')
  return puts "Error: Destination IP required." if dest_ip.empty?

  port = ask('Port to forward (ASL3 uses 4569): ').to_i
  proto = ask('Protocol (udp/tcp): ').downcase
  proto = 'udp' if proto.empty? # Default to UDP for IAX2

  if system('systemctl is-active --quiet firewalld')
    # Firewalld Duplicate Check
    rule_spec = "port=#{port}:proto=#{proto}:toport=#{port}:toaddr=#{dest_ip}"
    check_cmd = "firewall-cmd --permanent --zone=public --query-forward-port=#{rule_spec}"
    
    if system("#{check_cmd} >/dev/null 2>&1")
      puts "Notice: This rule already exists in Firewalld. Skipping."
    else
      run('firewall-cmd', '--permanent', '--zone=public', "--add-forward-port=#{rule_spec}")
      run('firewall-cmd', '--reload')
      puts "Rule applied via Firewalld."
    end
  else
    # Iptables Duplicate Check (using -C)
    dnat_exists = system("iptables -t nat -C PREROUTING -i #{ext_iface} -p #{proto} --dport #{port} -j DNAT --to-destination #{dest_ip} 2>/dev/null")
    fwd_exists = system("iptables -C FORWARD -p #{proto} -d #{dest_ip} --dport #{port} -j ACCEPT 2>/dev/null")

    if dnat_exists && fwd_exists
      puts "Notice: This rule already exists in Iptables. Skipping."
    else
      run('iptables', '-t', 'nat', '-I', 'PREROUTING', '-i', ext_iface, '-p', proto, '--dport', port.to_s, '-j', 'DNAT', '--to-destination', dest_ip) unless dnat_exists
      run('iptables', '-I', 'FORWARD', '-p', proto, '-d', dest_ip, '--dport', port.to_s, '-j', 'ACCEPT') unless fwd_exists
      puts "Rule applied via Iptables."
    end
  end
end

def list_clients
  puts "\n--- Configured VPN Clients ---"
  Dir[File.join(WG_CLIENTS, '*.conf')].each do |f|
    name = File.basename(f, '.conf')
    ip = File.read(f)[/Address\s*=\s*(\S+)/, 1]
    puts "#{name.ljust(20)} | VPN IP: #{ip}"
  end
end

def ask(prompt)
  print prompt
  $stdin.gets&.strip || ''
end

# CLI Router
case ARGV[0]
when 'setup'          then setup_server
when 'add-client'     then add_client(ARGV[1], ARGV[2], ARGV[3] == 'full')
when 'remove-client'  then remove_client(ARGV[1])
when 'list'           then list_clients
when nil, ''
  loop do
    puts "\n--- WireGuard Manager ---"
    puts "1) Add Client (CGNAT Node)"
    puts "2) Remove Client"
    puts "3) List Clients"
    puts "4) Show VPN Status"
    puts "5) Port Forwarding (for Public ASL3 access)"
    puts "6) Exit"
    case ask('Choice: ')
    when '1' then add_client
    when '2' then remove_client
    when '3' then list_clients
    when '4' then run('wg', 'show')
    when '5' then port_forward_menu
    when '6' then break
    end
  end
else
  puts "Usage: #{$0} [setup | add-client | remove-client | list]"
end