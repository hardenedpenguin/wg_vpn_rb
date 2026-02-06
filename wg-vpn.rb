#!/usr/bin/env ruby
# frozen_string_literal: true

# WireGuard VPN Manager (Ruby)
# Single script for server setup and client management.
# Requires: root, Debian with wireguard + firewalld (+ qrencode for QR).

require 'fileutils'
require 'open3'

WG_DIR = '/etc/wireguard'
WG_CLIENTS = File.join(WG_DIR, 'clients')
WG_CONF = File.join(WG_DIR, 'wg0.conf')
SERVER_KEY = File.join(WG_DIR, 'server.key')
SERVER_PUB = File.join(WG_DIR, 'server.pub')
VPN_SUBNET = '10.8.0.0/24'
VPN_SERVER_IP = '10.8.0.1'
WG_PORT = 51820
CLIENT_DNS = '1.1.1.1'  # DNS in generated client configs; change if desired

def run(*cmd, **opts)
  system(*cmd, **opts) || (raise "Command failed: #{cmd.join(' ')}")
end

# WireGuard requires "Key = Value" (spaces around =). Normalize every key=value line.
def normalize_wg_config(content)
  content = content.delete("\r")
  content.each_line.map do |line|
    line = line.chomp
    # Match Key=Value (no space) or Key = Value -> output "Key = Value"
    if line =~ /\A(\s*)([A-Za-z][A-Za-z0-9]*)=(\S.*)\z/
      "#{$1}#{$2} = #{$3.strip}\n"
    elsif line =~ /\A(\s*)([A-Za-z][A-Za-z0-9]*)\s+=\s+(.*)\z/
      "#{$1}#{$2} = #{$3.strip}\n"
    else
      "#{line}\n"
    end
  end.join
end

def capture(*cmd, **opts)
  out, err, status = Open3.capture3(*cmd, **opts)
  raise "Command failed: #{cmd.join(' ')}: #{err}" unless status.success?
  out.strip
end

# Apply server config. wg syncconf only accepts kernel keys (PrivateKey, ListenPort);
# Address/DNS are wg-quick extensions, so we use wg-quick reload (full config) or
# wg-quick strip + wg syncconf as fallback.
def apply_wg0_conf
  return unless File.file?(WG_CONF)
  return unless capture('wg', 'show', 'interfaces').include?('wg0')
  # Prefer wg-quick reload so full config (Address, etc.) is applied
  run('systemctl', 'reload', 'wg-quick@wg0', exception: true)
rescue StandardError
  # Fallback: strip wg-quick-only keys, then wg syncconf (requires bash process substitution)
  run('bash', '-c', "wg syncconf wg0 <(wg-quick strip #{WG_CONF})", exception: true)
end

def root_check
  return if Process.uid == 0
  warn 'This script must be run as root.'
  exit 1
end

def ensure_dirs
  FileUtils.mkdir_p(WG_CLIENTS)
  FileUtils.chmod(0o700, WG_DIR)
  FileUtils.chmod(0o700, WG_CLIENTS)
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
  return "#{VPN_SERVER_IP.sub(/\.\d+$/, '')}.2" if !File.file?(WG_CONF)

  File.read(WG_CONF).scan(/AllowedIPs\s*=\s*10\.8\.0\.(\d+)/).each do |m|
    used << m[0].to_i
  end
  Dir[File.join(WG_CLIENTS, '*.conf')].each do |f|
    c = File.read(f)
    c.scan(/Address\s*=\s*10\.8\.0\.(\d+)/).each { |m| used << m[0].to_i }
  rescue Errno::EACCES, Errno::ENOENT
    next
  end
end
  n = (2..254).find { |i| !used.include?(i) } || (raise 'No free client IP in 10.8.0.0/24')
  "10.8.0.#{n}"
end

def server_keys_exist?
  File.file?(SERVER_KEY) && File.file?(SERVER_PUB)
end

def ensure_server_keys
  return if server_keys_exist?
  ensure_dirs
  priv = genkey
  pub = pubkey(priv)
  File.write(SERVER_KEY, priv)
  File.write(SERVER_PUB, pub)
  FileUtils.chmod(0o600, SERVER_KEY)
  FileUtils.chmod(0o600, SERVER_PUB)
  pub
end

def setup_server
  root_check
  puts 'Installing packages (wireguard, firewalld, qrencode)...'
  run('apt-get', 'update', exception: true)
  run('apt-get', 'install', '-y', 'wireguard', 'firewalld', 'qrencode', exception: true)

  puts 'Enabling IP forwarding...'
  run('sysctl', '-w', 'net.ipv4.ip_forward=1', exception: true)
  sysctl_conf = '/etc/sysctl.d/99-wireguard.conf'
  line = "net.ipv4.ip_forward=1"
  unless File.file?(sysctl_conf) && File.read(sysctl_conf).include?(line)
    File.open(sysctl_conf, 'a') { |f| f.puts line }
  end

  ensure_dirs
  pub = ensure_server_keys

  # Build or update server config
  conf = <<~CONF
    [Interface]
    Address = #{VPN_SERVER_IP}/24
    ListenPort = #{WG_PORT}
    PrivateKey = #{File.read(SERVER_KEY).strip}
  CONF

  if File.file?(WG_CONF)
    # Keep existing [Peer] blocks
    peer_section = File.read(WG_CONF).split(/^\[Peer\]/).drop(1).map { |p| '[Peer]' + p }.join
    conf << peer_section
  end

  File.write(WG_CONF, normalize_wg_config(conf))
  FileUtils.chmod(0o600, WG_CONF)

  puts 'Configuring firewalld (UDP 51820, masquerade)...'
  run('firewall-cmd', '--permanent', '--add-port', "#{WG_PORT}/udp", exception: true)
  run('firewall-cmd', '--permanent', '--add-masquerade', exception: true)
  run('firewall-cmd', '--reload', exception: true)

  run('systemctl', 'enable', '--now', 'wg-quick@wg0', exception: true)

  puts "\nServer setup complete."
  puts "Server public key: #{pub}"
  puts "\nRouter: forward UDP #{WG_PORT} -> this host."
end

def add_client(server_endpoint = nil, client_name = nil, route_all_traffic = nil)
  root_check
  ensure_dirs
  ensure_server_keys

  # Fix server config format first (Address=... -> Address = ...)
  if File.file?(WG_CONF)
    raw = File.read(WG_CONF)
    fixed = normalize_wg_config(raw)
    if raw != fixed
      File.write(WG_CONF, fixed)
      apply_wg0_conf
    end
  end

  server_endpoint ||= ask('VPN server public IP or hostname: ')
  client_name ||= ask('Client name (e.g. work-laptop): ')
  client_name = client_name.strip.gsub(/\s+/, '-')
  raise 'Client name required' if client_name.empty?

  # Route all traffic through VPN? (prompt if not given on CLI)
  route_all = route_all_traffic
  if route_all.nil?
    ans = ask('Route all traffic through VPN? [y/N]: ').strip.downcase
    route_all = (ans == 'y' || ans == 'yes')
  end
  allowed_ips = route_all ? '0.0.0.0/0, ::/0' : '10.8.0.0/24'

  client_priv = genkey
  client_pub = pubkey(client_priv)
  client_ip = next_client_ip

  client_conf_path = File.join(WG_CLIENTS, "#{client_name}.conf")
  if File.file?(client_conf_path)
    puts "Client #{client_name} already exists. Overwrite? [y/N]"
    exit 1 unless $stdin.gets.strip.downcase == 'y'
  end

  # Client config
  server_pub = File.read(SERVER_PUB).strip
  endpoint = server_endpoint.include?(':') ? server_endpoint : "#{server_endpoint}:#{WG_PORT}"
  client_conf = <<~CLIENT
    [Interface]
    PrivateKey = #{client_priv}
    Address = #{client_ip}/24
    DNS = #{CLIENT_DNS}

    [Peer]
    PublicKey = #{server_pub}
    Endpoint = #{endpoint}
    AllowedIPs = #{allowed_ips}
  CLIENT
  File.write(client_conf_path, client_conf)
  FileUtils.chmod(0o600, client_conf_path)

  # Append peer to server config (read, normalize, append, write so format is correct)
  current = File.read(WG_CONF)
  peer_block = <<~PEER

    [Peer]
    PublicKey = #{client_pub}
    AllowedIPs = #{client_ip}/32
  PEER
  File.write(WG_CONF, normalize_wg_config(current + peer_block))

  # Reload WireGuard so new peer is applied
  apply_wg0_conf

  puts "\nClient config written: #{client_conf_path}"
  puts "Client VPN IP: #{client_ip}"
  puts '(All traffic will route through VPN.)' if route_all
  if system('which', 'qrencode', out: File::NULL, err: File::NULL)
    puts "\nQR code (scan with WireGuard app):"
    run('qrencode', '-t', 'ansiutf8', '-r', client_conf_path, exception: false)
  end
end

def remove_client(name = nil)
  root_check
  name ||= ask('Client name to remove: ')
  name = name.strip
  client_conf = File.join(WG_CLIENTS, "#{name}.conf")
  unless File.file?(client_conf)
    puts "No such client: #{name}"
    exit 1
  end
  client_ip = File.read(client_conf)[/Address\s*=\s*(\S+)/, 1]
  unless client_ip
    puts 'Could not determine client IP from config.'
    exit 1
  end

  # Remove peer block from server config (entire [Peer] block that contains this client's AllowedIPs)
  content = File.read(WG_CONF)
  blocks = content.split(/(?=\[Peer\])/).reject(&:empty?)
  interface_part = blocks[0] || ''
  peer_blocks = blocks[1..] || []
  target_ip_pattern = /AllowedIPs\s*=\s*#{Regexp.escape(client_ip)}\/\d+/
  peer_blocks_to_keep = peer_blocks.reject { |b| b =~ target_ip_pattern }
  if peer_blocks_to_keep.size < peer_blocks.size
    new_content = ([interface_part] + peer_blocks_to_keep).join("\n").gsub(/\n{3,}/, "\n\n")
    File.write(WG_CONF, normalize_wg_config(new_content))
    File.delete(client_conf)
    apply_wg0_conf
    puts "Removed client: #{name}"
  else
    puts 'Peer block not found in server config; removed config file only.'
    File.delete(client_conf)
  end
end

def list_clients
  root_check
  if !File.directory?(WG_CLIENTS)
    puts 'No clients directory.'
    return
  end
  Dir[File.join(WG_CLIENTS, '*.conf')].each do |f|
    name = File.basename(f, '.conf')
    ip = File.read(f)[/Address\s*=\s*(\S+)/, 1] rescue '-'
    puts "  #{name}: #{ip}"
  end
  puts "\nConnected (wg show):"
  run('wg', 'show', 'wg0', 'latest-handshakes') rescue nil
end

def show_connected
  root_check
  run('wg', 'show', 'wg0')
end

def monitor
  root_check
  puts 'Live monitor (press q to quit):'
  script = <<~BASH
    while true; do
      clear
      wg show wg0
      read -t 2 -n 1 key || true
      [[ "$key" == "q" || "$key" == "Q" ]] && break
    done
  BASH
  run('bash', '-c', script.strip, exception: true)
end

def show_server_key
  root_check
  unless File.file?(SERVER_PUB)
    puts 'Server not set up. Run: setup'
    exit 1
  end
  puts File.read(SERVER_PUB).strip
end

def ask(prompt)
  print prompt
  $stdin.gets&.strip || ''
end

def interactive_menu
  loop do
    puts "\n--- WireGuard VPN Manager ---"
    puts '1) Add Client'
    puts '2) Remove Client'
    puts '3) List Clients'
    puts '4) Show Connected (wg show)'
    puts '5) Live Monitor'
    puts '6) Show Server Public Key'
    puts '7) Exit'
    print 'Choice: '
    case $stdin.gets&.strip
    when '1' then add_client
    when '2' then remove_client
    when '3' then list_clients
    when '4' then show_connected
    when '5' then monitor
    when '6' then show_server_key
    when '7' then break
    else puts 'Invalid option.'
    end
  end
end

# Subcommands
case ARGV[0]
when 'setup'
  setup_server
when 'add-client'
  route_all = !ARGV[3].to_s.strip.empty? && %w[full y yes 1].include?(ARGV[3].to_s.strip.downcase)
  add_client(ARGV[1], ARGV[2], route_all ? true : nil)
when 'remove-client'
  remove_client(ARGV[1])
when 'list-clients'
  list_clients
when 'show-connected'
  show_connected
when 'monitor'
  monitor
when 'show-key'
  show_server_key
when nil, ''
  interactive_menu
else
  puts "Usage: #{$0} [ setup | add-client [server_ip] [name] [full] | remove-client [name] | list-clients | show-connected | monitor | show-key ]"
  puts '  No args: interactive menu.'
  exit 1
end
