#!/usr/bin/env ruby
# frozen_string_literal: true
#
# WireGuard VPN server manager for Debian.
# Run with no args for menu, or: setup | add-client | forward [ext_port] [internal_ip] [internal_port] [proto] | status
#

require 'fileutils'
require 'open3'
require 'tempfile'

# Configuration
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

def get_fw_zone
  capture('firewall-cmd', '--get-default-zone')
end

def run(*cmd)
  system(*cmd) || (raise "Command failed: #{cmd.join(' ')}")
end

def capture(*cmd)
  out, err, status = Open3.capture3(*cmd)
  raise "Command failed: #{cmd.join(' ')}: #{err}" unless status.success?
  out.strip
end

def get_wan_interface
  capture("ip route show default | awk '/default/ {print $5}'").split("\n").first
end

def list_client_ips
  return [] unless File.file?(WG_CONF)
  File.read(WG_CONF).scan(/AllowedIPs = (10\.8\.0\.\d+)/).flatten.uniq.sort
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

def setup_server
  root_check
  wan = get_wan_interface
  puts "Detected WAN Interface: #{wan}"

  puts 'Installing WireGuard and Firewalld...'
  run('apt-get', 'update')
  run('apt-get', 'install', '-y', 'wireguard', 'firewalld', 'resolvconf', 'qrencode')

  File.open('/etc/sysctl.d/99-wireguard.conf', 'w') { |f| f.puts "net.ipv4.ip_forward=1" }
  run('sysctl', '-p', '/etc/sysctl.d/99-wireguard.conf')

  FileUtils.mkdir_p(WG_CLIENTS, mode: 0o700)

  unless File.file?(SERVER_KEY)
    priv = capture('wg', 'genkey')
    File.open(SERVER_KEY, 'w', 0o600) { |f| f.write(priv) }
    File.open(SERVER_PUB, 'w', 0o600) { |f| f.write(capture('wg', 'pubkey', stdin_data: priv)) }
  end

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

  puts "Configuring Firewall..."
  run('systemctl', 'enable', '--now', 'firewalld')
  zone = get_fw_zone
  puts "Using zone: #{zone}"

  run('firewall-cmd', '--permanent', '--add-port', "#{WG_PORT}/udp")
  run('firewall-cmd', '--permanent', "--zone=#{zone}", '--add-interface=wg0')

  # NAT: no zone masquerade (preserves source IP for port-forwards). Targeted masquerade for VPN→internet only.
  run('firewall-cmd', '--permanent', '--direct', '--add-rule', 'ipv4', 'nat', 'POSTROUTING', '0',
      '-o', 'wg0', '-j', 'ACCEPT')
  run('firewall-cmd', '--permanent', '--direct', '--add-rule', 'ipv4', 'nat', 'POSTROUTING', '0',
      '-s', VPN_SUBNET, '-o', wan, '-j', 'MASQUERADE')

  # FORWARD: allow wg0↔WAN (firewalld drops physical→virtual by default)
  run('firewall-cmd', '--permanent', '--direct', '--add-rule', 'ipv4', 'filter', 'FORWARD', '0', '-i', 'wg0', '-o', wan, '-j', 'ACCEPT')
  run('firewall-cmd', '--permanent', '--direct', '--add-rule', 'ipv4', 'filter', 'FORWARD', '0', '-i', wan, '-o', 'wg0', '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT')

  run('firewall-cmd', '--reload')
  run('systemctl', 'enable', '--now', 'wg-quick@wg0')
  puts "Server Setup Complete."
end

def forward_interactive
  root_check
  clients = list_client_ips
  if clients.any?
    puts "Clients: #{clients.join(', ')}"
  else
    puts "No clients yet. Run 'add-client' first."
    return
  end

  print "External port (e.g. 8080): "
  ext_port = gets.strip
  return if ext_port.empty?

  print "Internal port [#{ext_port}]: "
  internal_port = gets.strip
  internal_port = ext_port if internal_port.empty?

  print "Internal IP (e.g. 10.8.0.4) [#{clients.first}]: "
  internal_ip = gets.strip
  internal_ip = clients.first if internal_ip.empty?

  print "Protocol [udp]: "
  proto = gets.strip
  proto = 'udp' if proto.empty?

  add_port_forward(ext_port, internal_ip, internal_port, proto)
end

def add_port_forward(ext_port, internal_ip, internal_port = nil, proto = 'udp')
  root_check
  internal_port ||= ext_port
  wan = get_wan_interface
  zone = get_fw_zone
  proto = proto.downcase

  puts "Forwarding #{wan}:#{ext_port} -> #{internal_ip}:#{internal_port} (#{proto})"

  run('firewall-cmd', '--permanent', "--zone=#{zone}", '--add-forward-port',
      "port=#{ext_port}:proto=#{proto}:toport=#{internal_port}:toaddr=#{internal_ip}")
  run('firewall-cmd', '--permanent', '--direct', '--add-rule', 'ipv4', 'filter', 'FORWARD', '0',
      '-d', internal_ip, '-p', proto, '--dport', internal_port.to_s, '-j', 'ACCEPT')

  run('firewall-cmd', '--reload')
  puts "Done."
end

def add_client
  root_check
  print "Client Name (e.g., node1): "
  name = gets.strip.gsub(/\s+/, '-')

  used_ips = File.read(WG_CONF).scan(/10\.8\.0\.(\d+)/).flatten.map(&:to_i)
  next_ip = "10.8.0.#{(2..254).find { |i| !used_ips.include?(i) }}"

  client_priv = capture('wg', 'genkey')
  client_pub = capture('wg', 'pubkey', stdin_data: client_priv)
  server_pub = File.read(SERVER_PUB).strip
  endpoint = "#{capture('curl', '-s', 'ifconfig.me')}:#{WG_PORT}"

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

  peer_entry = "\n[Peer]\n# Name = #{name}\nPublicKey = #{client_pub}\nAllowedIPs = #{next_ip}/32\n"
  File.open(WG_CONF, 'a') { |f| f.write(peer_entry) }

  apply_wg_config

  puts "\n--- Client Config: #{conf_path} ---"
  run('qrencode', '-t', 'ansiutf8', '-r', conf_path) if system('which qrencode > /dev/null')
  puts "Assigned IP: #{next_ip}"
end

def run_menu
  loop do
    puts
    puts "WireGuard VPN Manager"
    puts "  1) Setup server"
    puts "  2) Add client"
    puts "  3) Forward port"
    puts "  4) Status"
    puts "  5) Exit"
    print "Choice: "
    case gets.strip
    when '1' then setup_server
    when '2' then add_client
    when '3' then forward_interactive
    when '4' then run('wg', 'show')
    when '5' then puts "Bye."; break
    else puts "Invalid choice."
    end
  end
end

case ARGV[0]
when 'setup'       then setup_server
when 'add-client'  then add_client
when 'forward'
  if ARGV[1] && ARGV[2]
    ext_port, internal_ip = ARGV[1], ARGV[2]
    if ARGV[4]
      add_port_forward(ext_port, internal_ip, ARGV[3], ARGV[4])
    elsif ARGV[3]
      add_port_forward(ext_port, internal_ip, ARGV[3] =~ /^\d+$/ ? ARGV[3] : nil, ARGV[3] =~ /^\d+$/ ? 'udp' : ARGV[3])
    else
      add_port_forward(ext_port, internal_ip)
    end
  else
    forward_interactive
  end
when 'status'      then run('wg', 'show')
when nil, 'menu'   then run_menu
else
  puts "Commands: setup | add-client | forward [ext_port] [internal_ip] [internal_port] [proto] | status"
  puts "Run with no args for menu."
end