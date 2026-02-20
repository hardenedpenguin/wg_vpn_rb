#!/usr/bin/env ruby
# frozen_string_literal: true
#
# WireGuard VPN server manager for Debian.
# Uses firewalld policies (no direct rules).
# Run with no args for menu, or: setup | add-client | remove-client [name] | forward | list-forwards | status
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

def list_client_names
  return [] unless Dir.exist?(WG_CLIENTS)
  Dir[File.join(WG_CLIENTS, '*.conf')].map { |f| File.basename(f, '.conf') }.sort
end

def client_ip_for_name(name)
  return nil unless File.file?(WG_CONF)
  content = File.read(WG_CONF)
  in_matching_peer = false
  content.each_line do |line|
    if line.strip == '[Peer]'
      in_matching_peer = false
    elsif line =~ /# Name = #{Regexp.escape(name)}\s*$/
      in_matching_peer = true
    elsif in_matching_peer && line =~ /AllowedIPs = (10\.8\.0\.\d+)/
      return $1
    end
  end
  nil
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
  wan_zone = get_fw_zone
  puts "Detected WAN: #{wan} (zone: #{wan_zone})"

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

  puts "Configuring Firewall (policy-based)..."
  run('systemctl', 'enable', '--now', 'firewalld')

  zones = capture('firewall-cmd', '--permanent', '--get-zones').split(/[\s]+/)
  run('firewall-cmd', '--permanent', '--new-zone=wireguard') unless zones.include?('wireguard')
  run('firewall-cmd', '--permanent', '--zone=wireguard', '--add-interface=wg0')
  run('firewall-cmd', '--permanent', "--zone=#{wan_zone}", '--add-port', "#{WG_PORT}/udp")

  policies = capture('firewall-cmd', '--permanent', '--get-policies').split(/[\s]+/)
  run('firewall-cmd', '--permanent', '--new-policy=wg-to-wan') unless policies.include?('wg-to-wan')
  run('firewall-cmd', '--permanent', '--policy=wg-to-wan', '--add-ingress-zone=wireguard')
  run('firewall-cmd', '--permanent', '--policy=wg-to-wan', "--add-egress-zone=#{wan_zone}")
  run('firewall-cmd', '--permanent', '--policy=wg-to-wan', '--set-target=ACCEPT')
  run('firewall-cmd', '--permanent', '--policy=wg-to-wan', '--add-rich-rule',
      "rule family='ipv4' source address='#{VPN_SUBNET}' masquerade")

  run('firewall-cmd', '--permanent', '--new-policy=wan-to-wg') unless policies.include?('wan-to-wg')
  run('firewall-cmd', '--permanent', '--policy=wan-to-wg', "--add-ingress-zone=#{wan_zone}")
  run('firewall-cmd', '--permanent', '--policy=wan-to-wg', '--add-egress-zone=wireguard')
  run('firewall-cmd', '--permanent', '--policy=wan-to-wg', '--set-target=ACCEPT')

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

def list_forwards
  root_check
  zone = get_fw_zone
  forwards = capture('firewall-cmd', '--permanent', "--zone=#{zone}", '--list-forward-ports')
  lines = forwards.split("\n").map(&:strip).reject(&:empty?)
  if lines.empty?
    puts "No port forwards configured."
    return
  end
  ip_to_name = {}
  ip_to_name = File.file?(WG_CONF) ? File.read(WG_CONF).scan(/# Name = ([^\n]+)\s*\n.*?AllowedIPs = (10\.8\.0\.\d+)/m).to_h { |name, ip| [ip, name.strip] } : {}
  puts "Port forwards (#{zone}):"
  puts "  Ext Port  Proto  ->  Internal           Client"
  puts "  " + "-" * 50
  lines.each do |line|
    if line =~ /port=(\d+):proto=(\w+):toport=(\d+):toaddr=(10\.8\.0\.\d+)/
      ext, proto, int, ip = $1, $2, $3, $4
      name = ip_to_name[ip] || "-"
      puts "  %-8s  %-4s   ->  %s:%-5s  %s" % [ext, proto, ip, int, name]
    else
      puts "  #{line}"
    end
  end
end

def add_port_forward(ext_port, internal_ip, internal_port = nil, proto = 'udp')
  root_check
  internal_port ||= ext_port
  wan = get_wan_interface
  zone = get_fw_zone
  proto = proto.downcase

  forward_spec = "port=#{ext_port}:proto=#{proto}:toport=#{internal_port}:toaddr=#{internal_ip}"
  if system('firewall-cmd', '--permanent', "--zone=#{zone}", '--query-forward-port', forward_spec)
    puts "Forward already configured."
    return
  end

  puts "Forwarding #{wan}:#{ext_port} -> #{internal_ip}:#{internal_port} (#{proto})"

  run('firewall-cmd', '--permanent', "--zone=#{zone}", '--add-forward-port', forward_spec)
  run('firewall-cmd', '--permanent', '--policy=wan-to-wg', '--add-rich-rule',
      "rule family='ipv4' destination address='#{internal_ip}' port port='#{internal_port}' protocol='#{proto}' accept")

  run('firewall-cmd', '--reload')
  puts "Done."
end

def add_client
  root_check
  abort "Error: #{WG_CONF} not found. Run setup first." unless File.file?(WG_CONF)

  print "Client Name (e.g., node1): "
  name = gets.strip.gsub(/\s+/, '-')

  used_ips = File.read(WG_CONF).scan(/10\.8\.0\.(\d+)/).flatten.map(&:to_i)
  next_ip = "10.8.0.#{(2..254).find { |i| !used_ips.include?(i) }}"

  client_priv = capture('wg', 'genkey')
  client_pub = capture('wg', 'pubkey', stdin_data: client_priv)
  server_pub = File.read(SERVER_PUB).strip

  print "Server endpoint - domain name or IP (Enter = auto-detect IP): "
  endpoint_input = gets.strip
  endpoint = if endpoint_input.empty?
    "#{capture('curl', '-s', 'ifconfig.me')}:#{WG_PORT}"
  elsif endpoint_input.include?(':')
    endpoint_input
  else
    "#{endpoint_input}:#{WG_PORT}"
  end

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

def remove_port_forwards_for(client_ip)
  zone = get_fw_zone
  forwards = capture('firewall-cmd', '--permanent', "--zone=#{zone}", '--list-forward-ports')
  removed = false
  forwards.split("\n").each do |line|
    line = line.strip
    next if line.empty?
    next unless line.include?("toaddr=#{client_ip}")
    system('firewall-cmd', '--permanent', "--zone=#{zone}", '--remove-forward-port', line)
    if line =~ /port=(\d+):proto=(\w+):toport=(\d+):toaddr=/
      system('firewall-cmd', '--permanent', '--policy=wan-to-wg', '--remove-rich-rule',
             "rule family='ipv4' destination address='#{client_ip}' port port='#{$3}' protocol='#{$2}' accept")
    end
    removed = true
  end
  run('firewall-cmd', '--reload') if removed
end

def remove_peer_block_from_conf(client_ip)
  lines = File.readlines(WG_CONF)
  out = []
  i = 0
  while i < lines.size
    if lines[i].strip == '[Peer]'
      block = [lines[i]]
      i += 1
      while i < lines.size && !lines[i].strip.start_with?('[')
        block << lines[i]
        i += 1
      end
      out.concat(block) unless block.any? { |l| l.include?("AllowedIPs = #{client_ip}/") }
    else
      out << lines[i]
      i += 1
    end
  end
  File.open(WG_CONF, 'w', 0o600) { |f| f.write(out.join) }
end

def remove_client_interactive
  root_check
  names = list_client_names
  if names.empty?
    puts "No clients."
    return
  end
  puts "Clients: #{names.join(', ')}"
  print "Client name to remove: "
  name = gets.strip
  return if name.empty?
  remove_client(name)
end

def remove_client(name)
  root_check
  abort "Error: #{WG_CONF} not found. Run setup first." unless File.file?(WG_CONF)

  client_ip = client_ip_for_name(name)
  abort "Error: Client '#{name}' not found." unless client_ip

  conf_path = File.join(WG_CLIENTS, "#{name}.conf")
  unless File.file?(conf_path)
    puts "Warning: Config #{conf_path} not found (may have been removed)."
  end

  print "Remove client #{name} (#{client_ip})? [y/N]: "
  abort "Aborted." unless $stdin.gets&.strip&.downcase == 'y'

  remove_port_forwards_for(client_ip)
  remove_peer_block_from_conf(client_ip)
  if File.file?(conf_path)
    backup_dir = File.join(WG_CLIENTS, 'removed')
    FileUtils.mkdir_p(backup_dir, mode: 0o700)
    backup_path = File.join(backup_dir, "#{name}.conf.#{Time.now.strftime('%Y%m%d%H%M%S')}")
    FileUtils.cp(conf_path, backup_path, preserve: true)
    File.delete(conf_path)
    puts "Config backed up to #{backup_path}"
  end
  apply_wg_config
  puts "Removed #{name}."
end

def run_menu
  loop do
    puts
    puts "WireGuard VPN Manager"
    puts "  1) Setup server"
    puts "  2) Add client"
    puts "  3) Forward port"
    puts "  4) Remove client"
    puts "  5) List forwards"
    puts "  6) Status"
    puts "  7) Exit"
    print "Choice: "
    case gets.strip
    when '1' then setup_server
    when '2' then add_client
    when '3' then forward_interactive
    when '4' then remove_client_interactive
    when '5' then list_forwards
    when '6' then run('wg', 'show')
    when '7' then puts "Bye."; break
    else puts "Invalid choice."
    end
  end
end

case ARGV[0]
when 'setup'       then setup_server
when 'add-client'  then add_client
when 'remove-client'
  if ARGV[1]
    remove_client(ARGV[1])
  else
    remove_client_interactive
  end
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
when 'list-forwards' then list_forwards
when 'status'       then run('wg', 'show')
when nil, 'menu'    then run_menu
else
  puts "Commands: setup | add-client | remove-client [name] | forward [...] | list-forwards | status"
  puts "Run with no args for menu."
end