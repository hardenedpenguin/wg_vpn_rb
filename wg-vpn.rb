#!/usr/bin/env ruby
# frozen_string_literal: true
#
# WireGuard VPN server manager for Debian.
# Uses firewalld policies (no direct rules).
# Run with no args for menu, or: setup | add-client | remove-client [name] | forward | remove-forward | list-forwards | list-clients | export | status
#

require 'fileutils'
require 'ipaddr'
require 'open3'
require 'tempfile'
require 'timeout'

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
CLIENT_ALLOWED_IPS = '0.0.0.0/0'

def get_fw_zone
  capture('firewall-cmd', '--get-default-zone')
end

def ensure_firewalld_running
  run('systemctl', 'enable', '--now', 'firewalld')
end

def ensure_zone(name)
  ensure_firewalld_running
  zones = capture('firewall-cmd', '--permanent', '--get-zones').split(/[\s]+/)
  run('firewall-cmd', '--permanent', "--new-zone=#{name}") unless zones.include?(name)
end

def zone_for_interface(interface, permanent: false)
  cmd = ['firewall-cmd']
  cmd << '--permanent' if permanent
  cmd += ['--get-zone-of-interface', interface]
  out, _err, status = Open3.capture3(*cmd)
  return '' unless status.success?
  z = out.to_s.strip
  z.empty? ? '' : z
end

# Runtime, then permanent firewalld, then zone XML (wg0 down or reload pending).
def effective_wg_zone(interface = 'wg0')
  zone = zone_for_interface(interface)
  zone = zone_for_interface(interface, permanent: true) if zone.empty?
  zone = zone_from_firewalld_xml(interface) if zone.empty?
  zone
end

def zone_from_firewalld_xml(interface)
  pattern = /<interface\s+name=["']#{Regexp.escape(interface)}["']\s*\/>/
  Dir['/etc/firewalld/zones/*.xml'].each do |path|
    base = File.basename(path)
    next if base.include?('.old') || base.include?('.bak') || base.include?('.dpkg-dist')
    next unless File.read(path).match?(pattern)
    return File.basename(path, '.xml')
  end
  ''
rescue StandardError
  ''
end

def ensure_wireguard_zone(interface: 'wg0', zone: 'wireguard')
  current = effective_wg_zone(interface)
  return current unless current.empty?

  ensure_zone(zone)
  run('firewall-cmd', '--permanent', "--zone=#{zone}", "--add-interface=#{interface}")
  zone
end

def policy_zone_list(name, direction)
  capture('firewall-cmd', '--permanent', "--policy=#{name}", "--get-#{direction}-zones").split(/[\s]+/)
rescue RuntimeError
  []
end

def ensure_policy(name, ingress_zone:, egress_zone:)
  ensure_firewalld_running
  policies = capture('firewall-cmd', '--permanent', '--get-policies').split(/[\s]+/)
  run('firewall-cmd', '--permanent', "--new-policy=#{name}") unless policies.include?(name)

  ensure_zone(ingress_zone)
  ensure_zone(egress_zone)

  ingress = policy_zone_list(name, 'ingress')
  egress = policy_zone_list(name, 'egress')
  run('firewall-cmd', '--permanent', "--policy=#{name}", "--add-ingress-zone=#{ingress_zone}") unless ingress.include?(ingress_zone)
  run('firewall-cmd', '--permanent', "--policy=#{name}", "--add-egress-zone=#{egress_zone}") unless egress.include?(egress_zone)
  run('firewall-cmd', '--permanent', "--policy=#{name}", '--set-target=ACCEPT')
end

def permanent_port_open?(zone, port_spec)
  system('firewall-cmd', '--permanent', "--zone=#{zone}", '--query-port', port_spec,
         out: File::NULL, err: File::NULL)
end

def permanent_rich_rule_present?(rule_target, rich_rule)
  system('firewall-cmd', '--permanent', *rule_target, '--query-rich-rule', rich_rule,
         out: File::NULL, err: File::NULL)
end

def add_permanent_rich_rule_if_missing(rule_target, rich_rule)
  run('firewall-cmd', '--permanent', *rule_target, '--add-rich-rule', rich_rule) unless permanent_rich_rule_present?(rule_target, rich_rule)
end

def remove_permanent_rich_rule_if_present(rule_target, rich_rule)
  run('firewall-cmd', '--permanent', *rule_target, '--remove-rich-rule', rich_rule) if permanent_rich_rule_present?(rule_target, rich_rule)
end

def run(*cmd)
  system(*cmd) || (raise "Command failed: #{cmd.join(' ')}")
end

def capture(*cmd, **opts)
  out, err, status = Open3.capture3(*cmd, **opts)
  raise "Command failed: #{cmd.join(' ')}: #{err}" unless status.success?
  out.strip
end

def debian_check
  abort 'Error: This script is for Debian-based systems only.' unless File.file?('/etc/debian_version')
end

def get_wan_interface
  out, status = Open3.capture2('ip', '-4', 'route', 'show', 'default')
  return '' unless status.success?
  # e.g. "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
  md = out.match(/\bdev\s+(\S+)/)
  md ? md[1] : ''
end

def validate_port(port_str)
  return false unless port_str.to_s.match?(/^\d+$/)
  p = port_str.to_i
  return false if p < 1 || p > 65_535
  true
end

def validate_vpn_client_ip(ip)
  md = ip.to_s.match(/\A10\.8\.0\.(\d+)\z/)
  return false unless md
  n = md[1].to_i
  n >= 2 && n <= 254
end

def validate_proto(proto)
  %w[tcp udp].include?(proto.to_s.downcase)
end

def port_forward_rich_rule(internal_ip, internal_port, proto)
  p = proto.to_s.downcase
  "rule family=\"ipv4\" destination address=\"#{internal_ip}\" port port=\"#{internal_port}\" protocol=\"#{p}\" accept"
end

# WAN zone + where per-forward rich rules live (policy when wg0 is in a separate zone).
def port_forward_wan_zone_and_rule_target
  zone = get_fw_zone
  wg_zone = effective_wg_zone('wg0')
  wg_zone = ensure_wireguard_zone(interface: 'wg0', zone: 'wireguard') if wg_zone.empty?
  use_policy = (wg_zone != zone)
  ensure_policy('wan-to-wg', ingress_zone: zone, egress_zone: wg_zone) if use_policy
  rule_target = use_policy ? ['--policy=wan-to-wg'] : ["--zone=#{zone}"]
  [zone, rule_target]
end

def parse_forward_spec(line)
  return nil unless line =~ /\Aport=(\d+):proto=(\w+):toport=(\d*):toaddr=(\S+)\z/
  ext = Regexp.last_match(1)
  int_port = Regexp.last_match(3)
  int_port = ext if int_port.empty?
  { kind: :port, ext: ext, proto: Regexp.last_match(2).downcase,
    int_port: int_port, ip: Regexp.last_match(4), dest: nil, line: line }
end

# Rich-rule forward, e.g. rule family="ipv4" destination address="10.10.2.3"
#   forward-port port="4569" protocol="udp" to-port="4569" to-addr="10.8.0.7"
def parse_rich_forward(rule)
  return nil unless rule.include?('forward-port')
  attr = ->(name) { rule[/\b#{name}=["']([^"']+)["']/, 1] }
  fwd = rule[/forward-port\s+(.*)\z/, 1].to_s
  ext = fwd[/(?<![-\w])port=["'](\d+)["']/, 1]
  proto = fwd[/\bprotocol=["'](\w+)["']/, 1]
  ip = attr.call('to-addr')
  return nil unless ext && proto && ip
  dest = rule[/destination\s+address=["']([^"']+)["']/, 1]
  { kind: :rich, ext: ext, proto: proto.downcase, int_port: attr.call('to-port') || ext,
    ip: ip, dest: dest, line: rule }
end

def permanent_forward_port_lines(zone)
  out = capture('firewall-cmd', '--permanent', "--zone=#{zone}", '--list-forward-ports')
  out.split("\n").map(&:strip).reject(&:empty?)
end

# Read-only: plain forward-ports plus rich-rule forwards in the zone.
def forward_entries(zone)
  plain = permanent_forward_port_lines(zone).filter_map { |line| parse_forward_spec(line) }
  rich = permanent_rich_rules(["--zone=#{zone}"]).split("\n").map(&:strip).filter_map { |r| parse_rich_forward(r) }
  plain + rich
end

def remove_forward_entry(zone, entry)
  if entry[:kind] == :rich
    run('firewall-cmd', '--permanent', "--zone=#{zone}", '--remove-rich-rule', entry[:line])
  else
    run('firewall-cmd', '--permanent', "--zone=#{zone}", '--remove-forward-port', entry[:line])
  end
end

def forwards_matching_ext_port(zone, ext_port, proto = nil)
  forward_entries(zone).select do |e|
    e[:ext] == ext_port.to_s && (proto.nil? || e[:proto] == proto.to_s.downcase)
  end
end

def forward_still_targets_internal?(zone, internal_ip, internal_port, proto)
  forward_entries(zone).any? do |e|
    e[:ip] == internal_ip && e[:int_port] == internal_port.to_s && e[:proto] == proto.to_s.downcase
  end
end

# Legacy iptables DNATs from firewalld direct rules (shown only; not managed here).
def direct_dnat_rules
  out = capture('firewall-cmd', '--permanent', '--direct', '--get-all-rules')
  out.split("\n").map(&:strip).select { |l| l.include?('-j DNAT') }
rescue RuntimeError
  []
end

def permanent_rich_rules(rule_target)
  capture('firewall-cmd', '--permanent', *rule_target, '--list-rich-rules')
rescue RuntimeError
  ''
end

def validate_client_name(name, max_len: 15)
  return false if name.nil? || name.empty? || name.length > max_len
  name.match?(/\A[a-zA-Z0-9][a-zA-Z0-9_.-]*\z/)
end

def validate_dns(dns_str)
  return false if dns_str.nil? || dns_str.strip.empty?
  parts = dns_str.split(',', -1).map(&:strip)
  return false if parts.empty? || parts.any?(&:empty?)
  parts.all? do |addr|
    IPAddr.new(addr)
    true
  rescue IPAddr::InvalidAddressError
    false
  end
end

def format_endpoint(input)
  return nil if input.nil? || input.empty? || input.match?(/[\s\r\n]/)
  begin
    ip = IPAddr.new(input)
    return ip.ipv6? ? "[#{input}]:#{WG_PORT}" : "#{input}:#{WG_PORT}"
  rescue IPAddr::InvalidAddressError
    # Hostname or host:port / [ipv6]:port
  end
  if input =~ /\A\[([^\]]+)\]:(\d+)\z/
    host = Regexp.last_match(1)
    port = Regexp.last_match(2)
    return nil unless validate_port(port)
    begin
      return nil unless IPAddr.new(host).ipv6?
    rescue IPAddr::InvalidAddressError
      return nil
    end
    return input
  end
  if input =~ /\A([^:]+):(\d+)\z/
    return validate_port(Regexp.last_match(2)) ? input : nil
  end
  return nil if input.include?(':')
  "#{input}:#{WG_PORT}"
end

def package_installed?(pkg)
  out, status = Open3.capture2('dpkg-query', '-W', '-f=${Status}', pkg, err: File::NULL)
  status.success? && out.include?('install ok installed')
end

def command_executable?(name)
  ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).each do |dir|
    next if dir.empty?
    path = File.join(dir, name)
    return true if File.file?(path) && File.executable?(path)
  end
  false
end

def fetch_public_ip(timeout_sec: 10)
  abort 'Error: curl not found. Install curl or enter the server endpoint manually.' unless command_executable?('curl')
  urls = ['https://ifconfig.me/ip', 'https://icanhazip.com']
  urls.each do |url|
    out, _err, status = Timeout.timeout(timeout_sec) do
      Open3.capture3('curl', '-4', '-s', '-f', '--max-time', '8', '--proto', '=https', url)
    end
    ip = out.to_s.strip
    if status.success?
      begin
        return ip if IPAddr.new(ip).ipv4?
      rescue IPAddr::InvalidAddressError
        next
      end
    end
  rescue Timeout::Error, SystemCallError
    next
  end
  abort 'Error: Could not detect public IP (curl failed or no response). Enter endpoint manually.'
end

def list_client_ips
  return [] unless File.file?(WG_CONF)
  File.read(WG_CONF).scan(/AllowedIPs = (10\.8\.0\.\d+)\/32/).flatten.uniq.sort_by { |ip| ip.split('.').last.to_i }
end

def list_client_names
  return [] unless Dir.exist?(WG_CLIENTS)
  Dir[File.join(WG_CLIENTS, '*.conf')].map { |f| File.basename(f, '.conf') }.sort
end

def peer_names_from_conf
  return [] unless File.file?(WG_CONF)
  File.read(WG_CONF).scan(/# Name = ([^\n]+)\s*$/).flatten.map(&:strip).uniq.sort
end

def peer_ip_to_name_map
  return {} unless File.file?(WG_CONF)
  map = {}
  current_name = nil
  File.foreach(WG_CONF) do |line|
    if line.strip == '[Peer]'
      current_name = nil
    elsif line =~ /\A\s*#\s*Name\s*=\s*([^\n]+?)\s*\z/
      current_name = Regexp.last_match(1)
    elsif current_name && line =~ /\A\s*AllowedIPs\s*=\s*(10\.8\.0\.\d+)/
      map[Regexp.last_match(1)] = current_name
    end
  end
  map
end

def client_ip_for_name(name)
  return nil unless File.file?(WG_CONF)
  content = File.read(WG_CONF)
  in_matching_peer = false
  content.each_line do |line|
    if line.strip == '[Peer]'
      in_matching_peer = false
    elsif line =~ /\A\s*#\s*Name\s*=\s*#{Regexp.escape(name)}\s*\z/
      in_matching_peer = true
    elsif in_matching_peer && line =~ /\A\s*AllowedIPs\s*=\s*(10\.8\.0\.\d+)/
      return Regexp.last_match(1)
    end
  end
  nil
end

def root_check
  return if Process.uid == 0
  abort 'Error: This script must be run as root (sudo).'
end

def apply_wg_config
  if capture('wg', 'show', 'interfaces').split.include?('wg0')
    puts "Syncing WireGuard configuration..."
    Tempfile.create(['wg_sync', '']) do |f|
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
  debian_check
  wan = get_wan_interface
  abort 'Error: No default route found. Configure networking first.' if wan.nil? || wan.empty?

  puts 'Installing WireGuard tools and Firewalld...'
  run('apt-get', 'update')
  # Userspace only (wg, wg-quick). Do not install the wireguard metapackage: it can
  # pull wireguard-dkms and linux-headers when the running kernel already has WireGuard.
  # openresolv conflicts with systemd-resolved; skip it when systemd-resolved is present.
  packages = %w[wireguard-tools firewalld qrencode curl]
  if package_installed?('systemd-resolved')
    puts 'systemd-resolved is installed; skipping openresolv.'
  else
    packages << 'openresolv'
  end
  run('apt-get', 'install', '-y', '--no-install-recommends', *packages)

  File.open('/etc/sysctl.d/99-wireguard.conf', 'w') { |f| f.puts "net.ipv4.ip_forward=1" }
  run('sysctl', '-p', '/etc/sysctl.d/99-wireguard.conf')

  FileUtils.mkdir_p(WG_CLIENTS, mode: 0o700)
  FileUtils.chmod(0o700, WG_DIR)
  FileUtils.chmod(0o700, WG_CLIENTS)

  unless File.file?(SERVER_KEY)
    priv = capture('wg', 'genkey')
    File.open(SERVER_KEY, 'w', 0o600) { |f| f.write(priv) }
    File.chmod(0o600, SERVER_KEY)
  end
  unless File.file?(SERVER_PUB)
    priv = File.read(SERVER_KEY).strip
    File.open(SERVER_PUB, 'w', 0o600) { |f| f.write(capture('wg', 'pubkey', stdin_data: priv)) }
    File.chmod(0o600, SERVER_PUB)
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
    File.chmod(0o600, WG_CONF)
  end

  puts "Configuring Firewall (policy-based)..."
  ensure_firewalld_running
  wan_zone = get_fw_zone
  puts "Detected WAN: #{wan} (zone: #{wan_zone})"

  wg_zone = effective_wg_zone('wg0')
  if wg_zone.empty?
    ensure_zone('wireguard')
    run('firewall-cmd', '--permanent', '--zone=wireguard', '--add-interface=wg0')
    wg_zone = 'wireguard'
  else
    puts "Keeping wg0 in existing zone: #{wg_zone}"
  end

  run('firewall-cmd', '--permanent', "--zone=#{wan_zone}", '--add-port', "#{WG_PORT}/udp") unless permanent_port_open?(wan_zone, "#{WG_PORT}/udp")

  if wg_zone == wan_zone
    masq_rule = "rule family=\"ipv4\" source address=\"#{VPN_SUBNET}\" destination not address=\"#{VPN_SUBNET}\" masquerade"
    add_permanent_rich_rule_if_missing(["--zone=#{wan_zone}"], masq_rule)
  else
    masq_rule = "rule family=\"ipv4\" source address=\"#{VPN_SUBNET}\" masquerade"
    ensure_policy('wg-to-wan', ingress_zone: wg_zone, egress_zone: wan_zone)
    add_permanent_rich_rule_if_missing(['--policy=wg-to-wan'], masq_rule)
    ensure_policy('wan-to-wg', ingress_zone: wan_zone, egress_zone: wg_zone)
  end

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
  ext_port = $stdin.gets&.strip
  return if ext_port.nil? || ext_port.empty?

  print "Internal port [#{ext_port}]: "
  internal_port = $stdin.gets&.strip
  internal_port = ext_port if internal_port.nil? || internal_port.empty?

  print "Internal IP (e.g. 10.8.0.4) [#{clients.first}]: "
  internal_ip = $stdin.gets&.strip
  internal_ip = clients.first if internal_ip.nil? || internal_ip.empty?

  print "Protocol [udp]: "
  proto = $stdin.gets&.strip
  proto = 'udp' if proto.nil? || proto.empty?

  unless validate_port(ext_port)
    puts "Error: Invalid external port (must be 1-65535)."
    return
  end
  unless validate_port(internal_port)
    puts "Error: Invalid internal port (must be 1-65535)."
    return
  end
  unless validate_proto(proto)
    puts "Error: Protocol must be tcp or udp."
    return
  end
  unless validate_vpn_client_ip(internal_ip)
    puts "Error: Internal IP must be a VPN client address in #{VPN_SUBNET} (10.8.0.2–10.8.0.254)."
    return
  end
  add_port_forward(ext_port, internal_ip, internal_port, proto)
end

def remove_forward_interactive
  root_check
  clients = list_client_ips
  if clients.any?
    puts "Clients: #{clients.join(', ')}"
  else
    puts "No clients yet. Run 'add-client' first."
    return
  end

  print "External port to stop forwarding: "
  ext_port = $stdin.gets&.strip
  return if ext_port.nil? || ext_port.empty?

  print "Internal port [#{ext_port}]: "
  internal_port = $stdin.gets&.strip
  internal_port = ext_port if internal_port.nil? || internal_port.empty?

  print "Internal IP (e.g. 10.8.0.4) [#{clients.first}]: "
  internal_ip = $stdin.gets&.strip
  internal_ip = clients.first if internal_ip.nil? || internal_ip.empty?

  print "Protocol [udp]: "
  proto = $stdin.gets&.strip
  proto = 'udp' if proto.nil? || proto.empty?

  unless validate_port(ext_port)
    puts "Error: Invalid external port (must be 1-65535)."
    return
  end
  unless validate_port(internal_port)
    puts "Error: Invalid internal port (must be 1-65535)."
    return
  end
  unless validate_proto(proto)
    puts "Error: Protocol must be tcp or udp."
    return
  end
  unless validate_vpn_client_ip(internal_ip)
    puts "Error: Internal IP must be a VPN client address in #{VPN_SUBNET} (10.8.0.2–10.8.0.254)."
    return
  end
  remove_port_forward(ext_port, internal_ip, internal_port, proto)
end

def list_forwards
  root_check
  zone = get_fw_zone
  entries = forward_entries(zone).sort_by { |e| [e[:ext].to_i, e[:proto]] }
  direct = direct_dnat_rules

  ip_to_name = peer_ip_to_name_map

  if entries.empty?
    puts "No port forwards configured."
  else
    puts "Port forwards (#{zone}):"
    puts "  Ext Port  Proto  ->  Internal           Client        Type"
    puts "  " + "-" * 64
    entries.each do |e|
      type = e[:kind] == :rich ? "rich#{e[:dest] ? " (dst #{e[:dest]})" : ''}" : 'forward-port'
      puts "  %-8s  %-4s   ->  %-17s  %-12s  %s" % [e[:ext], e[:proto], "#{e[:ip]}:#{e[:int_port]}", ip_to_name[e[:ip]] || '-', type]
    end
  end

  return if direct.empty?
  puts
  puts "Legacy direct DNAT rules (not managed by this script):"
  direct.each { |l| puts "  #{l}" }
end

def list_clients
  root_check
  names_with_file = list_client_names
  all_peer_names = peer_names_from_conf
  orphan_names = all_peer_names - names_with_file

  if names_with_file.any?
    puts "Clients:"
    puts "  %-20s  %s" % ["Name", "VPN IP"]
    puts "  " + "-" * 40
    names_with_file.each do |name|
      ip = client_ip_for_name(name) || "-"
      puts "  %-20s  %s" % [name, ip]
    end
    puts
  end

  if orphan_names.any?
    puts "Orphan peers (in wg0.conf only, no config file):"
    puts "  %-20s  %s" % ["Name", "VPN IP"]
    puts "  " + "-" * 40
    orphan_names.each do |name|
      ip = client_ip_for_name(name) || "-"
      puts "  %-20s  %s" % [name, ip]
    end
    puts "  (Remove with: remove-client <name>)"
    puts
  end

  puts "No clients." if names_with_file.empty? && orphan_names.empty?
end

def add_port_forward(ext_port, internal_ip, internal_port = nil, proto = 'udp')
  root_check
  internal_port ||= ext_port
  proto = proto.to_s.downcase
  abort "Error: Invalid external port (must be 1-65535)." unless validate_port(ext_port)
  abort "Error: Invalid internal port (must be 1-65535)." unless validate_port(internal_port)
  abort "Error: Protocol must be tcp or udp." unless validate_proto(proto)
  abort "Error: Internal IP must be a VPN client address in #{VPN_SUBNET} (10.8.0.2–10.8.0.254)." unless validate_vpn_client_ip(internal_ip)

  wan = get_wan_interface
  zone, rule_target = port_forward_wan_zone_and_rule_target
  forward_spec = "port=#{ext_port}:proto=#{proto}:toport=#{internal_port}:toaddr=#{internal_ip}"
  existing = forwards_matching_ext_port(zone, ext_port, proto)
  if existing.any? { |e| e[:ip] == internal_ip && e[:int_port] == internal_port.to_s }
    puts "Forward already configured."
    return
  end
  if (other = existing.first)
    abort "Error: #{ext_port}/#{proto} is already forwarded to #{other[:ip]}:#{other[:int_port]}. " \
          "Run: remove-forward #{ext_port} #{proto}"
  end

  rich_rule = port_forward_rich_rule(internal_ip, internal_port, proto)

  puts "Forwarding #{wan}:#{ext_port} -> #{internal_ip}:#{internal_port} (#{proto})"

  run('firewall-cmd', '--permanent', "--zone=#{zone}", '--add-forward-port', forward_spec)
  add_permanent_rich_rule_if_missing(rule_target, rich_rule)

  run('firewall-cmd', '--reload')
  puts "Done."
end

def remove_port_forward(ext_port, internal_ip, internal_port = nil, proto = 'udp')
  root_check
  internal_port ||= ext_port
  proto = proto.to_s.downcase
  abort "Error: Invalid external port (must be 1-65535)." unless validate_port(ext_port)
  abort "Error: Invalid internal port (must be 1-65535)." unless validate_port(internal_port)
  abort "Error: Protocol must be tcp or udp." unless validate_proto(proto)
  abort "Error: Internal IP must be a VPN client address in #{VPN_SUBNET} (10.8.0.2–10.8.0.254)." unless validate_vpn_client_ip(internal_ip)

  zone, rule_target = port_forward_wan_zone_and_rule_target
  matches = forwards_matching_ext_port(zone, ext_port, proto).select do |e|
    e[:ip] == internal_ip && e[:int_port] == internal_port.to_s
  end
  if matches.empty?
    puts "No matching permanent forward (#{ext_port}/#{proto} -> #{internal_ip}:#{internal_port})."
    return
  end

  matches.each { |e| remove_forward_entry(zone, e) }

  unless forward_still_targets_internal?(zone, internal_ip, internal_port, proto)
    rich_rule = port_forward_rich_rule(internal_ip, internal_port, proto)
    remove_permanent_rich_rule_if_present(rule_target, rich_rule)
  end

  run('firewall-cmd', '--reload')
  puts "Removed forward #{ext_port}/#{proto} -> #{internal_ip}:#{internal_port}."
end

def remove_port_forward_by_ext(ext_port, proto = nil)
  root_check
  abort "Error: Invalid external port (must be 1-65535)." unless validate_port(ext_port)
  abort "Error: Protocol must be tcp or udp." if proto && !validate_proto(proto)

  zone, = port_forward_wan_zone_and_rule_target
  matches = forwards_matching_ext_port(zone, ext_port, proto)
  if matches.empty?
    puts "No forward for external port #{ext_port}#{proto ? " (#{proto})" : ''}."
    return
  end
  if matches.size > 1
    puts "Multiple forwards match port #{ext_port}; specify protocol and/or full target:"
    matches.each do |m|
      puts "  #{m[:ext]}/#{m[:proto]} -> #{m[:ip]}:#{m[:int_port]}"
    end
    puts "Example: remove-forward #{ext_port} #{matches.first[:ip]} #{matches.first[:int_port]} #{matches.first[:proto]}"
    return
  end
  m = matches.first
  remove_port_forward(m[:ext], m[:ip], m[:int_port], m[:proto])
end

def add_client
  root_check
  abort "Error: #{WG_CONF} not found. Run setup first." unless File.file?(WG_CONF)

  print "Client Name (e.g., node1): "
  name = ($stdin.gets || '').strip.gsub(/\s+/, '-')
  abort "Error: Client name cannot be empty." if name.empty?
  abort "Error: Client name must start with a letter or digit and contain only letters, digits, underscores, dots, and hyphens (max 15 chars for Linux interface names)." unless validate_client_name(name)
  conf_path = File.join(WG_CLIENTS, "#{name}.conf")
  abort "Error: Client '#{name}' already exists. Choose another name or remove-client first." if File.file?(conf_path) || client_ip_for_name(name)

  used_ips = File.read(WG_CONF).scan(/10\.8\.0\.(\d+)/).flatten.map(&:to_i)
  next_host = (2..254).find { |i| !used_ips.include?(i) }
  abort "Error: No free client IP in #{VPN_SUBNET}. Subnet exhausted." unless next_host
  next_ip = "10.8.0.#{next_host}"

  client_priv = capture('wg', 'genkey')
  client_pub = capture('wg', 'pubkey', stdin_data: client_priv)
  server_pub = File.read(SERVER_PUB).strip

  print "Server endpoint - domain name or IP (Enter = auto-detect IP): "
  endpoint_input = ($stdin.gets || '').strip
  endpoint = if endpoint_input.empty?
    "#{fetch_public_ip}:#{WG_PORT}"
  else
    formatted = format_endpoint(endpoint_input)
    abort "Error: Invalid endpoint '#{endpoint_input}'." unless formatted
    formatted
  end

  print "Client DNS [#{CLIENT_DNS}]: "
  dns_input = ($stdin.gets || '').strip
  client_dns = dns_input.empty? ? CLIENT_DNS : dns_input
  abort "Error: Invalid DNS '#{client_dns}' (must be comma-separated IP addresses)." unless validate_dns(client_dns)

  client_conf = <<~CONF
    [Interface]
    PrivateKey = #{client_priv}
    Address = #{next_ip}/24
    DNS = #{client_dns}
    MTU = #{DEFAULT_MTU}

    [Peer]
    PublicKey = #{server_pub}
    Endpoint = #{endpoint}
    AllowedIPs = #{CLIENT_ALLOWED_IPS}
    PersistentKeepalive = 25
  CONF

  File.open(conf_path, 'w', 0o600) { |f| f.write(client_conf) }

  peer_entry = "\n[Peer]\n# Name = #{name}\nPublicKey = #{client_pub}\nAllowedIPs = #{next_ip}/32\n"
  File.open(WG_CONF, 'a') { |f| f.write(peer_entry) }

  apply_wg_config

  puts "\n--- Client Config: #{conf_path} ---"
  run('qrencode', '-t', 'ansiutf8', '-r', conf_path) if command_executable?('qrencode')
  puts "Assigned IP: #{next_ip}"
end

def remove_port_forwards_for(client_ip)
  zone, rule_target = port_forward_wan_zone_and_rule_target
  to_remove = forward_entries(zone).select { |e| e[:ip] == client_ip }
  return if to_remove.empty?

  to_remove.each { |e| remove_forward_entry(zone, e) }

  to_remove.map { |e| [e[:int_port], e[:proto]] }.uniq.each do |internal_port, proto|
    rich_rule = port_forward_rich_rule(client_ip, internal_port, proto)
    remove_permanent_rich_rule_if_present(rule_target, rich_rule)
  end

  run('firewall-cmd', '--reload')
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
  names = (list_client_names + peer_names_from_conf).uniq.sort
  if names.empty?
    puts "No clients."
    return
  end
  puts "Clients: #{names.join(', ')}"
  print "Client name to remove: "
  name = ($stdin.gets || '').strip
  return if name.empty?
  remove_client(name)
end

def remove_client(name, yes: false)
  root_check
  abort "Error: #{WG_CONF} not found. Run setup first." unless File.file?(WG_CONF)
  abort "Error: Invalid client name '#{name}'." unless validate_client_name(name, max_len: 64)

  client_ip = client_ip_for_name(name)
  abort "Error: Client '#{name}' not found." unless client_ip

  conf_path = File.join(WG_CLIENTS, "#{name}.conf")
  unless File.file?(conf_path)
    puts "Warning: Config #{conf_path} not found (may have been removed)."
  end

  unless yes
    print "Remove client #{name} (#{client_ip})? [y/N]: "
    abort "Aborted." unless $stdin.gets&.strip&.downcase == 'y'
  end

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

def export_backup
  root_check
  abort "Error: #{WG_CONF} not found. Nothing to export." unless File.file?(WG_CONF)

  ts = Time.now.strftime('%Y%m%d%H%M%S')
  archive = File.expand_path("wg-vpn-export-#{ts}.tar.gz")
  File.open(archive, 'w', 0o600) {}
  File.chmod(0o600, archive)
  run('tar', 'czf', archive, '-C', '/etc', 'wireguard')
  File.chmod(0o600, archive)

  wg_zone = effective_wg_zone('wg0')
  wan_zone = get_fw_zone
  forwards = begin
    forward_entries(wan_zone)
  rescue RuntimeError
    []
  end
  direct = direct_dnat_rules

  manifest = File.expand_path("wg-vpn-export-#{ts}.txt")
  File.open(manifest, 'w', 0o600) do |f|
    f.puts "WireGuard export #{ts}"
    f.puts "wg0 zone: #{wg_zone.empty? ? '(unassigned)' : wg_zone}"
    f.puts "WAN/default zone: #{wan_zone}"
    f.puts "Archive: #{archive}"
    f.puts
    f.puts "Port forwards (#{wan_zone}):"
    if forwards.empty?
      f.puts "  (none)"
    else
      forwards.each { |e| f.puts "  [#{e[:kind]}] #{e[:line]}" }
    end
    unless direct.empty?
      f.puts
      f.puts "Legacy direct DNAT rules (copied only with /etc/firewalld):"
      direct.each { |l| f.puts "  #{l}" }
    end
    f.puts
    f.puts "Re-add forwards after restore (if not restoring full firewalld):"
    f.puts "  (rich-rule forwards are re-added as plain forward-ports, without the destination-address limit)"
    forwards.each do |e|
      f.puts "  ./wg-vpn.rb forward #{e[:ext]} #{e[:ip]} #{e[:int_port]} #{e[:proto]}"
    end
    f.puts
    f.puts "Restore: tar xzf #{File.basename(archive)} -C /etc"
    f.puts "If wg0 is in a custom zone (e.g. allstarlink), restore /etc/firewalld first"
    f.puts "and ensure wg0 appears in only one zone XML before firewall-cmd --reload."
  end

  File.chmod(0o600, manifest)

  puts "Exported #{archive}"
  puts "Manifest #{manifest}"
  puts "wg0 zone: #{wg_zone.empty? ? '(unassigned)' : wg_zone}  WAN zone: #{wan_zone}"
end

def show_status
  root_check
  run('wg', 'show')
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
    puts "  6) List clients"
    puts "  7) Status"
    puts "  8) Remove port forward"
    puts "  9) Export backup"
    puts " 10) Exit"
    print "Choice: "
    choice = $stdin.gets
    unless choice
      puts "Bye."
      break
    end
    begin
      case choice.strip
      when '1' then setup_server
      when '2' then add_client
      when '3' then forward_interactive
      when '4' then remove_client_interactive
      when '5' then list_forwards
      when '6' then list_clients
      when '7' then show_status
      when '8' then remove_forward_interactive
      when '9' then export_backup
      when '10' then puts "Bye."; break
      else puts "Invalid choice."
      end
    rescue RuntimeError => e
      warn "Error: #{e.message}"
    end
  end
end

case ARGV[0]
when 'setup'       then setup_server
when 'add-client'  then add_client
when 'remove-client'
  args = ARGV[1..] || []
  yes = !!(args.delete('-y') || args.delete('--yes') || ENV['WG_YES'] == '1')
  name = args[0]
  if name
    remove_client(name, yes: yes)
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
when 'remove-forward'
  if ARGV[1]
    ext_port = ARGV[1]
    if ARGV[2].nil?
      remove_port_forward_by_ext(ext_port)
    elsif validate_vpn_client_ip(ARGV[2])
      internal_ip = ARGV[2]
      if ARGV[4]
        remove_port_forward(ext_port, internal_ip, ARGV[3], ARGV[4])
      elsif ARGV[3]
        remove_port_forward(ext_port, internal_ip, ARGV[3] =~ /^\d+$/ ? ARGV[3] : nil, ARGV[3] =~ /^\d+$/ ? 'udp' : ARGV[3])
      else
        remove_port_forward(ext_port, internal_ip)
      end
    elsif validate_proto(ARGV[2])
      remove_port_forward_by_ext(ext_port, ARGV[2])
    else
      abort "Error: Invalid argument '#{ARGV[2]}'. Expected a VPN client IP (10.8.0.2-10.8.0.254) or protocol (tcp/udp)."
    end
  else
    remove_forward_interactive
  end
when 'export'        then export_backup
when 'list-forwards' then list_forwards
when 'list-clients'  then list_clients
when 'status'        then show_status
when nil, 'menu'     then run_menu
else
  puts "Commands: setup | add-client | remove-client [-y] [name] | forward [...] | remove-forward [...] | list-forwards | list-clients | export | status"
  puts "Run with no args for menu."
end
