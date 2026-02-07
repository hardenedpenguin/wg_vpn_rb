#!/usr/bin/env ruby
# frozen_string_literal: true

# TCP/UDP port forward: listen on a port and relay to a VPN client (or any host).
# Example: forward 10.10.2.3:4569 -> 10.8.0.2:4569 so services on the client are reachable via the server.
# Managed by systemd on Debian: install once, add forwards to config, start/stop with systemctl.

require 'socket'
require 'timeout'

DEFAULT_CONFIG = '/etc/wg-vpn-forward.conf'
SYSTEMD_UNIT   = '/etc/systemd/system/wg-vpn-forward.service'

EXIT_USAGE      = 1
EXIT_NOT_FOUND  = 2
EXIT_PERMISSION = 3

# --- Simple hardening knobs ---
TCP_IDLE_TIMEOUT = 300        # seconds before killing stalled TCP streams
UDP_SESSION_TTL  = 60         # seconds before expiring UDP "connections"

def script_path
  File.expand_path(File.realpath(__FILE__))
end

def usage
  puts <<~USAGE
    Usage:
      #{$0} install                    Install systemd service (run once as root).
      #{$0} status                    Show service state and configured forwards.
      #{$0} add [--bind ADDR] [--udp] PORT TARGET_IP [TARGET_PORT]
      #{$0} remove [--udp] PORT TARGET_IP [TARGET_PORT]
      #{$0} remove INDEX              Remove by list index (e.g. remove 1).
      #{$0} list                      Show configured forwards.
      #{$0} [--config PATH]           Run as daemon (used by systemd; reads config).

    After add or remove, restart to apply: systemctl restart wg-vpn-forward

    Config: #{DEFAULT_CONFIG}
      One forward per line: [udp] PORT TARGET_IP [TARGET_PORT]
      Optional: --bind ADDR at start of line; "udp" for UDP.
      Example:
        4569 10.8.0.2
        udp 4569 10.8.0.2
        --bind 10.10.2.3 4569 10.8.0.2 80
  USAGE
end

def parse_config_line(line)
  line = line.strip
  line = line.sub(/\s+#.*\z/, '').strip  # strip inline comments
  return nil if line.empty? || line.start_with?('#')
  tokens = line.split(/\s+/)
  bind_addr = '0.0.0.0'
  protocol = :tcp
  if tokens[0] == '--bind' && tokens.size >= 4
    bind_addr = tokens[1]
    tokens = tokens[2..]
  end
  if tokens[0] == 'udp' || tokens[0] == 'tcp'
    protocol = tokens[0].to_sym
    tokens = tokens[1..]
  end
  return nil if tokens.size < 2
  listen_port = tokens[0].to_i
  target_ip   = tokens[1]
  target_port = (tokens[2] || listen_port).to_i
  return nil if listen_port <= 0 || target_ip.empty? || target_port <= 0
  { bind_addr: bind_addr, protocol: protocol, listen_port: listen_port, target_ip: target_ip, target_port: target_port }
end

def parse_config(path)
  return [] unless File.file?(path)
  File.readlines(path).filter_map { |line| parse_config_line(line) }
end

# Returns [forwards, nil] or [nil, "line N: reason"] on first parse error.
def parse_config_validate(path)
  return [[], nil] unless File.file?(path)
  forwards = []
  File.readlines(path).each_with_index do |line, i|
    line = line.strip.sub(/\s+#.*\z/, '').strip
    next if line.empty? || line.start_with?('#')
    parsed = parse_config_line(line)
    unless parsed
      return [nil, "line #{i + 1}: invalid forward (expected [udp] PORT TARGET_IP [TARGET_PORT])"]
    end
    forwards << parsed
  end
  [forwards, nil]
end

def service_active?
  system('systemctl', 'is-active', 'wg-vpn-forward.service', out: File::NULL, err: File::NULL)
end

def port_in_use_hint(port, udp: false)
  cmd = udp ? "ss -ulnp | grep #{port}" : "ss -tlnp | grep #{port}"
  " Check: #{cmd}"
end

def relay_tcp(client, target)
  threads = [
    Thread.new do
      begin
        Timeout.timeout(TCP_IDLE_TIMEOUT) { IO.copy_stream(client, target) }
      rescue Timeout::Error
        warn "[wg-vpn-forward] TCP client->target idle timeout"
      end
    end,
    Thread.new do
      begin
        Timeout.timeout(TCP_IDLE_TIMEOUT) { IO.copy_stream(target, client) }
      rescue Timeout::Error
        warn "[wg-vpn-forward] TCP target->client idle timeout"
      end
    end
  ]
  threads.each(&:join)
ensure
  client.close rescue nil
  target.close rescue nil
end

def run_one_tcp_forward(bind_addr, listen_port, target_host, target_port)
  server = TCPServer.new(bind_addr, listen_port)
  $stderr.puts "[wg-vpn-forward] TCP #{bind_addr}:#{listen_port} -> #{target_host}:#{target_port}"
  loop do
    client = server.accept
    Thread.new do
      begin
        target = TCPSocket.new(target_host, target_port)
        relay_tcp(client, target)
      rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT, Errno::ENETUNREACH => e
        warn "Forward failed: #{e.message}"
        client.close rescue nil
      end
    end
  end
rescue Errno::EADDRINUSE => e
  warn "Port #{listen_port} in use: #{e.message}#{port_in_use_hint(listen_port, udp: false)}"
  raise
end

def relay_udp(listen_sock, target_host, target_port)
  client_sockets = {}    # [addr, port] -> UDPSocket
  target_to_client = {} # UDPSocket -> [addr, port]
  last_seen = {}        # [addr, port] -> Time

  loop do
    socks = [listen_sock] + client_sockets.values
    readable, = IO.select(socks, nil, nil, 1.0)

    # Periodic cleanup of stale UDP "sessions"
    now = Time.now
    last_seen.each do |key, ts|
      if now - ts > UDP_SESSION_TTL
        sock = client_sockets.delete(key)
        target_to_client.delete(sock)
        last_seen.delete(key)
        sock&.close rescue nil
      end
    end

    next unless readable

    readable.each do |sock|
      if sock == listen_sock
        data, sender = listen_sock.recvfrom(65_535)
        key = [sender[0], sender[1]]
        last_seen[key] = Time.now

        unless client_sockets[key]
          tsock = UDPSocket.new
          tsock.connect(target_host, target_port)
          client_sockets[key] = tsock
          target_to_client[tsock] = key
        end

        client_sockets[key].send(data, 0)
      else
        data = sock.recv(65_535)
        break if data.empty?
        addr, port = target_to_client[sock]
        listen_sock.send(data, 0, addr, port)
        last_seen[[addr, port]] = Time.now
      end
    end
  end
rescue Errno::EBADF
  # socket closed
end

def run_one_udp_forward(bind_addr, listen_port, target_host, target_port)
  sock = UDPSocket.new
  sock.bind(bind_addr, listen_port)
  $stderr.puts "[wg-vpn-forward] UDP #{bind_addr}:#{listen_port} -> #{target_host}:#{target_port}"
  relay_udp(sock, target_host, target_port)
rescue Errno::EADDRINUSE => e
  warn "Port #{listen_port} in use: #{e.message}#{port_in_use_hint(listen_port, udp: true)}"
  raise
rescue Errno::EBADF
  # socket closed
end

def daemon_mode(config_path)
  forwards, err = parse_config_validate(config_path)
  if err
    $stderr.puts "[wg-vpn-forward] Config error: #{err}"
    exit(EXIT_USAGE)
  end
  if forwards.empty?
    $stderr.puts "[wg-vpn-forward] No forwards in #{config_path}; exiting."
    exit 0
  end
  threads = forwards.map do |f|
    Thread.new do
      if f[:protocol] == :udp
        run_one_udp_forward(f[:bind_addr], f[:listen_port], f[:target_ip], f[:target_port])
      else
        run_one_tcp_forward(f[:bind_addr], f[:listen_port], f[:target_ip], f[:target_port])
      end
    end
  end
  threads.each(&:join)
end

def root_check
  return if Process.uid == 0
  warn 'This command must be run as root (e.g. sudo).'
  exit(EXIT_PERMISSION)
end

def systemd_unit_content
  <<~UNIT
    [Unit]
    Description=WireGuard VPN port forward
    After=network-online.target
    Wants=network-online.target

    [Service]
    Type=simple
    ExecStart=#{script_path} --config #{DEFAULT_CONFIG}
    Restart=always
    RestartSec=5

    [Install]
    WantedBy=multi-user.target
  UNIT
end

def install_subcmd
  root_check
  File.write(SYSTEMD_UNIT, systemd_unit_content)
  puts "Wrote #{SYSTEMD_UNIT}"
  unless File.file?(DEFAULT_CONFIG)
    File.write(DEFAULT_CONFIG, "# wg-vpn-forward config: one forward per line\n# [udp] PORT TARGET_IP [TARGET_PORT]\n# Optional: --bind ADDR at start; 'udp' for UDP\n# Example:\n# 4569 10.8.0.2\n# udp 4569 10.8.0.2\n")
    puts "Created #{DEFAULT_CONFIG}"
  end
  system('systemctl', 'daemon-reload') || (warn 'systemctl daemon-reload failed'; exit(1))
  system('systemctl', 'enable', 'wg-vpn-forward.service') || (warn 'systemctl enable failed'; exit(1))
  puts 'Enabled wg-vpn-forward.service'
  if parse_config(DEFAULT_CONFIG).empty?
    puts 'No forwards in config yet. Add one with: sudo ' + $PROGRAM_NAME + ' add 4569 10.8.0.2'
  else
    system('systemctl', 'start', 'wg-vpn-forward.service')
    puts 'Started wg-vpn-forward.service'
  end
  puts 'Manage: systemctl start|stop|restart|status wg-vpn-forward'
end

def add_subcmd(args)
  root_check
  bind_addr = '0.0.0.0'
  udp = false
  args = args.dup
  if args[0] == '--bind' && args.size >= 4
    bind_addr = args[1]
    args = args[2..]
  end
  if args[0] == '--udp'
    udp = true
    args.shift
  end
  listen_port = args[0]&.to_i
  target_ip   = args[1]
  target_port = (args[2] || listen_port)&.to_i
  if listen_port.nil? || listen_port <= 0 || target_ip.to_s.empty? || target_port <= 0
    warn 'Usage: add [--bind ADDR] [--udp] PORT TARGET_IP [TARGET_PORT]'
    exit(EXIT_USAGE)
  end
  protocol = udp ? :udp : :tcp
  existing = parse_config(DEFAULT_CONFIG)
  if existing.any? { |f| f[:protocol] == protocol && f[:bind_addr] == bind_addr && f[:listen_port] == listen_port && f[:target_ip] == target_ip && f[:target_port] == target_port }
    warn "Forward already exists: #{protocol.to_s.upcase} #{listen_port} -> #{target_ip}:#{target_port}" + (bind_addr == '0.0.0.0' ? '' : " (bind #{bind_addr})")
    exit(EXIT_NOT_FOUND)
  end
  parts = []
  parts << '--bind' << bind_addr if bind_addr != '0.0.0.0'
  parts << 'udp' if udp
  parts << listen_port << target_ip << target_port
  line = parts.join(' ') + "\n"
  File.open(DEFAULT_CONFIG, 'a') { |f| f.write(line) }
  proto = udp ? 'UDP' : 'TCP'
  puts "Added #{proto}: #{listen_port} -> #{target_ip}:#{target_port}" + (bind_addr == '0.0.0.0' ? '' : " (bind #{bind_addr})")
  puts 'Restart to apply: systemctl restart wg-vpn-forward' if File.file?(SYSTEMD_UNIT)
end

def remove_subcmd(args)
  root_check
  udp_only = false
  args = args.dup
  if args[0] == '--udp'
    udp_only = true
    args.shift
  end
  # Remove by index: "remove 1" when args = ["1"]
  if args.size == 1 && args[0] =~ /\A[1-9]\d*\z/
    idx = args[0].to_i
    forwards = parse_config(DEFAULT_CONFIG)
    if forwards.empty?
      warn 'No forwards configured. Use list to see indexes.'
      exit(EXIT_NOT_FOUND)
    end
    if idx < 1 || idx > forwards.size
      warn "No forward at index #{idx} (use list to see 1..#{forwards.size})"
      exit(EXIT_NOT_FOUND)
    end
    f = forwards[idx - 1]
    lines = File.readlines(DEFAULT_CONFIG)
    removed = false
    lines.reject! do |l|
      parsed = parse_config_line(l)
      next false unless parsed
      match = parsed[:protocol] == f[:protocol] && parsed[:bind_addr] == f[:bind_addr] && parsed[:listen_port] == f[:listen_port] && parsed[:target_ip] == f[:target_ip] && parsed[:target_port] == f[:target_port]
      if match && !removed
        removed = true
        true
      else
        false
      end
    end
    File.write(DEFAULT_CONFIG, lines.join)
    proto = f[:protocol].to_s.upcase
    puts "Removed #{proto} #{f[:bind_addr] == '0.0.0.0' ? '' : "(bind #{f[:bind_addr]}) "}#{f[:listen_port]} -> #{f[:target_ip]}:#{f[:target_port]}"
    puts 'Restart to apply: systemctl restart wg-vpn-forward' if File.file?(SYSTEMD_UNIT)
    return
  end
  listen_port = args[0]&.to_i
  target_ip   = args[1]
  target_port = args[2]&.to_i
  if listen_port.nil? || listen_port <= 0 || target_ip.to_s.empty?
    warn 'Usage: remove [--udp] PORT TARGET_IP [TARGET_PORT] or remove INDEX'
    exit(EXIT_USAGE)
  end
  lines = File.readlines(DEFAULT_CONFIG)
  target_port = listen_port if target_port.nil? || target_port <= 0
  to_remove = []
  lines.each do |l|
    parsed = parse_config_line(l)
    next unless parsed
    next if udp_only && parsed[:protocol] != :udp
    if parsed[:listen_port] == listen_port && parsed[:target_ip] == target_ip && (target_port <= 0 || parsed[:target_port] == target_port)
      to_remove << parsed
    end
  end
  if to_remove.empty?
    warn "No matching forward: #{listen_port} -> #{target_ip}" + (udp_only ? ' (UDP)' : '')
    exit(EXIT_NOT_FOUND)
  end
  # Remove all matching lines (TCP and UDP when both exist)
  removed_protos = to_remove.map { |f| f[:protocol].to_s.upcase }.uniq
  lines.reject! do |l|
    parsed = parse_config_line(l)
    next false unless parsed
    next true if udp_only && parsed[:protocol] != :udp
    parsed[:listen_port] == listen_port && parsed[:target_ip] == target_ip && (target_port <= 0 || parsed[:target_port] == target_port)
  end
  File.write(DEFAULT_CONFIG, lines.join)
  msg = removed_protos.size == 1 ? "Removed #{removed_protos[0]}: #{listen_port} -> #{target_ip}:#{target_port}" : "Removed #{removed_protos.join(' and ')}: #{listen_port} -> #{target_ip}:#{target_port}"
  puts msg
  puts 'Restart to apply: systemctl restart wg-vpn-forward' if File.file?(SYSTEMD_UNIT)
end

def list_subcmd
  path = DEFAULT_CONFIG
  unless File.file?(path)
    puts "No config at #{path}. Run: #{$PROGRAM_NAME} install"
    return
  end
  forwards = parse_config(path)
  if File.file?(SYSTEMD_UNIT)
    state = service_active? ? 'active' : 'inactive'
    puts "Service: #{state}"
  end
  if forwards.empty?
    puts 'No forwards configured.'
    puts "Add one with: sudo #{$PROGRAM_NAME} add 4569 10.8.0.2"
    return
  end
  puts "Forwards (#{path}):"
  forwards.each_with_index do |f, i|
    bind = f[:bind_addr] == '0.0.0.0' ? '0.0.0.0' : f[:bind_addr]
    proto = f[:protocol].to_s.upcase
    puts "  #{i + 1}. #{proto} #{bind}:#{f[:listen_port]} -> #{f[:target_ip]}:#{f[:target_port]}"
  end
end

def status_subcmd
  if File.file?(SYSTEMD_UNIT)
    state = service_active? ? 'active' : 'inactive'
    puts "Service: #{state}"
  else
    puts 'Service: not installed (run install as root)'
  end
  path = DEFAULT_CONFIG
  unless File.file?(path)
    puts "Config: #{path} not found. Run: #{$PROGRAM_NAME} install"
    return
  end
  forwards = parse_config(path)
  if forwards.empty?
    puts 'No forwards configured.'
    puts "Add one with: sudo #{$PROGRAM_NAME} add 4569 10.8.0.2"
    return
  end
  puts "Forwards (#{path}):"
  forwards.each_with_index do |f, i|
    bind = f[:bind_addr] == '0.0.0.0' ? '0.0.0.0' : f[:bind_addr]
    proto = f[:protocol].to_s.upcase
    puts "  #{i + 1}. #{proto} #{bind}:#{f[:listen_port]} -> #{f[:target_ip]}:#{f[:target_port]}"
  end
end

# Parse global options and dispatch
args = ARGV.dup
config_path = DEFAULT_CONFIG
while (arg = args.shift)
  case arg
  when '--config'
    config_path = args.shift || DEFAULT_CONFIG
  when '-h', '--help'
    usage
    exit(0)
  else
    args.unshift(arg)
    break
  end
end

case args[0]
when 'install'
  args.shift
  install_subcmd
when 'add'
  args.shift
  add_subcmd(args)
when 'remove'
  args.shift
  remove_subcmd(args)
when 'list'
  args.shift
  list_subcmd
when 'status'
  args.shift
  status_subcmd
when nil, ''
  # Daemon mode only when --config was given (e.g. by systemd)
  if ARGV.include?('--config')
    daemon_mode(config_path)
  else
    usage
    exit(EXIT_USAGE)
  end
else
  usage
  exit(EXIT_USAGE)
end
