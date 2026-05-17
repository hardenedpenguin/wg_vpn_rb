#!/usr/bin/env ruby
# frozen_string_literal: true
#
# WireGuard VPN client setup for Debian.
# Commands: setup [path] | up | down | status | check | list | enable-boot | disable-boot
#

require 'fileutils'
require 'open3'

WG_DIR = '/etc/wireguard'
DEFAULT_VPN_GATEWAY = '10.8.0.1'
VERIFY_TIMEOUT_SEC = 45
VERIFY_POLL_SEC = 2
# Handshake older than this still counts as connected (manual check / idle tunnel).
HANDSHAKE_MAX_AGE_SEC = 600

def info(msg)
  puts "\e[32m[INFO]\e[0m #{msg}"
end

def error(msg)
  puts "\e[31m[ERROR]\e[0m #{msg}"
  exit 1
end

def run(*cmd)
  error "Command failed: #{cmd.join(' ')}" unless system(*cmd)
end

def root_check
  error 'This script must be run as root (sudo).' unless Process.uid == 0
end

def debian_check
  error 'This script is for Debian-based systems only.' unless File.file?('/etc/debian_version')
end

def command_executable?(name)
  ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).each do |dir|
    next if dir.empty?
    path = File.join(dir, name)
    return true if File.file?(path) && File.executable?(path)
  end
  false
end

def conf_path_for(interface)
  path = File.join(WG_DIR, "#{interface}.conf")
  File.file?(path) ? path : nil
end

# Server VPN IP on the tunnel subnet (usually .1); used for checks that must not use DNS.
def vpn_gateway_ip(conf_path)
  return DEFAULT_VPN_GATEWAY unless conf_path && File.file?(conf_path)
  content = File.read(conf_path)
  return DEFAULT_VPN_GATEWAY unless content =~ /^\s*Address\s*=\s*(\d+)\.(\d+)\.(\d+)\.(\d+)/m
  "#{$1}.#{$2}.#{$3}.1"
end

# Seconds since last peer handshake, or nil if none yet.
def latest_handshake_age(iface)
  latest_handshake_age_from_latest_handshakes(iface) ||
    latest_handshake_age_from_show(iface) ||
    latest_handshake_age_from_dump(iface)
end

def latest_handshake_age_from_latest_handshakes(iface)
  out, status = Open3.capture2('wg', 'show', iface, 'latest-handshakes')
  return nil unless status.success?
  now = Time.now.to_i
  best = nil
  out.each_line do |line|
    _key, ts = line.split("\t", 2)
    hs = ts.to_s.strip.to_i
    next if hs <= 0
    age = now - hs
    best = age if best.nil? || age < best
  end
  best
end

# Parse "latest handshake: 2 minutes, 6 seconds ago" from wg show (matches user-visible output).
def latest_handshake_age_from_show(iface)
  out, status = Open3.capture2('wg', 'show', iface)
  return nil unless status.success?
  out.each_line do |line|
    next unless line.include?('latest handshake:')
    if line =~ /latest handshake:\s*(\d+)\s+minute(?:s)?(?:,\s*(\d+)\s+second(?:s)?)?\s+ago/
      return ($1.to_i * 60) + ($2 || 0).to_i
    end
    if line =~ /latest handshake:\s*(\d+)\s+hour(?:s)?(?:,\s*(\d+)\s+minute(?:s)?)?\s+ago/
      return ($1.to_i * 3600) + (($2 || 0).to_i * 60)
    end
    if line =~ /latest handshake:\s*(\d+)\s+second(?:s)?\s+ago/
      return $1.to_i
    end
  end
  nil
end

def latest_handshake_age_from_dump(iface)
  out, status = Open3.capture2('wg', 'show', iface, 'dump')
  return nil unless status.success?
  now = Time.now.to_i
  best = nil
  out.each_line do |line|
    fields = line.split("\t")
    next if fields.size < 6
    hs = fields[5].to_s.strip
    next unless hs.match?(/\A\d+\z/)
    hs = hs.to_i
    next if hs <= 0
    next if hs < 1_000_000_000
    age = now - hs
    best = age if best.nil? || age < best
  end
  best
end

def tunnel_handshake_ok?(iface, max_age_sec: HANDSHAKE_MAX_AGE_SEC)
  age = latest_handshake_age(iface)
  !age.nil? && age <= max_age_sec
end

def ping_vpn_gateway?(iface, gateway_ip)
  return false unless command_executable?('ping')
  system('ping', '-c', '1', '-W', '3', '-I', iface, gateway_ip,
         out: File::NULL, err: File::NULL)
end

# Do not use curl/DNS here: wg-quick + resolvconf/openresolv redirects resolver after "up".
def verify_tunnel!(iface, conf_path: nil, timeout_sec: VERIFY_TIMEOUT_SEC)
  gateway = vpn_gateway_ip(conf_path || conf_path_for(iface))
  info "Checking VPN (handshake to server, no DNS)..."
  deadline = Time.now + timeout_sec
  until Time.now >= deadline
    if tunnel_handshake_ok?(iface)
      if ping_vpn_gateway?(iface, gateway)
        info "VPN OK (handshake + ping #{gateway} via #{iface})."
      else
        info "VPN OK (handshake with server; ping to #{gateway} skipped or failed)."
      end
      return true
    end
    sleep VERIFY_POLL_SEC
  end
  error "No WireGuard handshake within #{timeout_sec}s. Check server, Endpoint, UDP 51820, and routing."
end

def installed?
  command_executable?('wg')
end

# Interface name from config filename. With multiple configs, prefers the active one.
def default_interface
  confs = Dir[File.join(WG_DIR, '*.conf')].map { |p| File.basename(p, '.conf') }
  return 'wg0' if confs.empty?
  return confs.first if confs.size == 1

  out, = Open3.capture2('wg', 'show', 'interfaces')
  active = (out || '').split
  (confs & active).first || confs.first
end

# Install WireGuard, copy config to /etc/wireguard, bring up tunnel, optionally enable on boot.
def setup(config_path = nil)
  root_check
  debian_check

  unless installed?
    # Userspace only (wg, wg-quick). Do not install the wireguard metapackage or
    # recommends: those can pull wireguard-dkms and linux-headers, which fail or
    # bloat Chromebook / non-Debian-kernel environments where the module is in-tree.
    info 'Installing WireGuard tools and dependencies...'
    run('apt-get', 'update')
    # openresolv provides the resolvconf command wg-quick uses for DNS= lines (lighter than resolvconf).
    run('apt-get', 'install', '-y', '--no-install-recommends', 'wireguard-tools', 'openresolv')
  end

  config_path ||= (print 'Path to client config file: '; $stdin.gets&.strip)
  error 'Config path required' if config_path.nil? || config_path.empty?

  config_path = File.expand_path(config_path)
  error "Config file not found: #{config_path}" unless File.file?(config_path)

  FileUtils.mkdir_p(WG_DIR)
  FileUtils.chmod(0o700, WG_DIR)

  # Keep dots and hyphens (e.g. my.node -> my.node); strip path sep and other unsafe chars
  base_name = File.basename(config_path, '.conf').gsub(/[^a-zA-Z0-9_.-]/, '')
  base_name = 'wg0' if base_name.empty?
  dest = File.join(WG_DIR, "#{base_name}.conf")
  already_in_place = File.expand_path(config_path) == File.expand_path(dest)

  unless already_in_place
    run('install', '-m', '600', '-o', 'root', '-g', 'root', config_path, dest)
    File.delete(config_path) if File.exist?(config_path)
    info "Config secured at #{dest}"
  else
    info "Config already at #{dest}, bringing up tunnel."
  end

  run('wg-quick', 'up', base_name)
  verify_tunnel!(base_name, conf_path: dest)

  print 'Enable WireGuard on boot? [y/N]: '
  if $stdin.gets&.strip&.downcase == 'y'
    run('systemctl', 'enable', "wg-quick@#{base_name}")
    info "Enabled wg-quick@#{base_name} on boot."
  end

  info "Done. Tunnel #{base_name} is active."
  run('wg', 'show', base_name)
end

def up(interface = nil)
  root_check
  iface = interface || default_interface
  run('wg-quick', 'up', iface)
  verify_tunnel!(iface, conf_path: conf_path_for(iface)) unless ENV['WG_SKIP_VERIFY']
end

def down(interface = nil)
  root_check
  run('wg-quick', 'down', interface || default_interface)
end

def show_status(interface = nil)
  root_check
  run('wg', 'show', interface || default_interface)
end

def check_tunnel(interface = nil)
  root_check
  iface = interface || default_interface
  up, = Open3.capture2('wg', 'show', 'interfaces')
  unless (up || '').split.include?(iface)
    error "Interface #{iface} is not up. Run: #{$PROGRAM_NAME} up #{iface}"
  end
  if tunnel_handshake_ok?(iface)
    gateway = vpn_gateway_ip(conf_path_for(iface))
    age = latest_handshake_age(iface)
    info "Handshake #{age}s ago."
    info "Ping #{gateway}: #{ping_vpn_gateway?(iface, gateway) ? 'OK' : 'failed (handshake still OK)'}"
    run('wg', 'show', iface)
  else
    run('wg', 'show', iface)
    error 'No recent handshake with server.'
  end
end

def enable_boot(interface = nil)
  root_check
  run('systemctl', 'enable', "wg-quick@#{interface || default_interface}")
end

def disable_boot(interface = nil)
  root_check
  run('systemctl', 'disable', "wg-quick@#{interface || default_interface}")
end

def list_interfaces
  root_check
  confs = Dir[File.join(WG_DIR, '*.conf')].map { |p| File.basename(p, '.conf') }.sort
  if confs.empty?
    info "No configs in #{WG_DIR}."
    return
  end
  out, = Open3.capture2('wg', 'show', 'interfaces')
  active = (out || '').split
  puts "  %-20s  %s" % ["Interface", "Status"]
  puts "  " + "-" * 30
  confs.each do |iface|
    status = active.include?(iface) ? "up" : "down"
    puts "  %-20s  %s" % [iface, status]
  end
end

command = ARGV.shift
target = ARGV.shift

case command
when 'setup'       then setup(target)
when 'up'          then up(target)
when 'down'        then down(target)
when 'status'      then show_status(target)
when 'check'       then check_tunnel(target)
when 'list'        then list_interfaces
when 'enable-boot' then enable_boot(target)
when 'disable-boot' then disable_boot(target)
else
  puts <<~USAGE
    WireGuard VPN Client
    Usage: #{$PROGRAM_NAME} <command> [interface]

    Commands:
      setup [path]     Install WireGuard, import config, bring up tunnel
      up [iface]       Bring up tunnel (auto-detect iface if single config)
      down [iface]     Bring down tunnel
      status [iface]   Show wg status
      check [iface]    Verify handshake (and ping VPN gateway; no DNS)
      list             List configs and which interface is up
      enable-boot      Enable tunnel on boot
      disable-boot     Disable tunnel on boot
  USAGE
end
