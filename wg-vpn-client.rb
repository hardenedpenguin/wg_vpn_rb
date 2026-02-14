#!/usr/bin/env ruby
# frozen_string_literal: true

require 'fileutils'

WG_DIR = '/etc/wireguard'

def info(msg); puts "\e[32m[INFO]\e[0m #{msg}"; end
def warn(msg); puts "\e[33m[WARN]\e[0m #{msg}"; end
def error(msg); puts "\e[31m[ERROR]\e[0m #{msg}"; exit 1; end

def run(*cmd)
  success = system(*cmd)
  error "Command failed: #{cmd.join(' ')}" unless success
end

def root_check
  error 'This script must be run as root (sudo).' unless Process.uid == 0
end

def debian_check
  error 'This script is for Debian-based systems only.' unless File.file?('/etc/debian_version')
end

def installed?
  system('command -v wg > /dev/null 2>&1')
end

def default_interface
  confs = Dir[File.join(WG_DIR, '*.conf')].map { |p| File.basename(p, '.conf') }
  return 'wg0' if confs.empty?
  return confs.first if confs.size == 1
  
  active = `wg show interfaces 2>/dev/null`.split
  (confs & active).first || confs.first
end

def setup(config_path = nil)
  root_check
  debian_check

  unless installed?
    info 'Installing WireGuard and dependencies...'
    run('apt-get', 'update')
    run('apt-get', 'install', '-y', 'wireguard', 'resolvconf')
  end

  config_path ||= (print 'Path to client config file: '; $stdin.gets&.strip)
  error 'Config path required' if config_path.nil? || config_path.empty?
  
  config_path = File.expand_path(config_path)
  error "Config file not found: #{config_path}" unless File.file?(config_path)

  FileUtils.mkdir_p(WG_DIR)
  FileUtils.chmod(0o700, WG_DIR)

  base_name = File.basename(config_path, '.conf').gsub(/[^a-zA-Z0-9_]/, '')
  dest = File.join(WG_DIR, "#{base_name}.conf")

  run('install', '-m', '600', '-o', 'root', '-g', 'root', config_path, dest)
  info "Config secured at #{dest}"

  run('wg-quick', 'up', base_name)

  print "Enable WireGuard on boot? [y/N]: "
  if $stdin.gets&.strip&.downcase == 'y'
    run('systemctl', 'enable', "wg-quick@#{base_name}")
    info "Enabled wg-quick@#{base_name} on boot."
  end

  info "Done. Tunnel #{base_name} is active."
  run('wg', 'show', base_name)
end

def up(interface);   root_check; run('wg-quick', 'up', interface || default_interface); end
def down(interface); root_check; run('wg-quick', 'down', interface || default_interface); end

command = ARGV.shift
target  = ARGV.shift

case command
when 'setup'        then setup(target)
when 'up'           then up(target)
when 'down'         then down(target)
when 'status'       then run('wg', 'show', target || default_interface)
when 'enable-boot'  then run('systemctl', 'enable', "wg-quick@#{target || default_interface}")
when 'disable-boot' then run('systemctl', 'disable', "wg-quick@#{target || default_interface}")
else
  puts <<~USAGE
    Usage: #{$0} [command] [interface/path]

    Commands:
      setup [path]      Install WireGuard and import config
      up [iface]        Bring up tunnel
      down [iface]      Bring down tunnel
      status [iface]    Show WireGuard status
      enable-boot       Enable autostart on boot
      disable-boot      Disable autostart on boot
  USAGE
end