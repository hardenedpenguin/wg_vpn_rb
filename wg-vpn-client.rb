#!/usr/bin/env ruby
# frozen_string_literal: true

# WireGuard VPN Client Setup (Ruby)
# Debian only: install wireguard, copy config, bring up tunnel, optional enable on boot.
# Requires: root, Debian.

require 'fileutils'

WG_DIR = '/etc/wireguard'

def run(*cmd, **opts)
  system(*cmd, **opts) || (raise "Command failed: #{cmd.join(' ')}")
end

def root_check
  return if Process.uid == 0
  warn 'This script must be run as root (e.g. sudo).'
  exit 1
end

def debian_check
  return if File.file?('/etc/debian_version')
  warn 'This script is for Debian only.'
  exit 1
end

def ask(prompt)
  print prompt
  $stdin.gets&.strip || ''
end

def setup(config_path = nil)
  root_check
  debian_check

  config_path ||= ask('Path to client config file: ').strip
  raise 'Config path required' if config_path.empty?
  config_path = File.expand_path(config_path)
  raise "Config file not found: #{config_path}" unless File.file?(config_path)

  puts 'Installing wireguard...'
  run('apt-get', 'update', exception: true)
  run('apt-get', 'install', '-y', 'wireguard', exception: true)

  FileUtils.mkdir_p(WG_DIR)
  FileUtils.chmod(0o700, WG_DIR)

  base = File.basename(config_path)
  base += '.conf' unless base.end_with?('.conf')
  dest = File.join(WG_DIR, base)
  interface = base.chomp('.conf')

  FileUtils.cp(config_path, dest, preserve: true)
  FileUtils.chmod(0o600, dest)
  puts "Config copied to #{dest}"

  puts "Bringing up #{interface}..."
  run('wg-quick', 'up', interface, exception: true)

  ans = ask('Enable WireGuard on boot? [y/N]: ').strip.downcase
  if ans == 'y' || ans == 'yes'
    run('systemctl', 'enable', "wg-quick@#{interface}", exception: true)
    puts "Enabled wg-quick@#{interface} on boot."
  end

  puts "\nDone. Tunnel #{interface} is up."
  puts "To bring down later: sudo #{$0} down #{interface}"
end

def up(interface = nil)
  root_check
  interface ||= ARGV[1]
  interface ||= 'wg0'
  run('wg-quick', 'up', interface, exception: true)
  puts "#{interface} is up."
end

def down(interface = nil)
  root_check
  interface ||= ARGV[1]
  interface ||= 'wg0'
  run('wg-quick', 'down', interface, exception: true)
  puts "#{interface} is down."
end

def status(interface = nil)
  root_check
  interface ||= ARGV[1]
  interface ||= 'wg0'
  run('wg', 'show', interface, exception: true)
end

# Subcommands
case ARGV[0]
when 'setup'
  setup(ARGV[1])
when 'up'
  up
when 'down'
  down
when 'status'
  status
when nil, ''
  puts "Usage: #{$0} setup [config_path] | up [interface] | down [interface] | status [interface]"
  puts '  setup   - Install wireguard, copy config to /etc/wireguard, bring up tunnel (default interface: from config filename)'
  puts '  up      - Bring up tunnel (default: wg0)'
  puts '  down    - Bring down tunnel (default: wg0)'
  puts '  status  - Show wg show (default: wg0)'
  exit 1
else
  puts "Usage: #{$0} [ setup [config_path] | up [interface] | down [interface] | status [interface] ]"
  exit 1
end
