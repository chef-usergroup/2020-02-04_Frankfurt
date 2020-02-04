# encoding: utf-8

case node['platform']
when 'redhat', 'centos', 'amazon'
  default['ssh']['service'] = 'sshd'

when 'ubuntu', 'debian'
  default['ssh']['service'] = 'ssh'

else
  raise "Unsupported platform: #{node['platform']} #{node['platform_version']}"
end
