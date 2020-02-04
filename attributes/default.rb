# encoding: utf-8

case node['platform']
when 'redhat', 'centos', 'amazon'
  node.default['ssh']['service'] = 'sshd'
  node.default['tcpd']['package'] = 'tcp_wrappers'

  node.default['epel']['url'] = 'http://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm'

when 'ubuntu', 'debian'
  node.default['ssh']['service'] = 'ssh'
  node.default['tcpd']['package'] = 'tcpd'

else
  raise "Unsupported platform: #{node['platform']} #{node['platform_version']}"
end
