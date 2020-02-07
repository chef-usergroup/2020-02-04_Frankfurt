#
# Cookbook:: example-hardening
# Recipe:: default
#
# Copyright:: 2020, Chef Usergroup, All Rights Reserved.

case node['platform']
when 'centos'
  execute 'yum update --assumeyes'
when 'ubuntu'
  execute 'apt-get --yes update && DEBIAN_FRONTEND=noninteractive apt-get --yes upgrade'
end

############################################################################
# Configure SSH

# CIS Linux 5.2.1 - 5.2.1.16
service node['ssh']['service']

cookbook_file '/etc/ssh/sshd_config' do
  source 'sshd_config'
  owner 'root'
  group 'root'
  mode '0600'

  notifies :restart, "service[#{node['ssh']['service']}]"
end
