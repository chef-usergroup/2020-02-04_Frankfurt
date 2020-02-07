#
# Cookbook:: example-hardening
# Recipe:: demo
#
# Copyright:: 2020, Chef Usergroup, All Rights Reserved.

case node['platform']
when 'centos'
  execute 'yum update --assumeyes'
  cookbook_file '/etc/yum.repos.d/nginx.repo' do
    source 'nginx.repo'
    action :create
  end
when 'ubuntu'
  execute 'apt-get --yes update && DEBIAN_FRONTEND=noninteractive apt-get --yes upgrade'
end

package 'nginx'

service 'nginx' do
  action [ :enable, :start ]
end
