title 'SSH Server Configuration'

control 'ssh-sshd-permissions' do
  title 'Ensure permissions on /etc/ssh/sshd_config are configured'
  desc ''
  ref 'CIS Debian 8 Benchmark v1.0.0 - Item 9.3.3'
  ref 'CIS Generic Linux Benchmark v1.0.0 - Item 5.2.1'

  impact 0.71

  describe file('/etc/ssh/sshd_config') do
    it { should be_owned_by('root') }
    it { should be_grouped_into('root') }
    its('mode') { should cmp '0600' }
  end
end

control 'ssh-sshd-protocol' do
  title 'Ensure SSH Protocol is set to 2'
  desc ''
  ref 'CIS Amazon Linux Benchmark v2.0.0 - Item 5.2.2'
  ref 'CIS CentOS 7 Benchmark v2.1.0 - Item 5.2.2'
  ref 'CIS Debian 8 Benchmark v1.0.0 - Item 9.3.1'
  ref 'CIS Generic Linux Benchmark v1.0.0 - Item 5.2.1'
  ref 'CIS RHEL 7 Benchmark v2.1.0 - Item 5.2.2'
  ref 'CIS Ubuntu 14 Benchmark v2.0.0 - Item 5.2.2'
  ref 'CIS Ubuntu 16 Benchmark v1.0.0 - Item 5.2.2'

  impact 0.65

  describe sshd_config('/etc/ssh/sshd_config') do
    its('Protocol') { should cmp 2 }
  end
end

control 'ssh-sshd-loglevel' do
  title 'Ensure SSH LogLevel is set to INFO'
  desc ''
  ref 'CIS Debian 8 Benchmark v1.0.0 - Item 9.3.2'
  ref 'CIS Generic Linux Benchmark v1.0.0 - Item 5.2.3'

  impact 0.49
  tag cvss3: 'CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N'

  tag trc_audit_id: '4.4.4.3'
  tag trc_audit_item: 'instance_linux_remoteaccess'

  describe sshd_config('/etc/ssh/sshd_config') do
    its('LogLevel') { should cmp 'INFO' }
  end
end

control 'ssh-sshd-no-root' do
  title 'Ensure SSH root login is disabled'
  desc ''
  ref 'CIS Debian 8 Benchmark v1.0.0 - Item 9.3.8'
  ref 'CIS Generic Linux Benchmark v1.0.0 - Item 5.2.8'

  impact 0.98

  describe sshd_config('/etc/ssh/sshd_config') do
    its('PermitRootLogin') { should cmp 'no'}
  end
end
