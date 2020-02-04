# encoding: utf-8

check_extra = attribute('extra', default: false, description: 'Extra hardening, defaults to false')

title 'SSH Server Configuration'

control 'ssh-sshd-permissions' do
  title 'Ensure permissions on /etc/ssh/sshd_config are configured'
  desc ''
  ref 'CIS Debian 8 Benchmark v1.0.0 - Item 9.3.3'
  ref 'CIS Generic Linux Benchmark v1.0.0 - Item 5.2.1'

  impact 0.71
  tag cvss3: 'CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H'

  tag trc_audit_id: '4.4.4.3'
  tag trc_audit_item: 'instance_linux_remoteaccess'

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
  tag cvss3: 'CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N'

  tag trc_audit_id: '4.4.4.3'
  tag trc_audit_item: 'instance_linux_remoteaccess'

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

control 'ssh-sshd-x11forwarding' do
  title 'Ensure SSH X11 forwarding is disabled'
  desc ''
  ref 'CIS Debian 8 Benchmark v1.0.0 - Item 9.3.4'
  ref 'CIS Generic Linux Benchmark v1.0.0 - Item 5.2.4'

  impact 0.0
  tag cvss3: 'none'

  tag trc_audit_id: '4.4.4.3'
  tag trc_audit_item: 'instance_linux_remoteaccess'

  describe sshd_config('/etc/ssh/sshd_config') do
    its('X11Forwarding') { should cmp 'no' }
  end
end

control 'ssh-sshd-max-tries' do
  title 'Ensure SSH MaxAuthTries is set to 4 or less'
  desc ''
  ref 'CIS Debian 8 Benchmark v1.0.0 - Item 9.3.5'
  ref 'CIS Generic Linux Benchmark v1.0.0 - Item 5.2.5'

  impact 0.65
  tag cvss3: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L'

  tag trc_audit_id: '4.4.4.3'
  tag trc_audit_item: 'instance_linux_remoteaccess'

  describe sshd_config('/etc/ssh/sshd_config') do
    its('MaxAuthTries') { should cmp <= 4 }
  end
end

control 'ssh-sshd-rhosts' do
  title 'Ensure SSH IgnoreRhosts is enabled'
  desc ''
  ref 'CIS Debian 8 Benchmark v1.0.0 - Item 9.3.6'
  ref 'CIS Generic Linux Benchmark v1.0.0 - Item 5.2.6'

  impact 0.59
  tag cvss3: 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'

  tag trc_audit_id: '4.4.4.3'
  tag trc_audit_item: 'instance_linux_remoteaccess'

  describe sshd_config('/etc/ssh/sshd_config') do
    its('IgnoreRhosts') { should cmp 'yes' }
  end
end

control 'ssh-sshd-hostbased' do
  title 'Ensure SSH HostbasedAuthentication to No'
  desc ''
  ref 'CIS Debian 8 Benchmark v1.0.0 - Item 9.3.7'
  ref 'CIS Generic Linux Benchmark v1.0.0 - Item 5.2.7'

  impact 0.59
  tag cvss3: 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'

  tag trc_audit_id: '4.4.4.3'
  tag trc_audit_item: 'instance_linux_remoteaccess'

  describe sshd_config('/etc/ssh/sshd_config') do
    its('HostbasedAuthentication') { should cmp 'no' }
  end
end

control 'ssh-sshd-no-root' do
  title 'Ensure SSH root login is disabled'
  desc ''
  ref 'CIS Debian 8 Benchmark v1.0.0 - Item 9.3.8'
  ref 'CIS Generic Linux Benchmark v1.0.0 - Item 5.2.8'

  impact 0.98
  tag cvss3: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'

  tag trc_audit_id: '4.4.4.3'
  tag trc_audit_item: 'instance_linux_remoteaccess'

  describe sshd_config('/etc/ssh/sshd_config') do
    its('PermitRootLogin') { should match(/no|without-password/) }
  end
end

control 'ssh-sshd-no-empty' do
  title 'Ensure SSH PermitEmptyPasswords is disabled'
  desc ''
  ref 'CIS Debian 8 Benchmark v1.0.0 - Item 9.3.9'
  ref 'CIS Generic Linux Benchmark v1.0.0 - Item 5.2.9'

  impact 0.75
  tag cvss3: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'

  tag trc_audit_id: '4.4.4.3'
  tag trc_audit_item: 'instance_linux_remoteaccess'

  describe sshd_config('/etc/ssh/sshd_config') do
    its('PermitEmptyPasswords') { should cmp 'no' }
  end
end

control 'ssh-sshd-no-env' do
  title 'Ensure SSH PermitUserEnvironment is disabled'
  desc ''
  ref 'CIS Debian 8 Benchmark v1.0.0 - Item 9.3.10'
  ref 'CIS Generic Linux Benchmark v1.0.0 - Item 5.2.10'

  impact 0.59
  tag cvss3: 'CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N'

  tag trc_audit_id: '4.4.4.3'
  tag trc_audit_item: 'instance_linux_remoteaccess'

  describe sshd_config('/etc/ssh/sshd_config') do
    its('PermitUserEnvironment') { should cmp 'no' }
  end
end

control 'ssh-sshd-ciphers' do
  title 'Ensure only approved ciphers are used'
  desc ''
  ref 'CIS Debian 8 Benchmark v1.0.0 - Item 9.3.11'
  ref 'CIS Generic Linux Benchmark v1.0.0 - Item 5.2.11'

  impact 0.74
  tag cvss3: 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N'

  tag trc_audit_id: '4.4.4.4'
  tag trc_audit_item: 'instance_linux_remoteaccess'

  describe sshd_config('/etc/ssh/sshd_config') do
    its('Ciphers') { should_not match(/-cbc/) }
  end
end

control 'ssh-sshd-macs' do
  title 'Ensure only approved MAC algorithms are used'
  desc ''
  ref 'CIS Debian 8 Benchmark v1.0.0 - Item 9.3.12'
  ref 'CIS Generic Linux Benchmark v1.0.0 - Item 5.2.12'
  ref 'CIS Ubuntu 14 Benchmark v2.0.0 - Item 5.2.11'
  ref 'CIS Ubuntu 16 Benchmark v1.0.0 - Item 5.2.11'

  impact 0.74
  tag cvss3: 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N'

  tag trc_audit_id: '4.4.4.4'
  tag trc_audit_item: 'instance_linux_remoteaccess'

  describe sshd_config('/etc/ssh/sshd_config') do
    its('MACs') { should cmp('hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com') }
  end
end

control 'ssh-sshd-alive' do
  title 'Ensure SSH Idle Timeout Interval is configured'
  desc ''
  ref 'CIS Debian 8 Benchmark v1.0.0 - Item 9.3.13'
  ref 'CIS Generic Linux Benchmark v1.0.0 - Item 5.2.13'
  ref 'CIS Ubuntu 14 Benchmark v2.0.0 - Item 5.2.12'
  ref 'CIS Ubuntu 16 Benchmark v1.0.0 - Item 5.2.12'

  impact 0.0
  tag cvss3: 'none'

  describe sshd_config('/etc/ssh/sshd_config') do
    its('ClientAliveInterval') { should cmp <= 300 }
    its('ClientAliveCountMax') { should cmp <= 3 }
  end
end

control 'ssh-sshd-gracetime' do
  title 'Ensure SSH LoginGraceTime is set to one minute or less'
  desc ''
  ref 'CIS Debian 8 Benchmark v1.0.0 - Item 9.3.14'
  ref 'CIS Generic Linux Benchmark v1.0.0 - Item 5.2.14'
  ref 'CIS Ubuntu 14 Benchmark v2.0.0 - Item 5.2.13'
  ref 'CIS Ubuntu 16 Benchmark v1.0.0 - Item 5.2.13'

  impact 0.0
  tag cvss3: 'none'

  describe sshd_config('/etc/ssh/sshd_config') do
    its('LoginGraceTime') { should cmp <= 60 }
  end
end

control 'ssh-sshd-restrict' do
  title 'Ensure SSH access is limited'
  desc ''
  ref 'CIS Debian 8 Benchmark v1.0.0 - Item 9.3.15'
  ref 'CIS Generic Linux Benchmark v1.0.0 - Item 5.2.15'
  ref 'CIS Ubuntu 14 Benchmark v2.0.0 - Item 5.2.14'
  ref 'CIS Ubuntu 16 Benchmark v1.0.0 - Item 5.2.14'

  impact 0.0
  tag cvss3: 'none'

  describe.one do
    describe sshd_config('/etc/ssh/sshd_config') do
      its('AllowUsers') { should_not eq '' }
    end
    describe sshd_config('/etc/ssh/sshd_config') do
      its('AllowGroups') { should_not eq '' }
    end
    describe sshd_config('/etc/ssh/sshd_config') do
      its('DenyUsers') { should_not eq '' }
    end
    describe sshd_config('/etc/ssh/sshd_config') do
      its('DenyGroups') { should_not eq '' }
    end
  end
end

control 'ssh-sshd-banner' do
  title 'Ensure SSH warning banner is configured'
  desc ''
  ref 'CIS Debian 8 Benchmark v1.0.0 - Item 9.3.16'
  ref 'CIS Generic Linux Benchmark v1.0.0 - Item 5.2.16'
  ref 'CIS Ubuntu 14 Benchmark v2.0.0 - Item 5.2.15'
  ref 'CIS Ubuntu 16 Benchmark v1.0.0 - Item 5.2.15'

  impact 0.0
  tag cvss3: 'none'

  describe sshd_config('/etc/ssh/sshd_config') do
    its('Banner') { should_not eq '' }
  end
end

control 'ssh-sshd-ciphers-extra' do
  title 'Ensure only the most secure ciphers are used'
  desc ''
  ref 'Cipherli.ST OpenSSH Server', url: 'https://cipherli.st/'

  impact 0.84
  tag cvss3: 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/E:H/RL:U/RC:C/CR:H/IR:H/AR:H'

  tag trc_audit_item: 'instance_linux_remoteaccess_extra'

  describe sshd_config('/etc/ssh/sshd_config') do
    its('Ciphers') { should cmp('chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr') }

    its('Ciphers') { should_not match(/blowfish/) }
    its('Ciphers') { should_not match(/arcfour/) }
    its('Ciphers') { should_not match(/3des/) }
    its('Ciphers') { should_not match(/cast128/) }
  end
end if check_extra

control 'ssh-sshd-kex-extra' do
  title 'Ensure only the most secure key exchange is used'
  desc ''
  ref 'Cipherli.ST OpenSSH Server', url: 'https://cipherli.st/'

  impact 0.84
  tag cvss3: 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/E:H/RL:U/RC:C/CR:H/IR:H/AR:H'

  tag trc_audit_item: 'instance_linux_remoteaccess_extra'

  describe sshd_config('/etc/ssh/sshd_config') do
    its('KexAlgorithms') { should cmp('curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256') }
  end
end if check_extra

control 'ssh-sshd-keys-extra' do
  title 'Ensure only the most secure keys are used'
  desc ''
  ref 'Cipherli.ST OpenSSH Server', url: 'https://cipherli.st/'

  impact 0.84
  tag cvss3: 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/E:H/RL:U/RC:C/CR:H/IR:H/AR:H'

  tag trc_audit_item: 'instance_linux_remoteaccess_extra'

  describe sshd_config('/etc/ssh/sshd_config') do
    its('HostKey') { should_not match(/^[^#]*dsa/) }
  end
end if check_extra
