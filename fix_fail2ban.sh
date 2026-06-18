#!/bin/bash
cat > /etc/fail2ban/jail.d/aegisguard.conf << 'EOF'
[sshd]
enabled  = true
maxretry = 5
bantime  = 3600
findtime = 600

[aegisguard-vpn]
enabled   = true
filter    = aegisguard-vpn
logpath   = /var/log/aegisguard-ssl-vpn.log
maxretry  = 5
bantime   = 3600
findtime  = 300
action    = iptables-multiport[name=VPN, port="1194", protocol=udp]
EOF

systemctl restart fail2ban
sleep 1
fail2ban-client status
