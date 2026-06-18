#!/bin/bash
# Write corrected filter file
cat > /etc/fail2ban/filter.d/aegisguard-vpn.conf << 'EOF'
[Definition]
failregex = ^\S+ \S+ udp4:<HOST>:\d+ TLS Auth Error: Auth Username/Password verification failed
            ^\S+ \S+ udp4:<HOST>:\d+ SENT CONTROL \[UNDEF\]: 'AUTH_FAILED'
ignoreregex =
EOF

# Restart fail2ban
systemctl restart fail2ban
sleep 1
fail2ban-client status
fail2ban-client status aegisguard-vpn 2>/dev/null || echo "VPN jail status unavailable"
