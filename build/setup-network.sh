#!/bin/bash
# AegisGuard Network Setup
# Runs automatically after install to configure LAN/WAN

set -e
cd /opt/aegisguard

WAN_IF=$(ip route | grep default | awk '{print $5}' | head -1)
LAN_IF=$(ip link | grep -v $WAN_IF | grep -v lo | grep 'state UP\|state DOWN' | awk '{print $2}' | tr -d ':' | head -1)

# Fallback defaults
[ -z "$WAN_IF" ] && WAN_IF="eth0"
[ -z "$LAN_IF" ] && LAN_IF="eth1"

echo "[→] WAN: $WAN_IF | LAN: $LAN_IF"

# Configure LAN IP
ip addr flush dev $LAN_IF 2>/dev/null || true
ip addr add 10.0.0.1/24 dev $LAN_IF
ip link set $LAN_IF up

# Permanent netplan
cat > /etc/netplan/60-aegisguard-lan.yaml << EOF
network:
  version: 2
  ethernets:
    ${LAN_IF}:
      dhcp4: false
      addresses: [10.0.0.1/24]
EOF
netplan apply 2>/dev/null || true

# Firewall: WAN locked, LAN open
iptables -F INPUT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i $LAN_IF -j ACCEPT
iptables -A INPUT -i $WAN_IF -j DROP
iptables -P INPUT DROP
netfilter-persistent save 2>/dev/null || true

# Update DB with interface names
python3 - << PYEOF
import sys; sys.path.insert(0,'/opt/aegisguard')
from db import database
conn = database.get_connection()
conn.execute("UPDATE interfaces SET name=? WHERE role='WAN'", ('$WAN_IF',))
conn.execute("UPDATE interfaces SET name=? WHERE role='LAN'", ('$LAN_IF',))
conn.execute("UPDATE dhcp_config SET interface=? WHERE interface='eth1'", ('$LAN_IF',))
conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('wan_interface','$WAN_IF')")
conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('lan_interface','$LAN_IF')")
conn.commit(); conn.close()
print("DB updated")
PYEOF

# DHCP server on LAN
cat > /etc/dnsmasq.d/aegisguard.conf << EOF
interface=${LAN_IF}
bind-interfaces
dhcp-range=${LAN_IF},10.0.0.100,10.0.0.200,255.255.255.0,24h
dhcp-option=${LAN_IF},3,10.0.0.1
dhcp-option=${LAN_IF},6,1.1.1.1,8.8.8.8
domain=aegis.local
bogus-priv
domain-needed
no-resolv
server=1.1.1.1
server=8.8.8.8
EOF
systemctl enable dnsmasq
systemctl restart dnsmasq

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf 2>/dev/null || true

# NAT masquerade
iptables -t nat -A POSTROUTING -o $WAN_IF -j MASQUERADE
iptables -A FORWARD -i $LAN_IF -o $WAN_IF -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

systemctl restart aegisguard

echo ""
echo "================================================"
echo " Setup complete!"
echo " LAN: $LAN_IF = 10.0.0.1/24"
echo " WAN: $WAN_IF = locked"
echo " Web UI: http://10.0.0.1:8080"
echo "================================================"
