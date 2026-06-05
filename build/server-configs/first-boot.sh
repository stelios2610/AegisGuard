#!/bin/bash
# AegisGuard First Boot Setup
# Runs once after installation to configure the network and start services.
# Ubuntu 26.04 uses Netplan — /etc/network/interfaces is ignored.

LOGFILE="/var/log/aegisguard-firstboot.log"
DONE_FLAG="/etc/aegisguard/.firstboot_done"

exec > >(tee -a "$LOGFILE") 2>&1

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

if [ -f "$DONE_FLAG" ]; then
    log "First-boot already completed. Skipping."
    exit 0
fi

log "=== AegisGuard First Boot Setup ==="
mkdir -p /etc/aegisguard

# ── 1. Detect actual interface names ─────────────────────────────────────────
IFACES=($(ls /sys/class/net | grep -v lo | sort))
WAN_IF="${IFACES[0]:-eth0}"
LAN_IF="${IFACES[1]:-eth1}"
log "Detected interfaces: WAN=$WAN_IF  LAN=$LAN_IF"

# ── 2. Write Netplan config (Ubuntu 26.04 — netplan only) ─────────────────────
rm -f /etc/netplan/00-installer-config.yaml 2>/dev/null || true
rm -f /etc/netplan/50-cloud-init.yaml 2>/dev/null || true

cat > /etc/netplan/50-aegisguard.yaml << EOF
network:
  version: 2
  ethernets:
    ${WAN_IF}:
      dhcp4: true
    ${LAN_IF}:
      dhcp4: false
      addresses:
        - 10.0.0.1/24
EOF
chmod 600 /etc/netplan/50-aegisguard.yaml
log "Written /etc/netplan/50-aegisguard.yaml"

# ── 3. Apply network config ───────────────────────────────────────────────────
netplan generate 2>/dev/null || true
netplan apply 2>/dev/null || true
sleep 2

# Set LAN IP immediately
ip link set "${LAN_IF}" up 2>/dev/null || true
ip addr flush dev "${LAN_IF}" 2>/dev/null || true
ip addr add 10.0.0.1/24 dev "${LAN_IF}" 2>/dev/null || true
log "LAN ${LAN_IF} up: 10.0.0.1/24"

ip link set "${WAN_IF}" up 2>/dev/null || true
log "WAN ${WAN_IF} up (DHCP via netplan)"

# ── 4. IP forwarding — persistent via sysctl.d ───────────────────────────────
cat > /etc/sysctl.d/99-aegisguard.conf << 'SYSCTL'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 1
SYSCTL
sysctl -p /etc/sysctl.d/99-aegisguard.conf 2>/dev/null || true
log "IP forwarding enabled (persistent)"

# ── 5. NAT masquerade on WAN ─────────────────────────────────────────────────
mkdir -p /etc/iptables
iptables -t nat -A POSTROUTING -o "${WAN_IF}" -j MASQUERADE 2>/dev/null || true
iptables -A FORWARD -i "${LAN_IF}" -o "${WAN_IF}" -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
log "NAT/masquerade set on ${WAN_IF}"

# ── 6. Firewall: LAN fully open, WAN locked ───────────────────────────────────
iptables -F INPUT 2>/dev/null || true
iptables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i "${LAN_IF}" -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i "${WAN_IF}" -p udp --dport 1194 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i "${WAN_IF}" -p tcp --dport 1194 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i "${WAN_IF}" -p udp --dport 51820 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i tun0 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i "${WAN_IF}" -j DROP 2>/dev/null || true
iptables -P INPUT DROP 2>/dev/null || true
log "Firewall: WAN locked. LAN open."

netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
log "iptables rules saved"

# ── 7. dnsmasq DHCP config ────────────────────────────────────────────────────
# Disable systemd-resolved stub on port 53
sed -i 's/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf 2>/dev/null || true
sed -i 's/DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf 2>/dev/null || true
systemctl restart systemd-resolved 2>/dev/null || true

# Write AegisGuard block into /etc/dnsmasq.conf
sed -i '/# AegisGuard DHCP config/,$ d' /etc/dnsmasq.conf 2>/dev/null || true

cat >> /etc/dnsmasq.conf << EOF
# AegisGuard DHCP config (dnsmasq)
# Listen only on LAN interface to avoid conflict with systemd-resolved
listen-address=10.0.0.1
bind-interfaces
no-resolv
no-poll
bogus-priv
domain-needed
server=1.1.1.1
server=8.8.8.8
local=/aegis.local/
domain=aegis.local
interface=${LAN_IF}
dhcp-range=${LAN_IF},10.0.0.100,10.0.0.200,255.255.255.0,86400s
dhcp-option=${LAN_IF},3,10.0.0.1
dhcp-option=${LAN_IF},6,10.0.0.1
EOF

systemctl enable dnsmasq 2>/dev/null || true
systemctl restart dnsmasq 2>/dev/null || true
log "dnsmasq started on ${LAN_IF} (10.0.0.100-200)"

# ── 8. Update AegisGuard DB with interface names ──────────────────────────────
python3 - << PYEOF || log "DB update skipped (will use defaults)"
import sys
sys.path.insert(0, '/opt/aegisguard')
from db import database
database.initialize()
conn = database.get_connection()
conn.execute("UPDATE interfaces SET name=? WHERE role='WAN'", ('${WAN_IF}',))
conn.execute("UPDATE interfaces SET name=? WHERE role='LAN'", ('${LAN_IF}',))
conn.execute("UPDATE dhcp_config SET interface=? WHERE interface='eth1'", ('${LAN_IF}',))
conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('wan_interface','${WAN_IF}')")
conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('lan_interface','${LAN_IF}')")
conn.commit()
conn.close()
print("DB updated: WAN=${WAN_IF} LAN=${LAN_IF}")
PYEOF

# ── 9. SSL cert for nginx ────────────────────────────────────────────────────
if [ ! -f /etc/nginx/ssl/aegisguard.crt ]; then
    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/aegisguard.key \
        -out    /etc/nginx/ssl/aegisguard.crt \
        -subj   "/CN=AegisGuard/O=AegisGuard/C=GR" 2>/dev/null || true
    chmod 640 /etc/nginx/ssl/aegisguard.key 2>/dev/null || true
    log "SSL cert generated"
fi

# ── 10. Start services ────────────────────────────────────────────────────────
systemctl enable aegisguard nginx fail2ban 2>/dev/null || true
systemctl restart nginx 2>/dev/null || true
systemctl start aegisguard 2>/dev/null || true
log "Services started"

# ── 11. Done ──────────────────────────────────────────────────────────────────
touch "$DONE_FLAG"
log "=== First boot complete ==="
log "Web UI: https://10.0.0.1:8080 (LAN only)"
log "SSH:    admin@10.0.0.1 (LAN only)"
log "Connect PC to ${LAN_IF}, get DHCP 10.0.0.x, open browser."
