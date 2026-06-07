#!/bin/bash
# AegisGuard Network Security - One-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/stelios2610/AegisGuard/main/install.sh | sudo bash
# Requires: Ubuntu 22.04/24.04/26.04, two network interfaces (WAN + LAN)

set -e

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${G}[✓]${NC} $*"; }
info() { echo -e "${C}[→]${NC} $*"; }
warn() { echo -e "${Y}[!]${NC} $*"; }
err()  { echo -e "${R}[✗]${NC} $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || err "Run as root: sudo bash install.sh"

echo ""
echo -e "${C}  ╔══════════════════════════════════════════════╗${NC}"
echo -e "${C}  ║     AegisGuard Network Security v1.0         ║${NC}"
echo -e "${C}  ║     One-line installer                       ║${NC}"
echo -e "${C}  ╚══════════════════════════════════════════════╝${NC}"
echo ""

LOGFILE="/var/log/aegisguard-install.log"
exec > >(tee -a "$LOGFILE") 2>&1
echo "=== AegisGuard Install: $(date) ==="

# ── 1. Detect interfaces ──────────────────────────────────────────────────────
info "[1/9] Detecting network interfaces..."
IFACES=($(ls /sys/class/net | grep -v lo | sort))
WAN_IF="${IFACES[0]:-eth0}"
LAN_IF="${IFACES[1]:-eth1}"
log "WAN=$WAN_IF  LAN=$LAN_IF"

# ── 2. Install packages ───────────────────────────────────────────────────────
info "[2/9] Installing packages (this takes a few minutes)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y \
    python3 python3-pip python3-venv \
    nginx openssl git curl wget \
    iptables iptables-persistent netfilter-persistent \
    iproute2 net-tools dnsmasq \
    openvpn fail2ban \
    clamav clamav-daemon \
    keepalived strongswan wireguard \
    htop \
    -qq
log "Packages installed"

# ── 3. Clone AegisGuard ───────────────────────────────────────────────────────
info "[3/9] Cloning AegisGuard from GitHub..."
rm -rf /opt/aegisguard
git clone --depth=1 https://github.com/stelios2610/AegisGuard.git /opt/aegisguard
mkdir -p /opt/aegisguard/build
log "Code cloned to /opt/aegisguard"

# ── 4. Python venv ────────────────────────────────────────────────────────────
info "[4/9] Setting up Python environment..."
python3 -m venv /opt/aegisguard/venv
/opt/aegisguard/venv/bin/pip install --quiet --upgrade pip
/opt/aegisguard/venv/bin/pip install --quiet \
    fastapi "uvicorn[standard]" jinja2 pydantic python-multipart \
    psutil bcrypt qrcode pillow python-dotenv PyYAML
log "Python packages installed"

# ── 5. nginx ──────────────────────────────────────────────────────────────────
info "[5/9] Configuring nginx..."
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/aegisguard.key \
    -out    /etc/nginx/ssl/aegisguard.crt \
    -subj   "/CN=AegisGuard/O=AegisGuard/C=GR" 2>/dev/null
chmod 640 /etc/nginx/ssl/aegisguard.key

cp /opt/aegisguard/build/server-configs/nginx-aegisguard.conf \
   /etc/nginx/sites-available/aegisguard
ln -sf /etc/nginx/sites-available/aegisguard /etc/nginx/sites-enabled/aegisguard
rm -f /etc/nginx/sites-enabled/default
nginx -t 2>/dev/null && systemctl restart nginx || warn "nginx config issue"
log "nginx configured (HTTPS :8080)"

# ── 6. systemd service ────────────────────────────────────────────────────────
info "[6/9] Installing systemd service..."
cp /opt/aegisguard/build/server-configs/aegisguard.service \
   /etc/systemd/system/aegisguard.service
systemctl daemon-reload
systemctl enable aegisguard
log "aegisguard.service enabled"

# ── 7. fail2ban ───────────────────────────────────────────────────────────────
info "[7/9] Configuring fail2ban..."
mkdir -p /etc/fail2ban/jail.d /etc/fail2ban/filter.d
cp /opt/aegisguard/build/server-configs/fail2ban-jail-aegisguard.conf \
   /etc/fail2ban/jail.d/aegisguard.conf 2>/dev/null || true
cp /opt/aegisguard/build/server-configs/fail2ban-filter-aegisguard-vpn.conf \
   /etc/fail2ban/filter.d/aegisguard-vpn.conf 2>/dev/null || true
systemctl enable fail2ban
systemctl start fail2ban 2>/dev/null || true
systemctl restart fail2ban 2>/dev/null || true
log "fail2ban configured"

# ── 8. Network: Netplan + ip_forward + NAT + dnsmasq ─────────────────────────
info "[8/9] Configuring network (eth1, NAT, DHCP)..."

# Netplan
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
netplan apply 2>/dev/null || true
sleep 2
ip link set "${LAN_IF}" up 2>/dev/null || true
ip addr add 10.0.0.1/24 dev "${LAN_IF}" 2>/dev/null || true
log "LAN ${LAN_IF} = 10.0.0.1/24"

# ip_forward
cat > /etc/sysctl.d/99-aegisguard.conf << 'SYSCTL'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 1
SYSCTL
sysctl -p /etc/sysctl.d/99-aegisguard.conf 2>/dev/null || true

# NAT + Firewall
mkdir -p /etc/iptables
iptables -t nat -A POSTROUTING -o "${WAN_IF}" -j MASQUERADE 2>/dev/null || true
iptables -A FORWARD -i "${LAN_IF}" -o "${WAN_IF}" -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -F INPUT 2>/dev/null || true
iptables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i "${LAN_IF}" -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i "${WAN_IF}" -p udp --dport 1194 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i "${WAN_IF}" -p tcp --dport 1194 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i "${WAN_IF}" -p udp --dport 51820 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i "${WAN_IF}" -p udp --dport 500  -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i "${WAN_IF}" -p udp --dport 4500 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i tun0 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i "${WAN_IF}" -j DROP 2>/dev/null || true
iptables -P INPUT DROP 2>/dev/null || true
netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
log "NAT + Firewall configured"

# dnsmasq
sed -i 's/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf 2>/dev/null || true
sed -i 's/DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf 2>/dev/null || true
systemctl restart systemd-resolved 2>/dev/null || true
# Clean any old embedded block from main dnsmasq.conf (legacy)
sed -i '/# AegisGuard DHCP config/,$ d' /etc/dnsmasq.conf 2>/dev/null || true
# Write DHCP config to the correct drop-in file (AegisGuard manages this file)
mkdir -p /etc/dnsmasq.d
cat > /etc/dnsmasq.d/aegisguard.conf << EOF
# AegisGuard managed - do not edit
no-resolv
no-poll
bogus-priv
domain-needed
server=8.8.8.8
server=1.1.1.1
local=/aegis.local/
domain=aegis.local

interface=${LAN_IF}
dhcp-range=${LAN_IF},10.0.0.100,10.0.0.200,255.255.255.0,86400s
dhcp-option=${LAN_IF},3,10.0.0.1
dhcp-option=${LAN_IF},6,10.0.0.1
EOF
systemctl enable dnsmasq 2>/dev/null || true
systemctl restart dnsmasq 2>/dev/null || true
log "dnsmasq DHCP started on ${LAN_IF} (10.0.0.100-200)"

# ── 9. Initialize DB + Start AegisGuard ──────────────────────────────────────
info "[9/9] Starting AegisGuard..."
mkdir -p /etc/aegisguard
cd /opt/aegisguard

python3 - << PYEOF || true
import sys
sys.path.insert(0, '/opt/aegisguard')
from db import database
database.initialize()
conn = database.get_connection()
conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('wan_interface','${WAN_IF}')")
conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('lan_interface','${LAN_IF}')")
conn.commit()
conn.close()
print("Database initialized")
PYEOF

# VPN auth scripts
cp /opt/aegisguard/build/server-configs/vpn-auth.sh /etc/aegisguard/vpn-auth.sh 2>/dev/null || true
cp /opt/aegisguard/build/server-configs/vpn_auth_check.py /etc/aegisguard/vpn_auth_check.py 2>/dev/null || true
chmod +x /etc/aegisguard/vpn-auth.sh 2>/dev/null || true

systemctl start aegisguard
sleep 3

# MOTD
cat > /etc/motd << 'MOTD'

  ╔══════════════════════════════════════════════════════╗
  ║           AegisGuard Network Security v1.0           ║
  ║                                                      ║
  ║  Web UI:  https://10.0.0.1:8080  (LAN only)          ║
  ║  SSH:     ssh admin@10.0.0.1     (LAN only)          ║
  ║                                                      ║
  ║  Default login: admin / admin                        ║
  ║  Change password after first login!                  ║
  ╚══════════════════════════════════════════════════════╝

MOTD

STATUS=$(systemctl is-active aegisguard)
log "AegisGuard: $STATUS"

echo ""
echo -e "${G}  ╔══════════════════════════════════════════════╗${NC}"
echo -e "${G}  ║   AegisGuard installed successfully!         ║${NC}"
echo -e "${G}  ║                                              ║${NC}"
echo -e "${G}  ║   Web UI: https://10.0.0.1:8080             ║${NC}"
echo -e "${G}  ║   Login:  admin / admin                      ║${NC}"
echo -e "${G}  ║                                              ║${NC}"
echo -e "${G}  ║   Connect PC to ${LAN_IF} port              ║${NC}"
echo -e "${G}  ╚══════════════════════════════════════════════╝${NC}"
echo ""
echo "Log: $LOGFILE"
