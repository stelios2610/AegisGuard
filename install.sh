#!/bin/bash
# FGUARD UTC Network Security - One-line installer
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
echo -e "${C}  ║     FGUARD UTC Network Security v1.0         ║${NC}"
echo -e "${C}  ║     One-line installer                       ║${NC}"
echo -e "${C}  ╚══════════════════════════════════════════════╝${NC}"
echo ""

LOGFILE="/var/log/aegisguard-install.log"
exec > >(tee -a "$LOGFILE") 2>&1
echo "=== FGUARD UTC Install: $(date) ==="

# ── 1. Detect interfaces ──────────────────────────────────────────────────────
info "[1/9] Detecting network interfaces..."
# WAN = the interface that already has an IP (assigned by upstream DHCP during OS install)
WAN_IF=""
for _if in $(ls /sys/class/net | grep -v lo | sort); do
    if ip addr show "$_if" 2>/dev/null | grep -q "inet "; then
        WAN_IF="$_if"
        break
    fi
done
WAN_IF="${WAN_IF:-eth0}"
# LAN = all other interfaces (support 1 or 2 LAN ports)
LAN_IFS=()
for _if in $(ls /sys/class/net | grep -v lo | sort); do
    [ "$_if" = "$WAN_IF" ] && continue
    LAN_IFS+=("$_if")
done
LAN_IF="${LAN_IFS[0]:-eth1}"
LAN2_IF="${LAN_IFS[1]:-}"
log "WAN=$WAN_IF  LAN=$LAN_IF  LAN2=${LAN2_IF:-none}"

# Lock interface names to MAC addresses — prevents name changes after power outage/reboot
WAN_MAC=$(cat /sys/class/net/${WAN_IF}/address 2>/dev/null || true)
LAN_MAC=$(cat /sys/class/net/${LAN_IF}/address 2>/dev/null || true)
log "WAN MAC=$WAN_MAC  LAN MAC=$LAN_MAC"

# Ensure 8021q VLAN module loads on boot
grep -q 8021q /etc/modules 2>/dev/null || echo 8021q >> /etc/modules
modprobe 8021q 2>/dev/null || true

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
    keepalived strongswan wireguard \
    htop \
    -qq
log "Packages installed"

# Disable automatic apt updates — prevents disk fill and unexpected changes
systemctl disable --now unattended-upgrades 2>/dev/null || true
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
apt-get remove unattended-upgrades -y -qq 2>/dev/null || true
log "Automatic apt updates disabled"

# ── 3. Clone AegisGuard ───────────────────────────────────────────────────────
info "[3/9] Cloning AegisGuard from GitHub..."
rm -rf /opt/aegisguard
git clone --depth=1 https://github.com/stelios2610/test-fguard.git /opt/aegisguard
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
      match:
        macaddress: ${WAN_MAC}
      set-name: ${WAN_IF}
      dhcp4: true
    ${LAN_IF}:
      match:
        macaddress: ${LAN_MAC}
      set-name: ${LAN_IF}
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

# NAT + Firewall — atomic restore to avoid partial-state races with aegisguard service
mkdir -p /etc/iptables
cat > /etc/iptables/rules.v4 << IPRULES
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:AEGISGUARD_FORWARD - [0:0]
:AEGISGUARD_INPUT - [0:0]
:AEGISGUARD_OUTPUT - [0:0]
-A INPUT -i ${WAN_IF} -p tcp --dport 22 -j DROP
-A INPUT -i ${WAN_IF} -p tcp --dport 80 -j DROP
-A INPUT -i ${WAN_IF} -p tcp --dport 443 -j DROP
-A INPUT -i ${WAN_IF} -p tcp --dport 8080 -j DROP
-A INPUT -i ${WAN_IF} -p tcp --dport 53 -j DROP
-A INPUT -i ${WAN_IF} -p udp --dport 53 -j DROP
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -i ${LAN_IF} -j ACCEPT
-A INPUT -i ${WAN_IF} -p udp --dport 1194 -j ACCEPT
-A INPUT -i ${WAN_IF} -p tcp --dport 1194 -j ACCEPT
-A INPUT -i ${WAN_IF} -p udp --dport 51820 -j ACCEPT
-A INPUT -i ${WAN_IF} -p udp --dport 500 -j ACCEPT
-A INPUT -i ${WAN_IF} -p udp --dport 4500 -j ACCEPT
-A INPUT -i tun0 -j ACCEPT
-A INPUT -j AEGISGUARD_INPUT
-A INPUT -i ${WAN_IF} -j DROP
-A FORWARD -i ${LAN_IF} -o ${WAN_IF} -j ACCEPT
-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -j AEGISGUARD_FORWARD
-A OUTPUT -j AEGISGUARD_OUTPUT
-A AEGISGUARD_FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
-A AEGISGUARD_INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A AEGISGUARD_INPUT -i lo -j ACCEPT
-A AEGISGUARD_OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -o ${WAN_IF} -j MASQUERADE
COMMIT
IPRULES
iptables-restore < /etc/iptables/rules.v4
netfilter-persistent save 2>/dev/null || true
log "NAT + Firewall configured"

# SSH hardening — block WAN via iptables (already above), listen on all interfaces
# so SSH always works on LAN regardless of IP or interface name after reboot
# Ubuntu 26.04 uses ssh.socket (systemd socket activation) — disable it
systemctl stop ssh.socket 2>/dev/null || true
systemctl disable ssh.socket 2>/dev/null || true
# Remove any ListenAddress restrictions — let sshd bind 0.0.0.0 (iptables handles WAN block)
sed -i '/^ListenAddress/d' /etc/ssh/sshd_config.d/50-cloud-init.conf 2>/dev/null || true
sed -i '/^ListenAddress/d' /etc/ssh/sshd_config
# Disable root login
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart ssh
log "SSH hardened: WAN blocked via iptables, LAN always accessible (PermitRootLogin no)"

# fail2ban — brute-force protection for SSH
DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban > /dev/null 2>&1 || true
mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/aegisguard-ssh.conf << 'F2BEOF'
[DEFAULT]
banaction = iptables-multiport

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
bantime  = 3600
findtime = 600
F2BEOF
systemctl enable fail2ban 2>/dev/null || true
systemctl restart fail2ban 2>/dev/null || true
log "fail2ban enabled (SSH brute-force protection)"

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
except-interface=${WAN_IF}

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
# Ensure dhcp_config uses the correct LAN interface (not a stale default from db schema)
conn.execute("UPDATE dhcp_config SET interface='${LAN_IF}' WHERE id=1")
conn.commit()
conn.close()
print("Database initialized with LAN=${LAN_IF}")
PYEOF

# VPN auth scripts
cp /opt/aegisguard/build/server-configs/vpn-auth.sh /etc/aegisguard/vpn-auth.sh 2>/dev/null || true
cp /opt/aegisguard/build/server-configs/vpn_auth_check.py /etc/aegisguard/vpn_auth_check.py 2>/dev/null || true
chmod +x /etc/aegisguard/vpn-auth.sh 2>/dev/null || true

# Tunnel watchdog scripts (WireGuard endpoint updater + IPSec watchdog)
cp /opt/aegisguard/build/server-configs/fguard-wg-updater.sh /usr/local/bin/fguard-wg-updater.sh
cp /opt/aegisguard/build/server-configs/fguard-ipsec-watchdog.sh /usr/local/bin/fguard-ipsec-watchdog.sh
chmod 755 /usr/local/bin/fguard-wg-updater.sh /usr/local/bin/fguard-ipsec-watchdog.sh
chown root:root /usr/local/bin/fguard-wg-updater.sh /usr/local/bin/fguard-ipsec-watchdog.sh
cat > /etc/cron.d/fguard-tunnel-watchdog << 'CRONEOF'
# FGUARD UTC WireGuard endpoint updater + IPSec watchdog
*/2 * * * * root /usr/local/bin/fguard-wg-updater.sh
*/2 * * * * root /usr/local/bin/fguard-ipsec-watchdog.sh
CRONEOF
chmod 644 /etc/cron.d/fguard-tunnel-watchdog
chown root:root /etc/cron.d/fguard-tunnel-watchdog
log "Tunnel watchdog scripts installed"

systemctl start aegisguard
sleep 3

# MOTD
cat > /etc/motd << 'MOTD'

  ╔══════════════════════════════════════════════════════╗
  ║           FGUARD UTC Network Security v1.0           ║
  ║                                                      ║
  ║  Web UI:  https://10.0.0.1:8080  (LAN only)          ║
  ║  SSH:     ssh admin@10.0.0.1     (LAN only)          ║
  ║                                                      ║
  ║  Default login: admin / admin                        ║
  ║  Change password after first login!                  ║
  ╚══════════════════════════════════════════════════════╝

MOTD

STATUS=$(systemctl is-active aegisguard)
log "FGUARD UTC: $STATUS"

echo ""
echo -e "${G}  ╔══════════════════════════════════════════════╗${NC}"
echo -e "${G}  ║   FGUARD UTC installed successfully!         ║${NC}"
echo -e "${G}  ║                                              ║${NC}"
echo -e "${G}  ║   Web UI: https://10.0.0.1:8080             ║${NC}"
echo -e "${G}  ║   Login:  admin / admin                      ║${NC}"
echo -e "${G}  ║                                              ║${NC}"
echo -e "${G}  ║   Connect PC to ${LAN_IF} port              ║${NC}"
echo -e "${G}  ╚══════════════════════════════════════════════╝${NC}"
echo ""
echo "Log: $LOGFILE"
