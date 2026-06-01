"""Branch Office VPN (BOV) Manager - Site-to-Site with all protocols.
Supports: IKEv2/IPSec, IKEv1/IPSec, L2TP/IPSec, SSL/OpenVPN, WireGuard, GRE."""
import os
import subprocess
import threading
from datetime import datetime
from db import database
from core.platform import IS_LINUX, run
from core.vpn_keygen import generate_wireguard_keypair, generate_wireguard_preshared_key

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
STRONGSWAN_CONF = "/etc/ipsec.conf"
STRONGSWAN_SECRETS = "/etc/ipsec.secrets"
STRONGSWAN_D = "/etc/ipsec.d"
WG_CONF_DIR = "/etc/wireguard"
BOV_CONF_DIR = os.path.join(BASE_DIR, "pki", "bov")

_tunnel_processes = {}   # tunnel_id -> process
_tunnel_statuses = {}    # tunnel_id -> "Up"|"Down"|"Error"|"Connecting"


# ══════════════════════════════════════════════════════════════════════════════
# StrongSwan / IPSec (IKEv1 + IKEv2 + L2TP)
# ══════════════════════════════════════════════════════════════════════════════

def _write_strongswan_conf(tunnel):
    """Generate StrongSwan ipsec.conf entry for a BOV tunnel."""
    name = tunnel["name"].replace(" ", "_")
    ike_ver = "2" if tunnel.get("ike_version", "IKEv2") == "IKEv2" else "1"

    # Ciphers
    ike_cipher = f"{tunnel.get('ike_cipher','AES256').lower()}-{tunnel.get('ike_hash','SHA256').lower()}-{tunnel.get('ike_dh','modp2048').lower()}"
    esp_cipher = f"{tunnel.get('esp_cipher','AES256').lower()}-{tunnel.get('esp_hash','SHA256').lower()}-{tunnel.get('pfs_group','modp2048').lower()}"

    # DH group name mapping
    dh_map = {
        "DH14": "modp2048", "DH15": "modp3072", "DH16": "modp4096",
        "DH19": "ecp256", "DH20": "ecp384", "DH21": "ecp521",
    }
    ike_dh = dh_map.get(tunnel.get("ike_dh", "DH14"), "modp2048")
    pfs_dh = dh_map.get(tunnel.get("pfs_group", "DH14"), "modp2048")

    ike_proposal = f"{tunnel.get('ike_cipher','aes256').lower()}-{tunnel.get('ike_hash','sha256').lower()}-{ike_dh}"
    esp_proposal = f"{tunnel.get('esp_cipher','aes256').lower()}-{tunnel.get('esp_hash','sha256').lower()}-{pfs_dh}"

    left_subnets = tunnel.get("local_subnets", "")
    right_subnets = tunnel.get("remote_subnets", "")

    if tunnel.get("type") == "L2TP-IPSec":
        return _write_l2tp_conf(tunnel)

    conf = f"""
conn {name}
    keyexchange=ikev{ike_ver}
    left=%defaultroute
    leftid={tunnel.get('local_gateway','%defaultroute') or '%defaultroute'}
    leftsubnet={left_subnets or '0.0.0.0/0'}
    right={tunnel['remote_gateway']}
    rightid={tunnel['remote_gateway']}
    rightsubnet={right_subnets}
    ike={ike_proposal}!
    esp={esp_proposal}!
    ikelifetime={tunnel.get('ike_lifetime',28800)}s
    lifetime={tunnel.get('esp_lifetime',3600)}s
    {'dpdaction=restart' if tunnel.get('dpd_enabled',1) else 'dpdaction=none'}
    dpddelay={tunnel.get('dpd_interval',30)}s
    dpdtimeout={tunnel.get('dpd_timeout',120)}s
    {'aggressive=yes' if tunnel.get('aggressive_mode') else 'aggressive=no'}
    {'forceencaps=yes' if tunnel.get('nat_traversal',1) else ''}
    authby=secret
    auto={'start' if tunnel.get('enabled',1) else 'ignore'}
    type=tunnel
"""
    return conf


def _write_l2tp_conf(tunnel):
    name = tunnel["name"].replace(" ", "_")
    return f"""
conn {name}-l2tp
    keyexchange=ikev1
    left=%defaultroute
    right={tunnel['remote_gateway']}
    authby=secret
    auto={'start' if tunnel.get('enabled',1) else 'ignore'}
    type=transport
    rightprotoport=17/1701
    leftprotoport=17/%any
"""


def _write_strongswan_secrets(tunnels):
    lines = ["# AegisGuard StrongSwan secrets"]
    for t in tunnels:
        if t.get("psk") and t["type"] in ("IKEv2", "IKEv1", "L2TP-IPSec"):
            local = t.get("local_gateway") or "%any"
            remote = t.get("remote_gateway", "%any")
            lines.append(f'{local} {remote} : PSK "{t["psk"]}"')
    return "\n".join(lines) + "\n"


def apply_ipsec_tunnels():
    """Write StrongSwan config and reload (auto-installs strongswan if missing)."""
    if not IS_LINUX:
        return False, "IPSec management requires Linux"

    # Auto-install strongswan if not present
    ok_check, _, _ = run(["which", "ipsec"])
    if not ok_check:
        database.add_log("INFO", details="IPSec: installing strongswan...")
        run(["apt-get", "install", "-y",
             "strongswan", "strongswan-swanctl", "charon-systemd"], timeout=180)

    tunnels = database.get_bov_tunnels()
    ipsec_tunnels = [t for t in tunnels if t["type"] in ("IKEv2", "IKEv1", "L2TP-IPSec")]
    if not ipsec_tunnels:
        return True, "No IPSec tunnels to apply"

    conf_content = "# AegisGuard IPSec config\n# Generated: " + datetime.now().isoformat() + "\n"
    conf_content += "config setup\n    charondebug=\"ike 2, knl 1, cfg 0\"\n\n"
    conf_content += 'conn %default\n    ikelifetime=60m\n    keylife=20m\n    rekeymargin=3m\n    keyingtries=1\n\n'

    for t in ipsec_tunnels:
        conf_content += _write_strongswan_conf(t)

    secrets_content = _write_strongswan_secrets(ipsec_tunnels)

    try:
        with open(STRONGSWAN_CONF, "w") as f:
            f.write(conf_content)
        with open(STRONGSWAN_SECRETS, "w") as f:
            f.write(secrets_content)
        os.chmod(STRONGSWAN_SECRETS, 0o600)
        ok, out, err = run(["ipsec", "reload"])
        return ok, out if ok else err
    except Exception as e:
        return False, str(e)


def connect_ipsec_tunnel(tunnel):
    """Bring up a specific IPSec tunnel."""
    name = tunnel["name"].replace(" ", "_")
    ok, out, err = run(["ipsec", "up", name], timeout=30)
    if ok:
        database.update_bov_tunnel(tunnel["id"], status="Up", last_up=datetime.now().isoformat())
        database.add_log("INFO", details=f"BOV IPSec UP: {tunnel['name']}")
    else:
        database.update_bov_tunnel(tunnel["id"], status="Error")
    return ok, out if ok else err


def disconnect_ipsec_tunnel(tunnel):
    name = tunnel["name"].replace(" ", "_")
    ok, out, err = run(["ipsec", "down", name], timeout=15)
    database.update_bov_tunnel(tunnel["id"], status="Down")
    database.add_log("INFO", details=f"BOV IPSec DOWN: {tunnel['name']}")
    return ok, out if ok else err


def get_ipsec_status():
    ok, out, _ = run(["ipsec", "status"])
    return out if ok else "ipsec not available"


# ══════════════════════════════════════════════════════════════════════════════
# WireGuard Site-to-Site (Hub-Spoke)
# ══════════════════════════════════════════════════════════════════════════════

def _write_wireguard_site_config(tunnel):
    """Generate WireGuard .conf for site-to-site tunnel."""
    conf = f"""# AegisGuard BOV WireGuard - {tunnel['name']}
[Interface]
PrivateKey = {tunnel.get('wg_private_key','')}
ListenPort = {tunnel.get('wg_port',51820)}
# Add local tunnel IP if needed:
# Address = 10.254.0.1/30

[Peer]
PublicKey = {tunnel.get('wg_peer_pubkey','')}
{'PresharedKey = ' + tunnel.get('wg_preshared_key','') if tunnel.get('wg_preshared_key') else ''}
Endpoint = {tunnel['remote_gateway']}:{tunnel.get('wg_port',51820)}
AllowedIPs = {tunnel.get('remote_subnets','0.0.0.0/0')}
PersistentKeepalive = {tunnel.get('wg_keepalive',25)}
"""
    return conf


def apply_wireguard_tunnel(tunnel):
    """Write WireGuard config and bring up interface."""
    os.makedirs(WG_CONF_DIR, exist_ok=True)
    iface_name = f"wg-bov-{tunnel['id']}"
    conf_path = os.path.join(WG_CONF_DIR, f"{iface_name}.conf")

    conf = _write_wireguard_site_config(tunnel)
    try:
        with open(conf_path, "w") as f:
            f.write(conf)
        os.chmod(conf_path, 0o600)
    except Exception as e:
        return False, str(e)

    if IS_LINUX:
        run(["wg-quick", "down", conf_path])
        ok, out, err = run(["wg-quick", "up", conf_path], timeout=15)
        if ok:
            database.update_bov_tunnel(tunnel["id"], status="Up", last_up=datetime.now().isoformat())
            database.add_log("INFO", details=f"BOV WireGuard UP: {tunnel['name']}")
        return ok, out if ok else err
    return True, f"Config written: {conf_path}"


def disconnect_wireguard_tunnel(tunnel):
    iface_name = f"wg-bov-{tunnel['id']}"
    conf_path = os.path.join(WG_CONF_DIR, f"{iface_name}.conf")
    if IS_LINUX and os.path.isfile(conf_path):
        ok, out, err = run(["wg-quick", "down", conf_path])
    database.update_bov_tunnel(tunnel["id"], status="Down")
    return True, "Disconnected"


# ══════════════════════════════════════════════════════════════════════════════
# SSL/OpenVPN Site-to-Site
# ══════════════════════════════════════════════════════════════════════════════

def _write_ssl_site_config(tunnel, mode="server"):
    """Generate OpenVPN site-to-site config."""
    is_server = (mode == "server")

    def _block(tag, content):
        return f"<{tag}>\n{content.strip()}\n</{tag}>\n" if content else ""

    conf = f"""# AegisGuard BOV SSL - {tunnel['name']} ({mode})
# Generated: {datetime.now().isoformat()}

{'dev tun' if is_server else 'dev tun'}
proto {tunnel.get('ssl_protocol','udp')}
{'port ' + str(tunnel.get('ssl_port',1194)) if is_server else 'remote ' + tunnel['remote_gateway'] + ' ' + str(tunnel.get('ssl_port',1194))}
{'server-bridge' if not is_server else ''}

{_block('ca', tunnel.get('ssl_ca_cert',''))}
{_block('cert', tunnel.get('ssl_cert',''))}
{_block('key', tunnel.get('ssl_key',''))}
{_block('tls-auth', tunnel.get('ssl_ta_key',''))}
key-direction {'0' if is_server else '1'}

cipher {tunnel.get('ssl_cipher','AES-256-GCM')}
auth SHA256
compress lz4-v2

{'ifconfig 10.254.0.1 10.254.0.2' if is_server else 'ifconfig 10.254.0.2 10.254.0.1'}
route {tunnel.get('remote_subnets','').split(',')[0].strip()} 255.255.255.0

keepalive 10 120
persist-key
persist-tun
verb 3
"""
    return conf


def apply_ssl_site_tunnel(tunnel):
    """Start OpenVPN site-to-site tunnel."""
    os.makedirs(BOV_CONF_DIR, exist_ok=True)
    conf_path = os.path.join(BOV_CONF_DIR, f"bov-ssl-{tunnel['id']}.conf")
    conf = _write_ssl_site_config(tunnel, mode="client")

    try:
        with open(conf_path, "w") as f:
            f.write(conf)
    except Exception as e:
        return False, str(e)

    exe = database.get_setting("vpn_openvpn_path", "openvpn")
    try:
        proc = subprocess.Popen([exe, "--config", conf_path],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _tunnel_processes[tunnel["id"]] = proc
        database.update_bov_tunnel(tunnel["id"], status="Connecting")
        threading.Timer(5, lambda: _check_ssl_up(tunnel, proc)).start()
        return True, f"SSL tunnel connecting (PID {proc.pid})"
    except Exception as e:
        return False, str(e)


def _check_ssl_up(tunnel, proc):
    if proc.poll() is None:
        database.update_bov_tunnel(tunnel["id"], status="Up", last_up=datetime.now().isoformat())
        database.add_log("INFO", details=f"BOV SSL UP: {tunnel['name']}")
    else:
        database.update_bov_tunnel(tunnel["id"], status="Error")


# ══════════════════════════════════════════════════════════════════════════════
# Generic connect/disconnect dispatcher
# ══════════════════════════════════════════════════════════════════════════════

def connect_tunnel(tunnel):
    t = tunnel["type"]
    if t in ("IKEv2", "IKEv1", "L2TP-IPSec"):
        apply_ipsec_tunnels()
        return connect_ipsec_tunnel(tunnel)
    elif t == "WireGuard":
        return apply_wireguard_tunnel(tunnel)
    elif t == "SSL-OpenVPN":
        return apply_ssl_site_tunnel(tunnel)
    return False, f"Protocol {t} not yet implemented"


def disconnect_tunnel(tunnel):
    t = tunnel["type"]
    if t in ("IKEv2", "IKEv1", "L2TP-IPSec"):
        return disconnect_ipsec_tunnel(tunnel)
    elif t == "WireGuard":
        return disconnect_wireguard_tunnel(tunnel)
    elif t == "SSL-OpenVPN":
        proc = _tunnel_processes.pop(tunnel["id"], None)
        if proc and proc.poll() is None:
            proc.terminate()
        database.update_bov_tunnel(tunnel["id"], status="Down")
        return True, "Disconnected"
    return False, f"Protocol {t} not supported"


def get_tunnel_status(tunnel_id):
    proc = _tunnel_processes.get(tunnel_id)
    if proc:
        return "Up" if proc.poll() is None else "Down"
    return None


# ── Config export ─────────────────────────────────────────────────────────────

def export_peer_config(tunnel):
    """Generate the configuration for the REMOTE peer (to paste on the other side)."""
    t = tunnel["type"]
    name = tunnel["name"]

    if t == "WireGuard":
        # Generate reverse config for remote peer
        conf = f"""# AegisGuard BOV - Remote peer config for '{name}'
# Paste this on the REMOTE WireGuard device

[Interface]
# Generate your own private key: wg genkey
# PrivateKey = <YOUR_PRIVATE_KEY>
ListenPort = {tunnel.get('wg_port',51820)}

[Peer]
PublicKey = {tunnel.get('wg_public_key','<LOCAL_PUBLIC_KEY>')}
{'PresharedKey = ' + tunnel.get('wg_preshared_key','') if tunnel.get('wg_preshared_key') else ''}
Endpoint = <YOUR_LOCAL_PUBLIC_IP>:{tunnel.get('wg_port',51820)}
AllowedIPs = {tunnel.get('local_subnets','0.0.0.0/0')}
PersistentKeepalive = {tunnel.get('wg_keepalive',25)}
"""
        return conf

    elif t in ("IKEv2", "IKEv1"):
        return f"""# StrongSwan config for REMOTE peer '{name}'
# Add to /etc/ipsec.conf on remote device

conn {name.replace(' ','_')}-remote
    keyexchange={t.lower()}
    left=%defaultroute
    leftsubnet={tunnel.get('remote_subnets','')}
    right=<LOCAL_GATEWAY_IP>
    rightsubnet={tunnel.get('local_subnets','')}
    ike={tunnel.get('ike_cipher','aes256').lower()}-{tunnel.get('ike_hash','sha256').lower()}-{'modp2048'}!
    esp={tunnel.get('esp_cipher','aes256').lower()}-{tunnel.get('esp_hash','sha256').lower()}!
    authby=secret
    auto=start

# /etc/ipsec.secrets on remote:
# %any <LOCAL_GATEWAY_IP> : PSK "{tunnel.get('psk','')}"
"""

    elif t == "SSL-OpenVPN":
        return _write_ssl_site_config(tunnel, mode="server")

    return f"# No peer config template for protocol {t}"
