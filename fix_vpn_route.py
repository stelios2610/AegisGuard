import paramiko, time, sys

host = "10.0.0.1"
user = "stelios"
pw = "Balloteli1997"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(host, username=user, password=pw, timeout=10)

def run(cmd, wait=3):
    chan = c.get_transport().open_session()
    chan.get_pty()
    chan.exec_command(f"echo {pw} | sudo -S bash -c '{cmd}' 2>&1")
    time.sleep(wait)
    return chan.recv(65535).decode("utf-8", errors="replace")

def pr(title, txt):
    sys.stdout.buffer.write(f"\n=== {title} ===\n".encode())
    sys.stdout.buffer.write(txt.encode("utf-8", errors="replace"))
    sys.stdout.buffer.flush()

# Fix FORWARD rules
pr("Add tun0↔eth1 FORWARD rules", run(
    "iptables -C FORWARD -i tun0 -o eth1 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i tun0 -o eth1 -j ACCEPT; "
    "iptables -C FORWARD -i eth1 -o tun0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i eth1 -o tun0 -j ACCEPT; "
    "echo done"
    , 3))

# Also add MASQUERADE for VPN clients accessing LAN
pr("Add MASQUERADE for VPN→LAN", run(
    "iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o eth1 -j MASQUERADE 2>/dev/null || "
    "iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth1 -j MASQUERADE; echo done"
    , 2))

# Save iptables
pr("Save iptables", run("netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4; echo saved", 3))

# Fix OpenVPN log permission and restart
pr("Fix log + restart OpenVPN", run(
    "touch /var/log/aegisguard-ssl-vpn.log; "
    "chown root:root /var/log/aegisguard-ssl-vpn.log; "
    "pkill openvpn 2>/dev/null || true; sleep 1; "
    "openvpn --config /opt/aegisguard/ssl-vpn-server.conf --daemon; "
    "sleep 2; pgrep -a openvpn && echo 'OpenVPN running' || echo 'FAILED'"
    , 6))

# Verify
pr("Server conf routes", run("grep 'push\\|route' /opt/aegisguard/ssl-vpn-server.conf | grep -v '#'", 2))
pr("FORWARD rules", run("iptables -L FORWARD -n --line-numbers", 2))
pr("NAT rules", run("iptables -t nat -L POSTROUTING -n", 2))

c.close()
sys.stdout.buffer.write(b"\n=== DONE ===\n")
sys.stdout.buffer.flush()
