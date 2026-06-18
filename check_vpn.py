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
    chan.exec_command(f"echo {pw} | sudo -S {cmd} 2>&1")
    time.sleep(wait)
    return chan.recv(65535).decode("utf-8", errors="replace")

def pr(title, txt):
    sys.stdout.buffer.write(f"\n=== {title} ===\n".encode())
    sys.stdout.buffer.write(txt.encode("utf-8", errors="replace"))
    sys.stdout.buffer.flush()

pr("Full OpenVPN server conf", run("cat /opt/aegisguard/ssl-vpn-server.conf | grep -v 'BEGIN\\|END\\|MII\\|^[A-Za-z0-9+/]'", 3))

pr("iptables FORWARD", run("iptables -L FORWARD -n -v --line-numbers", 2))

pr("VPN tun0 interface", run("ip addr show tun0 2>/dev/null || echo 'tun0 not up (no clients connected)'", 2))

pr("Routes", run("ip route show", 2))

c.close()
sys.stdout.buffer.write(b"\n=== DONE ===\n")
sys.stdout.buffer.flush()
