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

pr("tun0 IP", run("ip addr show tun0", 2))
pr("VPN clients connected", run("cat /var/log/aegisguard-ssl-vpn-status.log 2>/dev/null || echo NO_STATUS", 2))
pr("OpenVPN process", run("pgrep -a openvpn", 2))
pr("FORWARD chain", run("iptables -L FORWARD -n -v --line-numbers", 2))
pr("INPUT chain (tun0 allowed?)", run("iptables -L INPUT -n | grep -E 'tun|10.8' || echo 'no tun rules in INPUT'", 2))
pr("Route on server", run("ip route show", 2))
pr("iptables nat", run("iptables -t nat -L -n -v", 2))
pr("Ping 10.8.0.x from server", run("ping -c 2 -W 2 10.8.0.2 2>&1 || echo UNREACHABLE", 5))

c.close()
sys.stdout.buffer.write(b"\n=== DONE ===\n")
sys.stdout.buffer.flush()
