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

def run_plain(cmd, wait=2):
    chan = c.get_transport().open_session()
    chan.get_pty()
    chan.exec_command(cmd)
    time.sleep(wait)
    return chan.recv(65535).decode("utf-8", errors="replace")

def pr(title, txt):
    sys.stdout.buffer.write(f"\n=== {title} ===\n".encode())
    sys.stdout.buffer.write(txt.encode("utf-8", errors="replace"))
    sys.stdout.buffer.flush()

pr("NETPLAN configs", run("ls /etc/netplan/ && echo '---' && cat /etc/netplan/*.yaml", 2))
pr("dnsmasq AegisGuard config", run("grep -A200 'AegisGuard DHCP' /etc/dnsmasq.conf | head -20", 1))
pr("sysctl.d aegisguard", run("cat /etc/sysctl.d/99-aegisguard.conf", 1))
pr("iptables rules.v4", run("cat /etc/iptables/rules.v4", 1))
pr("nginx config", run("cat /etc/nginx/sites-enabled/aegisguard 2>/dev/null || cat /etc/nginx/conf.d/aegisguard.conf 2>/dev/null || echo 'NOT FOUND'", 1))
pr("systemd aegisguard service", run("cat /etc/systemd/system/aegisguard.service", 1))
pr("fail2ban jail", run("cat /etc/fail2ban/jail.d/aegisguard.conf 2>/dev/null || echo NOT_FOUND", 1))
pr("first-boot service", run("cat /etc/systemd/system/aegisguard-firstboot.service 2>/dev/null || echo NOT_FOUND", 1))
pr("hostname", run_plain("hostname", 1))
pr("os version", run_plain("cat /etc/os-release | head -5", 1))

c.close()
sys.stdout.buffer.write(b"\n=== DONE ===\n")
sys.stdout.buffer.flush()
