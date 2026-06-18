import paramiko, time, sys

host = "192.168.100.145"
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

pr("LOG LAST 15", run("tail -15 /var/log/aegisguard-install.log 2>/dev/null || echo NO_LOG", 3))
pr("PIP RUNNING?", run("pgrep -a python 2>/dev/null | head -5 || echo none", 2))
pr("INSTALL RUNNING?", run("pgrep -a bash | grep install | head -5 || echo none", 2))
pr("INTERFACES", run("ip addr show eth1 | grep inet", 2))
pr("SERVICES", run("systemctl is-active aegisguard nginx dnsmasq 2>/dev/null", 2))

c.close()
