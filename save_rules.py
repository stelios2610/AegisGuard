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

# Update sysctl.d to also include rp_filter=1 (loose mode) - avoids asymmetric routing issues
pr("Update sysctl.d config", run(
    "bash -c 'cat > /etc/sysctl.d/99-aegisguard.conf << EOF\n"
    "net.ipv4.ip_forward = 1\n"
    "net.ipv4.conf.all.forwarding = 1\n"
    "net.ipv4.conf.all.rp_filter = 1\n"
    "net.ipv4.conf.eth0.rp_filter = 1\n"
    "net.ipv4.conf.eth1.rp_filter = 1\n"
    "EOF'", 2
))

# Apply now
pr("Apply sysctl now", run("sysctl -p /etc/sysctl.d/99-aegisguard.conf", 2))

# Save current iptables to persist across reboots
pr("Save iptables rules", run("netfilter-persistent save", 3))

pr("Verify sysctl.d", run("cat /etc/sysctl.d/99-aegisguard.conf", 1))
pr("Verify ip_forward", run("sysctl net.ipv4.ip_forward", 1))
pr("Verify saved rules exist", run("ls -la /etc/iptables/rules.v4", 1))

c.close()
sys.stdout.buffer.write(b"\n=== DONE ===\n")
sys.stdout.buffer.flush()
