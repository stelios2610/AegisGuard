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

# Add tun0 to INPUT chain
pr("Add tun0 INPUT rule", run(
    "iptables -C INPUT -i tun0 -j ACCEPT 2>/dev/null || iptables -A INPUT -i tun0 -j ACCEPT; echo done", 2))

# Save
pr("Save iptables", run("netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4; echo saved", 3))

# Test ping from server to client
pr("Ping client 10.8.0.2", run("ping -c 2 -W 2 10.8.0.2 2>&1", 5))

# Verify INPUT
pr("INPUT rules", run("iptables -L INPUT -n --line-numbers | grep -E 'tun|ACCEPT|DROP|policy'", 2))

c.close()
sys.stdout.buffer.write(b"\n=== DONE ===\n")
sys.stdout.buffer.flush()
