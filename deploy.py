import paramiko, time, sys

host = "10.0.0.1"
user = "stelios"
pw = "Balloteli1997"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(host, username=user, password=pw, timeout=10)

def run(cmd, wait=4):
    chan = c.get_transport().open_session()
    chan.get_pty()
    chan.exec_command(f"echo {pw} | sudo -S {cmd} 2>&1")
    time.sleep(wait)
    return chan.recv(65535).decode("utf-8", errors="replace")

def pr(title, txt):
    sys.stdout.buffer.write(f"\n=== {title} ===\n".encode())
    sys.stdout.buffer.write(txt.encode("utf-8", errors="replace"))
    sys.stdout.buffer.flush()

pr("git pull", run("git -C /opt/aegisguard pull", 8))
pr("restart aegisguard", run("systemctl restart aegisguard", 5))
pr("status", run("systemctl is-active aegisguard nginx dnsmasq", 2))
pr("commit", run("git -C /opt/aegisguard log --oneline -3", 2))

c.close()
sys.stdout.buffer.write(b"\n=== DONE ===\n")
sys.stdout.buffer.flush()
