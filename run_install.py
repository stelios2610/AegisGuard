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
    chan.exec_command(f"echo {pw} | sudo -S bash -c \"{cmd}\" 2>&1")
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

# Kill stuck processes
pr("Kill stuck", run("pkill -9 -f 'wget.*install' 2>/dev/null || true; pkill -9 -f 'nohup bash' 2>/dev/null || true; sleep 1; echo done", 3))

# Run install as root in background
pr("Start install as root", run(
    "nohup bash /tmp/install.sh > /var/log/aegisguard-install.log 2>&1 & echo PID=$!", 3
))

print("\nInstall started! Monitoring log every 20s...")

# Monitor progress
for i in range(30):
    time.sleep(20)
    chan = c.get_transport().open_session()
    chan.get_pty()
    chan.exec_command(f"echo {pw} | sudo -S tail -5 /var/log/aegisguard-install.log 2>&1")
    time.sleep(3)
    out = chan.recv(65535).decode("utf-8", errors="replace")
    sys.stdout.buffer.write(f"\n--- [{(i+1)*20}s] ---\n".encode())
    sys.stdout.buffer.write(out.encode("utf-8", errors="replace"))
    sys.stdout.buffer.flush()
    if "successfully" in out or "installed successfully" in out.lower():
        break

c.close()
sys.stdout.buffer.write(b"\n=== DONE ===\n")
sys.stdout.buffer.flush()
