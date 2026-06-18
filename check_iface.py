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

pr("git pull", run("git -C /opt/aegisguard pull", 6))
pr("restart", run("systemctl restart aegisguard", 4))
pr("status", run("systemctl is-active aegisguard", 2))
pr("commit", run("git -C /opt/aegisguard log --oneline -3", 2))

# Check interfaces in DB
pr("interfaces in DB", run(
    "python3 -c \""
    "import sys; sys.path.insert(0,'/opt/aegisguard'); "
    "from db import database; "
    "[print(dict(i)) for i in database.get_interfaces()]\"", 3))

c.close()
sys.stdout.buffer.write(b"\n=== DONE ===\n")
sys.stdout.buffer.flush()
