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
    chan.exec_command(cmd)
    time.sleep(wait)
    return chan.recv(65535).decode("utf-8", errors="replace")

def pr(title, txt):
    sys.stdout.buffer.write(f"\n=== {title} ===\n".encode())
    sys.stdout.buffer.write(txt.encode("utf-8", errors="replace"))
    sys.stdout.buffer.flush()

pr("interfaces", run("ip addr show", 2))
pr("processes", run("ps aux | grep -E 'wget|bash|install' | grep -v grep", 1))
pr("install log", run("tail -20 /var/log/aegisguard-install.log 2>/dev/null || echo NO_LOG", 2))
pr("apt running?", run("pgrep -a apt 2>/dev/null || echo 'apt not running'", 1))

c.close()
