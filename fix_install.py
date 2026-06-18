import paramiko, time, sys

host = "192.168.100.145"
user = "stelios"
pw = "Balloteli1997"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(host, username=user, password=pw, timeout=10)

def run(cmd, wait=5):
    chan = c.get_transport().open_session()
    chan.get_pty()
    chan.exec_command(f"echo {pw} | sudo -S bash -c '{cmd}' 2>&1")
    time.sleep(wait)
    out = b""
    while chan.recv_ready():
        out += chan.recv(65535)
    if not out:
        out = chan.recv(65535)
    return out.decode("utf-8", errors="replace")

def pr(title, txt):
    sys.stdout.buffer.write(f"\n=== {title} ===\n".encode())
    sys.stdout.buffer.write(txt.encode("utf-8", errors="replace"))
    sys.stdout.buffer.flush()

pr("venv exists?", run("ls /opt/aegisguard/venv/bin/ 2>/dev/null | head -5 || echo NO_VENV", 3))

pr("pip test", run("/opt/aegisguard/venv/bin/pip install --upgrade pip 2>&1 | tail -5", 15))

pr("pip install packages", run(
    "/opt/aegisguard/venv/bin/pip install "
    "fastapi 'uvicorn[standard]' jinja2 pydantic python-multipart "
    "psutil bcrypt qrcode pillow python-dotenv PyYAML 2>&1 | tail -10", 60))

pr("verify", run("/opt/aegisguard/venv/bin/python -c 'import fastapi; print(fastapi.__version__)' 2>&1", 5))

c.close()
sys.stdout.buffer.write(b"\n=== DONE ===\n")
sys.stdout.buffer.flush()
