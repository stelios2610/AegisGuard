"""Application Control - manage per-application network access via Windows Firewall."""
import subprocess
import os
import psutil
from db import database


def _run_netsh(args):
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall"] + args,
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        return False, str(e)


def _rule_name(app_rule):
    return f"AegisGuard-App-{app_rule['id']}-{app_rule['name']}"


def sync_app_rule(app_rule):
    name = _rule_name(app_rule)
    _run_netsh(["delete", "rule", f"name={name}"])

    if not app_rule["enabled"]:
        return True, "Disabled"

    action = "allow" if app_rule["action"] == "ALLOW" else "block"
    direction = app_rule.get("direction", "BOTH")
    dirs = ["in", "out"] if direction == "BOTH" else [direction.lower()]
    exe = app_rule["exe_path"]

    for d in dirs:
        args = [
            "add", "rule",
            f"name={name}",
            f"dir={d}",
            f"action={action}",
            f"program={exe}",
            "enable=yes",
        ]
        ok, msg = _run_netsh(args)
        if not ok:
            return False, msg
    return True, "OK"


def remove_app_rule(app_rule):
    name = _rule_name(app_rule)
    return _run_netsh(["delete", "rule", f"name={name}"])


def sync_all_app_rules():
    rules = database.get_app_rules()
    results = []
    for rule in rules:
        ok, msg = sync_app_rule(rule)
        results.append((rule["name"], ok, msg))
    return results


def get_running_apps():
    """Return list of running processes with network connections."""
    apps = {}
    try:
        for proc in psutil.process_iter(["pid", "name", "exe", "status"]):
            try:
                info = proc.info
                exe = info.get("exe") or ""
                name = info.get("name") or f"PID {info['pid']}"
                if exe and exe not in apps:
                    conns = proc.net_connections()
                    if conns:
                        apps[exe] = {"name": name, "exe": exe, "connections": len(conns),
                                     "pid": info["pid"]}
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass
    return list(apps.values())


def block_process_now(pid):
    """Immediately terminate all connections for a PID (best-effort)."""
    try:
        proc = psutil.Process(pid)
        exe = proc.exe()
        name = proc.name()
        # Add a temporary block rule
        tmp_name = f"AegisGuard-TempBlock-{pid}"
        _run_netsh(["delete", "rule", f"name={tmp_name}"])
        for d in ["in", "out"]:
            _run_netsh(["add", "rule", f"name={tmp_name}",
                        f"dir={d}", "action=block", f"program={exe}", "enable=yes"])
        return True, f"Blocked {name} (PID {pid})"
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return False, str(e)
