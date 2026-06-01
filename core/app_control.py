"""Application Control - per-application firewall rules (Linux: iptables owner, Windows: netsh)."""
import subprocess
import os
import psutil
from db import database
from core.platform import IS_LINUX, run


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _rule_name(app_rule):
    return f"AegisGuard-App-{app_rule['id']}-{app_rule['name']}"


def _get_uids_for_exe(exe_path):
    """Return set of real UIDs currently running this executable."""
    uids = set()
    try:
        for proc in psutil.process_iter(["exe", "uids"]):
            try:
                if proc.info.get("exe") == exe_path:
                    uids.add(proc.uids().real)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass
    return uids


# ─── Linux backend (iptables owner match) ────────────────────────────────────

def _ipt_comment(app_rule):
    return f"aegisguard_app_{app_rule['id']}"


def _remove_app_rule_linux(app_rule):
    tag = _ipt_comment(app_rule)
    for chain in ("INPUT", "OUTPUT"):
        while True:
            ok, out, _ = run(["iptables", "-L", chain, "--line-numbers", "-n"])
            if not ok:
                break
            lines = [l for l in out.splitlines() if tag in l]
            if not lines:
                break
            num = lines[0].split()[0]
            run(["iptables", "-D", chain, num])
    return True, "OK"


def sync_app_rule_linux(app_rule):
    _remove_app_rule_linux(app_rule)

    if not app_rule["enabled"]:
        return True, "Disabled"

    exe = app_rule.get("exe_path", "")
    uids = _get_uids_for_exe(exe)
    if not uids:
        return True, f"Rule saved — process not running, will apply on next sync"

    action    = "ACCEPT" if app_rule["action"] == "ALLOW" else "DROP"
    direction = app_rule.get("direction", "BOTH")
    comment   = _ipt_comment(app_rule)

    chains = []
    if direction in ("OUT", "BOTH"):
        chains.append("OUTPUT")
    if direction in ("IN", "BOTH"):
        chains.append("INPUT")

    for uid in uids:
        for chain in chains:
            args = [
                "iptables", "-A", chain,
                "-m", "owner", "--uid-owner", str(uid),
                "-m", "comment", "--comment", comment,
                "-j", action,
            ]
            ok, out, err = run(args)
            if not ok:
                return False, err

    return True, f"Applied for UID(s): {', '.join(str(u) for u in uids)}"


def remove_app_rule_linux(app_rule):
    return _remove_app_rule_linux(app_rule)


# ─── Windows backend (netsh) ──────────────────────────────────────────────────

def _run_netsh(args):
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall"] + args,
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        return False, str(e)


def sync_app_rule_windows(app_rule):
    name = _rule_name(app_rule)
    _run_netsh(["delete", "rule", f"name={name}"])

    if not app_rule["enabled"]:
        return True, "Disabled"

    action    = "allow" if app_rule["action"] == "ALLOW" else "block"
    direction = app_rule.get("direction", "BOTH")
    dirs      = ["in", "out"] if direction == "BOTH" else [direction.lower()]
    exe       = app_rule["exe_path"]

    for d in dirs:
        args = ["add", "rule", f"name={name}", f"dir={d}",
                f"action={action}", f"program={exe}", "enable=yes"]
        ok, msg = _run_netsh(args)
        if not ok:
            return False, msg
    return True, "OK"


def remove_app_rule_windows(app_rule):
    name = _rule_name(app_rule)
    return _run_netsh(["delete", "rule", f"name={name}"])


# ─── Public API ───────────────────────────────────────────────────────────────

def sync_app_rule(app_rule):
    if IS_LINUX:
        return sync_app_rule_linux(app_rule)
    return sync_app_rule_windows(app_rule)


def remove_app_rule(app_rule):
    if IS_LINUX:
        return remove_app_rule_linux(app_rule)
    return remove_app_rule_windows(app_rule)


def sync_all_app_rules():
    rules = database.get_app_rules()
    results = []
    for rule in rules:
        ok, msg = sync_app_rule(rule)
        results.append((rule["name"], ok, msg))
    return results


def get_running_apps():
    """Return list of running processes that have network connections."""
    apps = {}
    try:
        for proc in psutil.process_iter(["pid", "name", "exe", "uids"]):
            try:
                info  = proc.info
                exe   = info.get("exe") or ""
                name  = info.get("name") or f"PID {info['pid']}"
                if exe and exe not in apps:
                    conns = proc.net_connections()
                    if conns:
                        uid = info.get("uids")
                        apps[exe] = {
                            "name": name,
                            "exe": exe,
                            "connections": len(conns),
                            "pid": info["pid"],
                            "uid": uid.real if uid else None,
                        }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass
    return list(apps.values())


def block_process_now(pid):
    """Best-effort: immediately block all connections for a PID."""
    try:
        proc = psutil.Process(pid)
        exe  = proc.exe()
        name = proc.name()

        if IS_LINUX:
            uid  = proc.uids().real
            for chain in ("INPUT", "OUTPUT"):
                run(["iptables", "-I", chain, "1",
                     "-m", "owner", "--uid-owner", str(uid),
                     "-m", "comment", "--comment", f"aegisguard_block_pid_{pid}",
                     "-j", "DROP"])
            return True, f"Blocked {name} (PID {pid}, UID {uid})"

        tmp_name = f"AegisGuard-TempBlock-{pid}"
        _run_netsh(["delete", "rule", f"name={tmp_name}"])
        for d in ["in", "out"]:
            _run_netsh(["add", "rule", f"name={tmp_name}",
                        f"dir={d}", "action=block", f"program={exe}", "enable=yes"])
        return True, f"Blocked {name} (PID {pid})"

    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return False, str(e)
