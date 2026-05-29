"""Intrusion Prevention System - signature-based threat detection."""
import re
import threading
import time
import psutil
from collections import defaultdict, deque
from datetime import datetime
from db import database

_lock = threading.Lock()
_connection_counts = defaultdict(lambda: deque(maxlen=100))  # ip -> timestamps
_blocked_ips = set()
_threat_callbacks = []

SIGNATURES = [
    {
        "id": "PORT_SCAN",
        "name": "Port Scan Detected",
        "description": "Remote IP connecting to many ports in short time",
        "severity": "HIGH",
        "threshold_ports": 15,
        "window_seconds": 60,
    },
    {
        "id": "SYN_FLOOD",
        "name": "SYN Flood",
        "description": "High rate of SYN connections from single IP",
        "severity": "CRITICAL",
        "threshold_conns": 50,
        "window_seconds": 10,
    },
    {
        "id": "BRUTE_FORCE_SSH",
        "name": "SSH Brute Force",
        "description": "Multiple connection attempts to port 22",
        "severity": "HIGH",
        "threshold_conns": 10,
        "window_seconds": 30,
        "port": 22,
    },
    {
        "id": "BRUTE_FORCE_RDP",
        "name": "RDP Brute Force",
        "description": "Multiple connection attempts to port 3389",
        "severity": "HIGH",
        "threshold_conns": 10,
        "window_seconds": 30,
        "port": 3389,
    },
    {
        "id": "BRUTE_FORCE_SMB",
        "name": "SMB Attack",
        "description": "Multiple connection attempts to SMB port 445",
        "severity": "HIGH",
        "threshold_conns": 8,
        "window_seconds": 30,
        "port": 445,
    },
]

_enabled_signatures = {sig["id"]: True for sig in SIGNATURES}
_ip_port_history = defaultdict(lambda: defaultdict(list))  # ip -> port -> [timestamps]
_ip_conn_history = defaultdict(list)  # ip -> [timestamps]
_running = False
_monitor_thread = None
_alerts = deque(maxlen=1000)


def register_callback(fn):
    _threat_callbacks.append(fn)


def _fire_alert(alert):
    _alerts.appendleft(alert)
    for fn in _threat_callbacks:
        try:
            fn(alert)
        except Exception:
            pass


def _check_signatures(conns):
    now = time.time()
    alerts = []

    for c in conns:
        if not c.get("remote_ip") or c["remote_ip"] in ("", "0.0.0.0", "::"):
            continue
        rip = c["remote_ip"]
        rport = c.get("local_port", 0)

        # Track per-port history
        _ip_port_history[rip][rport].append(now)
        _ip_port_history[rip][rport] = [
            t for t in _ip_port_history[rip][rport] if now - t < 120
        ]

        # Track connection history
        _ip_conn_history[rip].append(now)
        _ip_conn_history[rip] = [t for t in _ip_conn_history[rip] if now - t < 120]

    for sig in SIGNATURES:
        if not _enabled_signatures.get(sig["id"], True):
            continue

        if sig["id"] == "PORT_SCAN":
            for rip, port_map in list(_ip_port_history.items()):
                recent_ports = sum(
                    1 for port, times in port_map.items()
                    if any(now - t < sig["window_seconds"] for t in times)
                )
                if recent_ports >= sig["threshold_ports"]:
                    alert = _make_alert(sig, rip, f"{recent_ports} ports in {sig['window_seconds']}s")
                    if alert:
                        alerts.append(alert)

        elif sig["id"] == "SYN_FLOOD":
            for rip, times in list(_ip_conn_history.items()):
                recent = sum(1 for t in times if now - t < sig["window_seconds"])
                if recent >= sig["threshold_conns"]:
                    alert = _make_alert(sig, rip, f"{recent} connections in {sig['window_seconds']}s")
                    if alert:
                        alerts.append(alert)

        elif "BRUTE_FORCE" in sig["id"]:
            port = sig.get("port")
            for rip, port_map in list(_ip_port_history.items()):
                times = port_map.get(port, [])
                recent = sum(1 for t in times if now - t < sig["window_seconds"])
                if recent >= sig["threshold_conns"]:
                    alert = _make_alert(sig, rip, f"{recent} attempts to port {port}")
                    if alert:
                        alerts.append(alert)

    return alerts


_alerted_ips = {}


def _make_alert(sig, remote_ip, detail):
    key = f"{sig['id']}-{remote_ip}"
    now = time.time()
    if _alerted_ips.get(key, 0) > now - 60:
        return None
    _alerted_ips[key] = now

    alert = {
        "id": sig["id"],
        "name": sig["name"],
        "severity": sig["severity"],
        "remote_ip": remote_ip,
        "detail": detail,
        "timestamp": datetime.now().isoformat(),
    }
    database.add_log("THREAT", src_ip=remote_ip,
                     rule_name=sig["name"],
                     details=f"[{sig['severity']}] {detail}")
    return alert


def _monitor_loop():
    global _running
    while _running:
        try:
            raw = psutil.net_connections(kind="inet")
            conns = []
            for c in raw:
                if c.raddr:
                    conns.append({
                        "remote_ip": c.raddr.ip,
                        "local_port": c.laddr.port if c.laddr else 0,
                        "proto": "TCP" if c.type == 1 else "UDP",
                    })
            alerts = _check_signatures(conns)
            for alert in alerts:
                _fire_alert(alert)
        except Exception:
            pass
        time.sleep(2)


def start():
    global _running, _monitor_thread
    if _running:
        return
    _running = True
    _monitor_thread = threading.Thread(target=_monitor_loop, daemon=True)
    _monitor_thread.start()


def stop():
    global _running
    _running = False


def get_alerts(limit=100):
    return list(_alerts)[:limit]


def get_signatures():
    return [{"enabled": _enabled_signatures.get(s["id"], True), **s} for s in SIGNATURES]


def set_signature_enabled(sig_id, enabled):
    _enabled_signatures[sig_id] = enabled


def clear_alerts():
    _alerts.clear()
