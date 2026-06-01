"""Network interface, DHCP, DNS, NAT, and routing management (Linux/Windows)."""
import subprocess
import os
import json
import re
from db import database
from core.platform import IS_LINUX, IS_WINDOWS, run


# ─── Interface discovery ──────────────────────────────────────────────────────

def get_system_interfaces():
    """Return list of physical interfaces from the OS."""
    import psutil
    ifaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for name, addr_list in addrs.items():
        s = stats.get(name)
        ipv4 = next((a for a in addr_list if a.family.name in ("AF_INET", "2")), None)
        ifaces.append({
            "name": name,
            "ip": ipv4.address if ipv4 else "",
            "netmask": ipv4.netmask if ipv4 else "",
            "up": s.isup if s else False,
            "speed": s.speed if s else 0,
            "mtu": s.mtu if s else 1500,
        })
    return ifaces


def apply_interface(iface):
    """Apply interface config to the OS (Linux only)."""
    if not IS_LINUX:
        return False, "Interface config is Linux only"
    name = iface["name"]
    ip = iface.get("ip_address", "")
    netmask = iface.get("netmask", "255.255.255.0")
    gateway = iface.get("gateway", "")
    mode = iface.get("ip_mode", "static")

    if mode == "dhcp":
        ok, out, err = run(["dhclient", "-r", name])
        ok, out, err = run(["dhclient", name])
        return ok, out + err

    if mode == "static" and ip:
        prefix = _netmask_to_prefix(netmask)
        run(["ip", "addr", "flush", "dev", name])
        ok, out, err = run(["ip", "addr", "add", f"{ip}/{prefix}", "dev", name])
        if not ok:
            return False, err
        run(["ip", "link", "set", name, "up"])
        if gateway:
            run(["ip", "route", "add", "default", "via", gateway, "dev", name])
        return True, f"Interface {name} configured: {ip}/{prefix}"

    return True, "No changes applied"


def _netmask_to_prefix(netmask):
    try:
        return sum(bin(int(x)).count("1") for x in netmask.split("."))
    except Exception:
        return 24


def write_network_config(ifaces):
    """Write /etc/network/interfaces or Netplan config."""
    if not IS_LINUX:
        return False, "Linux only"

    # Try netplan first (Ubuntu)
    netplan_dir = "/etc/netplan"
    if os.path.isdir(netplan_dir):
        return _write_netplan(ifaces)
    return _write_interfaces_file(ifaces)


def _write_netplan(ifaces):
    config = {"network": {"version": 2, "ethernets": {}}}
    for iface in ifaces:
        if not iface.get("enabled"):
            continue
        name = iface["name"]
        mode = iface.get("ip_mode", "dhcp")
        entry = {}
        if mode == "dhcp":
            entry["dhcp4"] = True
        elif mode == "static":
            ip = iface.get("ip_address", "")
            nm = iface.get("netmask", "255.255.255.0")
            gw = iface.get("gateway", "")
            if ip:
                prefix = _netmask_to_prefix(nm)
                entry["dhcp4"] = False
                entry["addresses"] = [f"{ip}/{prefix}"]
                if gw:
                    entry["routes"] = [{"to": "0.0.0.0/0", "via": gw}]
        if iface.get("mtu", 1500) != 1500:
            entry["mtu"] = iface["mtu"]
        config["network"]["ethernets"][name] = entry

    path = "/etc/netplan/50-aegisguard.yaml"
    try:
        import yaml
        with open(path, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
        run(["netplan", "apply"])
        return True, "Netplan config applied"
    except ImportError:
        import json as _json
        with open(path.replace(".yaml", ".json"), "w") as f:
            _json.dump(config, f, indent=2)
        return True, "Config written (yaml module not installed)"
    except Exception as e:
        return False, str(e)


def _write_interfaces_file(ifaces):
    lines = ["# AegisGuard network config", "auto lo", "iface lo inet loopback", ""]
    for iface in ifaces:
        if not iface.get("enabled"):
            continue
        name = iface["name"]
        mode = iface.get("ip_mode", "dhcp")
        lines.append(f"auto {name}")
        if mode == "dhcp":
            lines.append(f"iface {name} inet dhcp")
        elif mode == "static":
            ip = iface.get("ip_address", "")
            nm = iface.get("netmask", "255.255.255.0")
            gw = iface.get("gateway", "")
            lines.append(f"iface {name} inet static")
            if ip:
                lines.append(f"  address {ip}")
            lines.append(f"  netmask {nm}")
            if gw:
                lines.append(f"  gateway {gw}")
        lines.append("")
    try:
        with open("/etc/network/interfaces", "w") as f:
            f.write("\n".join(lines))
        return True, "Written to /etc/network/interfaces"
    except Exception as e:
        return False, str(e)


# ─── DHCP server (dnsmasq) ────────────────────────────────────────────────────

def write_dhcp_config():
    """Write dnsmasq config for DHCP server."""
    if not IS_LINUX:
        return False, "DHCP server config is Linux only"
    configs = database.get_dhcp_configs()
    leases = database.get_dhcp_leases()

    lines = [
        "# AegisGuard DHCP config (dnsmasq)",
        "no-resolv",
        "no-poll",
        "bogus-priv",
        "domain-needed",
    ]

    dns_s = database.get_dns_settings()
    if dns_s.get("primary_dns"):
        lines.append(f"server={dns_s['primary_dns']}")
    if dns_s.get("secondary_dns"):
        lines.append(f"server={dns_s['secondary_dns']}")
    if dns_s.get("local_domain"):
        lines.append(f"local=/{dns_s['local_domain']}/")
        lines.append(f"domain={dns_s['local_domain']}")

    for cfg in configs:
        if not cfg["enabled"]:
            continue
        iface = cfg["interface"]
        lines.append(f"interface={iface}")
        lines.append(f"dhcp-range={iface},{cfg['start_ip']},{cfg['end_ip']},{cfg['subnet_mask']},{cfg['lease_time']}s")
        if cfg.get("gateway"):
            lines.append(f"dhcp-option={iface},3,{cfg['gateway']}")
        if cfg.get("dns1"):
            lines.append(f"dhcp-option={iface},6,{cfg['dns1']}" + (f",{cfg['dns2']}" if cfg.get("dns2") else ""))

    for lease in leases:
        lines.append(f"dhcp-host={lease['mac']},{lease['ip']}" + (f",{lease['hostname']}" if lease.get("hostname") else ""))

    conf = "\n".join(lines) + "\n"
    try:
        with open("/etc/dnsmasq.d/aegisguard.conf", "w") as f:
            f.write(conf)
        run(["systemctl", "restart", "dnsmasq"])
        return True, "dnsmasq config applied"
    except Exception as e:
        return False, str(e)


def get_dhcp_active_leases():
    """Read active DHCP leases from dnsmasq lease file."""
    path = "/var/lib/misc/dnsmasq.leases"
    if not os.path.isfile(path):
        path = "/var/lib/dnsmasq/dnsmasq.leases"
    leases = []
    try:
        with open(path) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4:
                    leases.append({
                        "expires": parts[0], "mac": parts[1],
                        "ip": parts[2], "hostname": parts[3]
                    })
    except Exception:
        pass
    return leases


# ─── DNS (resolv.conf / systemd-resolved) ─────────────────────────────────────

def apply_dns_settings():
    if not IS_LINUX:
        return False, "Linux only"
    s = database.get_dns_settings()
    servers = [s.get("primary_dns", "1.1.1.1"),
               s.get("secondary_dns", "8.8.8.8"),
               s.get("tertiary_dns", "")]
    servers = [x for x in servers if x]

    # Try systemd-resolved
    resolved_conf = "/etc/systemd/resolved.conf"
    if os.path.isfile(resolved_conf):
        try:
            dns_line = "DNS=" + " ".join(servers)
            domain = s.get("search_domain", "")
            content = f"[Resolve]\n{dns_line}\n"
            if domain:
                content += f"Domains={domain}\n"
            content += f"DNSSEC={'yes' if s.get('enable_dnssec') else 'no'}\n"
            with open(resolved_conf, "w") as f:
                f.write(content)
            run(["systemctl", "restart", "systemd-resolved"])
            return True, "DNS applied via systemd-resolved"
        except Exception as e:
            return False, str(e)

    # Fallback to resolv.conf
    try:
        lines = [f"nameserver {s}" for s in servers]
        if s.get("search_domain"):
            lines.insert(0, f"search {s['search_domain']}")
        with open("/etc/resolv.conf", "w") as f:
            f.write("\n".join(lines) + "\n")
        return True, "DNS applied via /etc/resolv.conf"
    except Exception as e:
        return False, str(e)


# ─── Static routes ────────────────────────────────────────────────────────────

def apply_routes():
    if not IS_LINUX:
        return False, "Linux only"
    routes = database.get_routes()
    results = []
    for r in routes:
        if not r["enabled"]:
            continue
        prefix = _netmask_to_prefix(r["netmask"])
        # Use "replace" instead of "add" to avoid duplicate route errors
        cmd = ["ip", "route", "replace", f"{r['destination']}/{prefix}", "via", r["gateway"]]
        if r.get("interface"):
            cmd += ["dev", r["interface"]]
        if r.get("metric"):
            cmd += ["metric", str(r["metric"])]
        ok, out, err = run(cmd)
        results.append((r["destination"], ok, err or out))
    return True, f"Applied {len(results)} routes"


def get_system_routes():
    if IS_LINUX:
        ok, out, _ = run(["ip", "route", "show"])
        return out if ok else ""
    ok, out, _ = run(["route", "print"])
    return out if ok else ""


# ─── NAT ──────────────────────────────────────────────────────────────────────

def apply_nat_rules():
    if not IS_LINUX:
        return False, "NAT management is Linux only"
    from core.rules_engine import _ipt
    nat_rules = database.get_nat_rules()
    results = []
    for r in nat_rules:
        if not r["enabled"]:
            continue
        if r["type"] == "DNAT":
            # Port forwarding: external:port -> internal:port
            args = ["-t", "nat", "-A", "PREROUTING"]
            if r.get("interface"):
                args += ["-i", r["interface"]]
            proto = r.get("protocol", "TCP").lower()
            args += ["-p", proto]
            if r.get("external_port"):
                args += ["--dport", r["external_port"]]
            args += ["-j", "DNAT", "--to-destination",
                     f"{r['internal_ip']}" + (f":{r['internal_port']}" if r.get("internal_port") else "")]
            ok, msg = _ipt(args)
        elif r["type"] == "SNAT":
            args = ["-t", "nat", "-A", "POSTROUTING"]
            args += ["-s", r["internal_ip"]]
            args += ["-j", "SNAT", "--to-source", r["external_ip"]]
            ok, msg = _ipt(args)
        elif r["type"] == "PAT":
            args = ["-t", "nat", "-A", "POSTROUTING"]
            if r.get("interface"):
                args += ["-o", r["interface"]]
            args += ["-j", "MASQUERADE"]
            ok, msg = _ipt(args)
        elif r["type"] == "1-to-1":
            ok, msg = _apply_static_nat(r)
        else:
            ok, msg = False, f"Unknown NAT type: {r['type']}"
        results.append((r["name"], ok, msg))
    return True, f"Applied {sum(1 for _,ok,_ in results if ok)}/{len(results)} NAT rules"


def _apply_static_nat(rule):
    """1-to-1 Static NAT: public_ip <-> private_ip (bidirectional)."""
    public_ip  = rule.get("external_ip", "").strip()
    private_ip = rule.get("internal_ip", "").strip()
    iface      = rule.get("interface", "")

    if not public_ip or not private_ip:
        return False, "Static NAT requires both external_ip (public) and internal_ip (private)"

    from core.rules_engine import _ipt

    # DNAT: incoming traffic to public IP → redirect to private IP
    dnat_args = ["-t", "nat", "-A", "PREROUTING"]
    if iface:
        dnat_args += ["-i", iface]
    dnat_args += ["-d", public_ip, "-j", "DNAT", "--to-destination", private_ip]
    ok1, msg1 = _ipt(dnat_args)

    # SNAT: outgoing traffic from private IP → appear as public IP
    snat_args = ["-t", "nat", "-A", "POSTROUTING",
                 "-s", private_ip, "-j", "SNAT", "--to-source", public_ip]
    ok2, msg2 = _ipt(snat_args)

    # Allow forwarding between public and private
    _ipt(["-A", "FORWARD", "-d", private_ip, "-j", "ACCEPT"])
    _ipt(["-A", "FORWARD", "-s", private_ip, "-j", "ACCEPT"])

    ok = ok1 and ok2
    msg = f"DNAT: {msg1} | SNAT: {msg2}" if not ok else f"Static NAT: {public_ip} <-> {private_ip}"
    return ok, msg


def remove_static_nat(rule):
    """Remove a 1-to-1 Static NAT rule from iptables."""
    public_ip  = rule.get("external_ip", "").strip()
    private_ip = rule.get("internal_ip", "").strip()

    if not public_ip or not private_ip:
        return False, "Missing IPs"

    from core.rules_engine import _ipt
    _ipt(["-t", "nat", "-D", "PREROUTING", "-d", public_ip, "-j", "DNAT",
          "--to-destination", private_ip])
    _ipt(["-t", "nat", "-D", "POSTROUTING", "-s", private_ip, "-j", "SNAT",
          "--to-source", public_ip])
    return True, "Static NAT removed"


# ─── QoS (tc - Linux Traffic Control) ────────────────────────────────────────

def apply_qos_rules(interface="eth0"):
    """Apply QoS/traffic shaping via tc (Linux only)."""
    if not IS_LINUX:
        return False, "QoS is Linux only"
    rules = database.get_qos_rules()
    if not rules:
        return True, "No QoS rules"

    # Clear existing
    run(["tc", "qdisc", "del", "dev", interface, "root"])
    # Add HTB root
    run(["tc", "qdisc", "add", "dev", interface, "root", "handle", "1:", "htb", "default", "30"])

    priority_map = {"HIGHEST": 1, "HIGH": 2, "NORMAL": 3, "LOW": 4, "LOWEST": 5}
    results = []
    for i, r in enumerate(rules):
        if not r["enabled"]:
            continue
        class_id = f"1:{10 + i}"
        prio = priority_map.get(r["priority"], 3)
        bw = r.get("bandwidth_limit", 0)
        unit = r.get("bandwidth_unit", "kbps")
        rate = f"{bw}{unit}" if bw else "1gbit"

        run(["tc", "class", "add", "dev", interface, "parent", "1:", "classid", class_id,
             "htb", "rate", rate, "prio", str(prio)])
        results.append(r["name"])

    return True, f"QoS applied: {len(results)} classes on {interface}"


# ─── Firewall status ──────────────────────────────────────────────────────────

def get_connection_tracking():
    """Get conntrack entries (Linux)."""
    if not IS_LINUX:
        return []
    ok, out, _ = run(["conntrack", "-L", "-n"], timeout=5)
    if not ok:
        return []
    entries = []
    for line in out.splitlines()[:100]:
        entries.append(line.strip())
    return entries
