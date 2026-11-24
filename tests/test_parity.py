from datetime import datetime

from core.parity import (
    boot_restore_plan, build_policy, expand_rule, feed_cap, ipset_restore_lines,
    parse_ip_network_list, parse_rule_hits, render_proto_rules, rsync_excludes,
    sanitize_policy, schedule_allows, top_talkers, rewrite_signatures,
)
from core.traffic_security import nfqueue_rules


def test_schedules_groups_and_vlan_scope_stay_selective():
    monday = datetime(2026, 11, 23, 10, 0)
    sunday = datetime(2026, 11, 22, 10, 0)
    assert schedule_allows("", monday)
    assert schedule_allows("mon,tue,wed,thu,fri 09:00-17:00", monday)
    assert not schedule_allows("mon,tue,wed,thu,fri 09:00-17:00", sunday)
    copies = expand_rule(
        {"local_ip": "@office", "remote_ip": "", "local_port": "", "remote_port": "@web"},
        {"office": {"kind": "address", "values": ["10.1.0.0/24"]}, "web": {"kind": "port", "values": ["80", "443"]}},
    )
    assert {item["remote_port"] for item in copies} == {"80", "443"}
    assert copies[0]["local_ip"] == "10.1.0.0/24"
    hits = parse_rule_hits("12 340 DROP all -- * * 0.0.0.0/0 0.0.0.0/0 /* fguard_7 */")
    assert hits[7] == 12
    vlan = nfqueue_rules(["eth1.10"], "")
    assert vlan[0][:2] == ["-i", "eth1.10"]
    assert "-o" not in vlan[0]


def test_ha_policy_keeps_the_node_password():
    assert "firewall.db" in rsync_excludes(True)
    assert "firewall.db" not in rsync_excludes(False)
    document = sanitize_policy(build_policy(
        [{"id": 1, "name": "web"}],
        [],
        [],
        {"ha_full_policy": "1", "admin_password_hash": "secret", "fleet_token": "tok"},
    ))
    assert "admin_password_hash" not in document["settings"]
    assert document["settings"]["ha_full_policy"] == "1"


def test_lists_graphs_and_protocol_names():
    assert feed_cap(False) == 20000
    assert feed_cap(True) == 100000
    assert parse_ip_network_list("# comment\n1.2.3.0/24 ; spamhaus\nnot-an-ip\n") == ["1.2.3.0/24"]
    assert "add fguard_block_ips 1.2.3.0/24" in ipset_restore_lines(["1.2.3.0/24"])
    text = rewrite_signatures(
        'drop ip any any -> any any (msg:"sample"; sid:5; rev:1;)\n'
        'drop ip any any -> any any (msg:"keep"; sid:6; rev:1;)',
        "alert",
        [5],
    )
    assert "# disabled sid 5" in text
    assert text.splitlines()[1].startswith("alert ")
    proto = render_proto_rules()
    assert "alert tls" in proto and "drop " not in proto
    assert top_talkers([{"src_ip": "10.0.0.2"}, {"src_ip": "10.0.0.2"}, {"src_ip": "10.0.0.3"}])[0]["ip"] == "10.0.0.2"


def test_reboot_restores_only_what_was_enabled():
    quiet = boot_restore_plan({})
    assert quiet == {"ips": False, "tls": False, "ipset": False}
    armed = boot_restore_plan({
        "traffic_ips_enabled": "1",
        "tls_inspect_enabled": "1",
        "tls_inspect_confirmed": "1",
        "traffic_lists_extended": "1",
    })
    assert armed == {"ips": True, "tls": True, "ipset": True}
    assert boot_restore_plan({"tls_inspect_enabled": "1"})["tls"] is False


def test_synced_policy_round_trip(fresh_db):
    fresh_db.add_rule("Web", "BLOCK", "IN", local_port="80", schedule="mon 09:00-17:00", in_iface="eth1", out_iface="eth2")
    fresh_db.add_alias("office", "address", "10.1.0.0/24")
    fresh_db.set_setting("admin_password_hash", "keep-me")
    fresh_db.set_setting("ha_full_policy", "1")
    document = sanitize_policy(build_policy(
        fresh_db.get_rules(), fresh_db.get_nat_rules(), fresh_db.list_aliases(), fresh_db.get_all_settings(),
    ))
    fresh_db.set_setting("admin_password_hash", "keep-me")
    fresh_db.replace_synced_policy(document)
    web = next(rule for rule in fresh_db.get_rules() if rule["name"] == "Web")
    assert web["schedule"] == "mon 09:00-17:00"
    assert web["in_iface"] == "eth1"
    assert fresh_db.alias_map()["office"]["values"] == ["10.1.0.0/24"]
    assert fresh_db.get_setting("admin_password_hash") == "keep-me"
