import json

import pytest

from core.fleet import health_url, normalize_base_url, token_matches
from core.session_sync import render_conntrackd_conf
from core.traffic_security import (
    dnsmasq_lines,
    interface_rates,
    nfqueue_rules,
    parse_domain_list,
    parse_eve_line,
    render_app_rules,
    package_install_argv,
    render_suricata_yaml,
    summarize_blocks,
    tls_plan,
)


def test_suricata_yaml_fails_open():
    text = render_suricata_yaml(["10.1.0.0/24"], ["lan0", "wan0"], file_store=True)
    assert "fail-open: yes" in text
    assert "10.1.0.0/24" in text
    assert "write-fileinfo: yes" in text


def test_forward_rules_use_queue_bypass():
    rules = nfqueue_rules(["lan0", "wan0"], "wan0")
    assert len(rules) == 1
    assert rules[0][:2] == ["-i", "lan0"]
    assert "--queue-bypass" in rules[0]
    assert "fguard_traffic_ips" in rules[0]


def test_eve_alert_and_file_events():
    alert = parse_eve_line(json.dumps({
        "event_type": "alert",
        "src_ip": "10.1.0.5",
        "dest_ip": "1.2.3.4",
        "src_port": 40000,
        "dest_port": 443,
        "alert": {"signature": "Test drop", "severity": 1, "action": "blocked"},
    }))
    assert alert["kind"] == "alert"
    assert alert["signature"] == "Test drop"
    assert parse_eve_line("{") is None
    stored = parse_eve_line(json.dumps({
        "event_type": "fileinfo",
        "src_ip": "10.1.0.5",
        "stored": True,
        "fileinfo": {"filename": "setup.exe", "sha256": "abc"},
    }))
    assert stored["sha256"] == "abc"


def test_category_list_and_dns_lines():
    domains = parse_domain_list(
        "# comment\n0.0.0.0 bad.example\nwww.phish.example\nnot a domain\n"
    )
    assert domains == ["bad.example", "phish.example"]
    text = dnsmasq_lines(["bad.example"])
    assert "address=/bad.example/0.0.0.0" in text
    assert "address=/bad.example/::" in text


def test_app_rules_skip_short_names():
    text = render_app_rules([{"name": "YouTube", "domains": ["yt", "youtube.com"]}])
    assert "youtube.com" in text
    assert 'content:"yt"' not in text
    assert "sid:9100001" in text


def test_block_summary_counts_reasons():
    rows = [
        {"rule_name": "Test drop", "src_ip": "10.1.0.5"},
        {"rule_name": "Test drop", "src_ip": "10.1.0.6"},
    ]
    report = summarize_blocks(rows)
    assert report["total"] == 2
    assert report["by_rule"][0] == ("Test drop", 2)


def test_measured_rates_use_byte_counters():
    before = {"wan0": {"rx_bytes": 0, "tx_bytes": 100}}
    after = {"wan0": {"rx_bytes": 1_000_000, "tx_bytes": 100}}
    rates = interface_rates(before, after, 1)
    assert rates["wan0"]["rx_mbps"] == 8.0
    assert rates["wan0"]["tx_mbps"] == 0.0


def test_tls_stays_off_without_confirmation():
    assert tls_plan(False, False)["enabled"] is False
    with pytest.raises(ValueError):
        tls_plan(True, False)


def test_conntrackd_uses_the_peer():
    text = render_conntrackd_conf("10.0.0.1", "10.0.0.2", "eth1")
    assert "IPv4_address 10.0.0.1" in text
    assert "IPv4_Destination_Address 10.0.0.2" in text
    assert "Port 3780" in text
    with pytest.raises(ValueError):
        render_conntrackd_conf("", "10.0.0.2", "eth1")


def test_commercial_inspection_stays_selective():
    import io
    import tarfile
    from core.commercial import (
        extract_rules_from_tar, filter_policy, quic_rules,
        render_appid_rules, render_https_category_rules, rule_file_list,
    )
    from core.traffic_security import TLS_BYPASS, sslsplit_command
    assert "fguard-signatures.rules" in rule_file_list(signatures=True)
    assert "fguard-signatures.rules" not in rule_file_list()
    text = render_appid_rules((("Zoom", ("zoom.us",)),))
    assert "alert tls" in text and "drop tls" not in text
    assert 'content:"zoom.us"' in text
    categories = render_https_category_rules(["bad.example"])
    assert 'msg:"FGUARD category bad.example"' in categories
    assert quic_rules(["lan0"])[0][3:5] == ["udp", "--dport"]
    assert "nbg.gr" in TLS_BYPASS and "windowsupdate.com" in TLS_BYPASS
    command = sslsplit_command({
        "ca_key": "/tmp/ca.key", "ca_cert": "/tmp/ca.crt", "listen_port": 8443,
        "content_log": "/tmp/tls",
    })
    assert "-S" in command and "/tmp/tls" in command
    blob = io.BytesIO()
    with tarfile.open(fileobj=blob, mode="w:gz") as archive:
        payload = b'alert ip any any -> any any (msg:"sample"; sid:1; rev:1;)\n'
        info = tarfile.TarInfo("rules/emerging-test.rules")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
        bad = tarfile.TarInfo("../evil.rules")
        bad.size = 4
        archive.addfile(bad, io.BytesIO(b"nope"))
    rules = extract_rules_from_tar(blob.getvalue())
    assert "sid:1" in rules and "nope" not in rules
    policy = filter_policy({"traffic_ips_enabled": "1", "tls_inspect_enabled": "1", "apps": {"YouTube": "1", "nope": "1"}}, ["YouTube"])
    assert policy["traffic_ips_enabled"] == "1"
    assert policy["tls_refused"] == "1"
    assert policy["apps"] == {"YouTube": "1"}


def test_download_buttons_install_with_apt():
    assert package_install_argv("suricata") == ["apt-get", "install", "-y", "suricata"]
    assert package_install_argv(["clamav", "clamav-freshclam"])[:4] == ["apt-get", "install", "-y", "clamav"]
    with pytest.raises(ValueError):
        package_install_argv("suricata;rm")


def test_fleet_url_rejects_metadata_and_passwords():
    assert normalize_base_url("https://firewall.example:8080/ui") == "https://firewall.example:8080"
    with pytest.raises(ValueError):
        normalize_base_url("http://169.254.169.254/latest")
    with pytest.raises(ValueError):
        normalize_base_url("https://admin:secret@firewall.example")
    assert health_url("https://firewall.example").endswith("/api/fleet/health")
    assert token_matches("same-token", "same-token")
    assert token_matches("", "same-token") is False
