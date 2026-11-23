import base64
import ipaddress

from core.ha_manager import (
    known_hosts_line, parse_host_key, rsync_rsh, ssh_reload_command, write_known_hosts,
)


HOST_KEY = "ssh-ed25519 " + base64.b64encode(b"\x00" * 32).decode("ascii")


def test_parse_keyscan_line():
    keytype, blob = parse_host_key("10.0.0.2 " + HOST_KEY)
    assert keytype == "ssh-ed25519"
    assert blob.startswith("AAAA")


def test_known_hosts_line_uses_the_peer_ip():
    line = known_hosts_line("10.0.0.2", HOST_KEY)
    assert line.startswith("10.0.0.2 ssh-ed25519 ")
    ipaddress.ip_address(line.split()[0])


def test_hostname_peer_is_rejected():
    try:
        known_hosts_line("backup.example", HOST_KEY)
    except ValueError as exc:
        assert "IP address" in str(exc)
    else:
        raise AssertionError("hostname peer was accepted")


def test_ssh_commands_check_the_pinned_key():
    command = rsync_rsh("/etc/fguard/ha_known_hosts")
    assert "StrictHostKeyChecking=yes" in command
    assert "StrictHostKeyChecking=no" not in command
    assert "UserKnownHostsFile=/etc/fguard/ha_known_hosts" in command
    reload_cmd = ssh_reload_command("10.0.0.2")
    assert "StrictHostKeyChecking=no" not in " ".join(reload_cmd)
    assert "root@10.0.0.2" in reload_cmd


def test_known_hosts_file_is_that_one_key(tmp_path):
    path = tmp_path / "known_hosts"
    write_known_hosts("192.168.1.20", HOST_KEY, str(path))
    text = path.read_text()
    assert text.strip().endswith(HOST_KEY.split()[1])
    assert "192.168.1.20" in text


def test_source_does_not_disable_host_key_checking():
    with open("core/ha_manager.py", "r", encoding="utf-8") as handle:
        source = handle.read()
    assert "StrictHostKeyChecking=no" not in source
