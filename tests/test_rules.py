from core.rules_engine import _match_ip, _match_port


def test_match_ip_any_and_cidr():
    assert _match_ip("", "8.8.8.8")
    assert _match_ip("ANY", "8.8.8.8")
    assert _match_ip("10.0.0.0/8", "10.1.2.3")
    assert not _match_ip("10.0.0.0/8", "192.168.0.1")
    assert _match_ip("1.2.3.4", "1.2.3.4")
    assert not _match_ip("not-a-cidr/99", "1.2.3.4")


def test_match_port_ranges_and_lists():
    assert _match_port("", 443)
    assert _match_port("ANY", 22)
    assert _match_port("80-90", 85)
    assert not _match_port("80-90", 443)
    assert _match_port("22,80,443", 80)
    assert not _match_port("22,80,443", 25)
    assert not _match_port("abc", 80)
