import pytest

from hobgoblin.netguard import check_all, check_ip, parse_cidrs


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",  # cloud metadata
        "100.64.0.1",  # CGNAT
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fe80::1",
        "fd00::1",
        "::ffff:127.0.0.1",  # v4-mapped loopback
        "::ffff:169.254.169.254",
        "64:ff9b::a9fe:a9fe",  # NAT64 -> 169.254.169.254
        "2002:a9fe:a9fe::1",  # 6to4 embedding metadata IP
        "2001:0:4136:e378::1",  # Teredo
        "198.18.0.1",
        "192.0.2.1",
    ],
)
def test_blocked(ip):
    ok, why = check_ip(ip)
    assert not ok, why


@pytest.mark.parametrize("ip", ["140.82.112.3", "151.101.0.223", "2606:4700::6810:84e5", "1.1.1.1"])
def test_public_allowed(ip):
    assert check_ip(ip)[0]


def test_allow_and_deny_precedence():
    allow = parse_cidrs(["10.0.0.0/8"])
    deny = parse_cidrs(["10.9.0.0/16", "140.82.112.0/20"])
    assert check_ip("10.1.1.1", allow, deny)[0]
    assert not check_ip("10.9.1.1", allow, deny)[0]  # deny beats allow
    assert not check_ip("140.82.112.3", (), deny)[0]  # deny beats public


def test_mixed_resolution_is_refused():
    ip, why = check_all(["140.82.112.3", "127.0.0.1"])
    assert ip is None and "127.0.0.1" in why
    assert check_all([])[0] is None
    assert check_all(["140.82.112.3", "140.82.112.3"])[0] == "140.82.112.3"
