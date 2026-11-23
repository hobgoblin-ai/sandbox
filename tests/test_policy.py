import pytest

from hobgoblin.policy import PolicyError, glob_to_regex, normalize_host, parse_policy, path_is_ambiguous


def pol(rules, **top):
    return parse_policy({"version": 1, "rule": rules, **top})


def test_normalize_host():
    assert normalize_host("GitHub.COM.") == "github.com"
    assert normalize_host("[::1]") == "::1"
    assert normalize_host("::FFFF:a00:1") == "::ffff:10.0.0.1"
    assert normalize_host("exa mple.com") is None
    assert normalize_host("bücher.de") is None  # non-ASCII never matches; use punycode in policy
    assert normalize_host("-bad.com") is None
    assert normalize_host("") is None


def test_exact_beats_wildcard_and_longest_wildcard_wins():
    p = pol(
        [
            {"host": "*.github.com", "action": "tunnel"},
            {"host": "*.api.github.com", "action": "tunnel"},
            {"host": "api.github.com", "action": "inspect"},
        ]
    )
    assert p.match("api.github.com").action == "inspect"
    assert p.match("x.api.github.com").host == "*.api.github.com"
    assert p.match("codeload.github.com").host == "*.github.com"
    assert p.match("github.com") is None  # wildcard does not cover the apex
    assert p.match("evilgithub.com") is None
    assert p.match("github.com.evil.com") is None


def test_ports_default_and_explicit():
    p = pol([{"host": "a.example", "action": "tunnel"}, {"host": "b.example", "action": "tcp", "ports": [22]}])
    assert p.match("a.example", 443)
    assert p.match("a.example", 80) is None
    assert p.match("b.example", 22)
    assert p.match("b.example", 443) is None


def test_globs():
    rx = glob_to_regex("/myorg/*/git-upload-pack")
    assert rx.match("/myorg/repo.git/git-upload-pack")
    assert not rx.match("/myorg/a/b/git-upload-pack")
    assert glob_to_regex("/repos/myorg/**").match("/repos/myorg/x/pulls/1")
    assert not glob_to_regex("/repos/myorg/**").match("/repos/myorgevil/x")
    assert not glob_to_regex("/a.b").match("/aXb")  # dots are literal


@pytest.mark.parametrize(
    "path",
    ["/a/../b", "/a/./b", "/a%2fb", "/a%2Fb", "/a%2e%2e/b", "/a\\b", "//evil", "/a/%00", "relative"],
)
def test_ambiguous_paths_rejected(path):
    assert path_is_ambiguous(path)


def test_allow_entries():
    p = pol(
        [
            {
                "host": "github.com",
                "action": "inspect",
                "allow": [
                    {"methods": ["GET"], "paths": ["/myorg/**"]},
                    {"methods": ["POST"], "paths": ["/myorg/*/git-upload-pack"]},
                ],
            }
        ]
    )
    r = p.match("github.com")
    assert r.permits_request("GET", "/myorg/repo")[0]
    assert r.permits_request("get", "/myorg/repo")[0]
    assert r.permits_request("POST", "/myorg/repo.git/git-upload-pack")[0]
    assert not r.permits_request("POST", "/myorg/repo.git/git-receive-pack")[0]  # push
    assert not r.permits_request("GET", "/otherorg/repo")[0]
    assert not r.permits_request("GET", "/myorg/../otherorg/repo")[0]


@pytest.mark.parametrize(
    "rule, msg",
    [
        ({"host": "x.com", "action": "tunnel", "allow": [{"paths": ["/**"]}]}, "needs action"),
        ({"host": "x.com", "action": "tunnel", "inject": [{"header": "A", "secret": "s"}]}, "needs action"),
        ({"host": "x.com", "action": "tcp"}, "requires explicit 'ports'"),
        ({"host": "*.com", "action": "tunnel"}, "too broad"),
        ({"host": "a.*.com", "action": "tunnel"}, "leading"),
        ({"host": "1.2.3.4", "action": "inspect"}, "IP literals"),
        ({"host": "x.com", "action": "proxy"}, "'action'"),
        ({"host": "x.com", "action": "inspect", "inject": [{"header": "Host", "secret": "s"}]}, "framing"),
        ({"host": "x.com", "action": "inspect", "inject": [{"header": "Bad Header", "secret": "s"}]}, "header"),
        ({"host": "x.com", "action": "inspect", "allow": [{"paths": ["nope"]}]}, "start with"),
        ({"host": "x.com", "action": "tunnel", "typo": 1}, "unknown keys"),
    ],
)
def test_validation_errors(rule, msg):
    with pytest.raises(PolicyError, match=msg):
        pol([rule])


def test_duplicate_host_port_rejected():
    with pytest.raises(PolicyError, match="already covered"):
        pol([{"host": "x.com", "action": "tunnel"}, {"host": "X.com.", "action": "inspect"}])


def test_top_level_validation():
    with pytest.raises(PolicyError, match="version"):
        parse_policy({"rule": []})
    with pytest.raises(PolicyError, match="mode"):
        parse_policy({"version": 1, "defaults": {"mode": "yolo"}})
    with pytest.raises(PolicyError, match="CIDR"):
        parse_policy({"version": 1, "network": {"allow_cidrs": ["nope"]}})


def test_secret_names_and_inspect_hosts():
    p = pol(
        [
            {"host": "a.com", "action": "inspect", "inject": [{"header": "X-Key", "secret": "k1"}]},
            {"host": "*.b.com", "action": "inspect", "inject": [{"header": "X-Key", "secret": "k1"}]},
            {"host": "c.com", "action": "tunnel"},
        ]
    )
    assert p.secret_names() == ["k1"]
    assert p.inspect_hosts() == ["a.com", "*.b.com"]


def test_example_policy_parses():
    from pathlib import Path

    from hobgoblin.policy import load_policy

    p = load_policy(Path(__file__).parent.parent / "examples" / "policy.toml")
    assert p.rules
