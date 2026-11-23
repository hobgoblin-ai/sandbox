"""Launcher tests. The isolation properties are asserted on the exact podman
argv we generate; the orchestration flow runs against a fake `podman`."""

from __future__ import annotations

import json
import os
import stat
import sys
import textwrap
from pathlib import Path

import pytest

from hobgoblin import launcher
from hobgoblin.launcher import Options, Session, agent_env, cmd_agent, cmd_networks, cmd_proxy
from hobgoblin.policy import load_policy, parse_policy

POLICY = {
    "version": 1,
    "rule": [
        {"host": "api.example.com", "action": "inspect", "inject": [{"header": "X-Key", "secret": "api_key"}]},
        {"host": "pypi.org", "action": "tunnel"},
    ],
}


def opts(tmp_path, **kw) -> Options:
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    pol = tmp_path / "policy.toml"
    pol.write_text('version = 1\n[[rule]]\nhost = "pypi.org"\naction = "tunnel"\n')
    return Options(policy_path=pol, workspace=ws, command=["bash"], **kw)


def flag_values(argv, flag):
    return [argv[i + 1] for i, a in enumerate(argv) if a == flag]


def mounts(argv):
    return flag_values(argv, "-v")


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    return Session.new("abcd1234")


def test_internal_network_has_no_route_or_dns(session):
    int_net, egress = cmd_networks(session)
    assert "--internal" in int_net and "--disable-dns" in int_net and int_net[-1] == session.net_int
    assert "--internal" not in egress and egress[-1] == session.net_egress
    assert "isolate=strict" in flag_values(egress, "--opt")


def test_proxy_only_accepts_session_subnet(tmp_path, session):
    p = cmd_proxy(session, opts(tmp_path), parse_policy(POLICY), [], ["10.89.7.0/24"])
    assert "HOBGOBLIN_CLIENT_CIDRS=10.89.7.0/24" in flag_values(p, "-e")


def test_proxy_runs_as_owner_of_bind_mounts(tmp_path, session, monkeypatch):
    monkeypatch.setattr(launcher.os, "getuid", lambda: 1234)
    monkeypatch.setattr(launcher.os, "getgid", lambda: 5678)
    p = cmd_proxy(session, opts(tmp_path), parse_policy(POLICY), [])
    assert "--userns=keep-id" in p
    assert flag_values(p, "--user") == ["1234:5678"]


def test_ipv6_proxy_address_is_bracketed():
    env = dict(e.split("=", 1) for e in agent_env("fd00::2", parse_policy(POLICY)))
    assert env["HTTPS_PROXY"] == "http://[fd00::2]:3128"


def test_runtime_dir_must_be_ours(tmp_path, monkeypatch):
    target = tmp_path / "elsewhere"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(RuntimeError, match="not a directory owned by you"):
        launcher._private_dir(link)


def test_agent_only_on_internal_network_and_in_microvm(tmp_path, session):
    pol = parse_policy(POLICY)
    a = cmd_agent(session, opts(tmp_path), pol, "10.89.0.2")
    assert flag_values(a, "--network") == [session.net_int]
    assert flag_values(a, "--runtime") == ["krun"]
    assert "--privileged" not in a


def test_agent_never_gets_secrets_ca_key_or_audit_log(tmp_path, session):
    pol = parse_policy(POLICY)
    a = cmd_agent(session, opts(tmp_path), pol, "10.89.0.2")
    joined = " ".join(a)
    assert "--secret" not in a
    assert str(session.pub) not in joined  # proxy output dir (ready marker etc.)
    assert str(session.state_dir) not in joined  # audit log
    assert "/run/secrets" not in joined
    assert any(m.startswith(f"{session.agent_dir}:/etc/hobgoblin:ro") for m in mounts(a))


def test_proxy_gets_secrets_both_networks_and_is_locked_down(tmp_path, session):
    pol = parse_policy(POLICY)
    p = cmd_proxy(session, opts(tmp_path), pol, ["203.0.113.7/32"])
    assert flag_values(p, "--network") == [session.net_egress, session.net_int]
    assert flag_values(p, "--secret") == ["api_key"]
    for f in ("--cap-drop=all", "--security-opt=no-new-privileges", "--read-only", "--userns=keep-id"):
        assert f in p
    assert "HOBGOBLIN_DENY_CIDRS=203.0.113.7/32" in flag_values(p, "-e")
    # The workspace is not visible to the proxy.
    assert not any(str(tmp_path / "ws") in m for m in mounts(p))


def test_selinux_hobgoblin_type(tmp_path, session):
    pol = parse_policy(POLICY)
    p = cmd_proxy(session, opts(tmp_path, selinux="hobgoblin"), pol, [])
    assert "label=type:hobgoblin_proxy.process" in flag_values(p, "--security-opt")
    p = cmd_proxy(session, opts(tmp_path), pol, [])
    assert "label=type:hobgoblin_proxy.process" not in flag_values(p, "--security-opt")


def test_agent_env_points_at_proxy_and_bundle():
    pol = parse_policy(POLICY)
    env = dict(e.split("=", 1) for e in agent_env("10.89.0.2", pol))
    assert env["HTTPS_PROXY"] == env["http_proxy"] == "http://10.89.0.2:3128"
    assert env["SSL_CERT_FILE"] == env["REQUESTS_CA_BUNDLE"] == "/etc/hobgoblin/ca-bundle.pem"
    assert env["NODE_EXTRA_CA_CERTS"] == "/etc/hobgoblin/ca.pem"
    tunnel_only = parse_policy({"version": 1, "rule": [{"host": "pypi.org", "action": "tunnel"}]})
    assert "NODE_EXTRA_CA_CERTS" not in dict(e.split("=", 1) for e in agent_env("x", tunnel_only))


@pytest.mark.parametrize(("example", "keys"), [
    ("opencode.toml", {"OPENAI_API_KEY"}),
    ("claude.toml", {"ANTHROPIC_API_KEY"}),
    ("policy.toml", {"OPENAI_API_KEY", "ANTHROPIC_API_KEY"}),
])
def test_provider_env_contains_only_policy_placeholders(example, keys, monkeypatch):
    for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.setenv(key, "host-secret")
    policy = load_policy(Path(__file__).parent.parent / "examples" / example)
    env = dict(e.split("=", 1) for e in agent_env("x", policy))
    assert {k: v for k, v in env.items() if k.endswith("_API_KEY")} == dict.fromkeys(keys, "injected-by-hobgoblin")


def test_provider_env_requires_matching_credential_injection():
    policy = parse_policy({"version": 1, "rule": [
        {"host": "api.openai.com", "action": "inspect", "inject": [{"header": "Other", "secret": "openai_api_key"}]},
        {"host": "api.anthropic.com", "action": "tunnel"},
    ]})
    assert not any(e.startswith(("OPENAI_API_KEY=", "ANTHROPIC_API_KEY=")) for e in agent_env("x", policy))


def test_relabel_none(tmp_path, session):
    a = cmd_agent(session, opts(tmp_path, relabel="none"), parse_policy(POLICY), "x")
    assert f"{tmp_path / 'ws'}:/workspace" in mounts(a)


def test_proxy_ip_parsing(session):
    data = json.dumps([{"NetworkSettings": {"Networks": {session.net_int: {"IPAddress": "10.89.3.4"}}}}])
    assert launcher.proxy_ip_on(session.net_int, data) == "10.89.3.4"
    with pytest.raises(RuntimeError):
        launcher.proxy_ip_on("other", data)


# ---------------------------------------------------------- fake podman flow

FAKE_PODMAN = textwrap.dedent(
    r'''
    #!PYTHON
    import json, os, sys
    from pathlib import Path
    log = Path(os.environ["FAKE_PODMAN_LOG"])
    with log.open("a") as f:
        f.write(json.dumps(sys.argv[1:]) + "\n")
    a = sys.argv[1:]
    if a[:2] == ["run", "-d"]:
        if os.environ.get("FAKE_PROXY_FAIL"):
            sys.exit(0)  # starts, then "dies": inspect will report not running
        for i, x in enumerate(a):
            if x == "-v" and ":/run/hobgoblin/pub" in a[i + 1]:
                pub = Path(a[i + 1].split(":")[0])
                (pub / "ca-bundle.pem").write_text("BUNDLE")
                (pub / "ca.pem").write_text("CA")
                (pub / "ready").write_text("1")
        sys.exit(0)
    if a[:1] == ["inspect"]:
        if "--format" in a:
            print("false" if os.environ.get("FAKE_PROXY_FAIL") else "true")
        else:
            name = a[-1]
            sid = name.split("-")[1]
            print(json.dumps([{"NetworkSettings": {"Networks": {f"hobgoblin-{sid}-int": {"IPAddress": "10.89.0.9"}}}}]))
        sys.exit(0)
    if a[:2] == ["network", "inspect"]:
        print(json.dumps([{"name": a[-1], "subnets": [{"subnet": "10.89.7.0/24", "gateway": "10.89.7.1"}]}]))
        sys.exit(0)
    if a[:1] == ["logs"]:
        calls = [json.loads(line) for line in log.read_text().splitlines()]
        if os.environ.get("FAKE_PROXY_FAIL") and any(c[:2] == ["run", "-d"] and "--rm" in c for c in calls):
            print("Error: no such container", file=sys.stderr)
            sys.exit(125)
        print("hobgoblin-proxy: missing secrets: api_key")
        sys.exit(0)
    if a[:1] == ["run"]:
        sys.exit(int(os.environ.get("FAKE_AGENT_RC", "0")))
    sys.exit(0)
    '''
).replace("#!PYTHON", f"#!{sys.executable}").lstrip()


@pytest.fixture
def fake_podman(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "podman"
    exe.write_text(FAKE_PODMAN)
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    log = tmp_path / "podman.log"
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_PODMAN_LOG", str(log))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(launcher, "host_public_addresses", lambda: [])
    return lambda: [json.loads(line) for line in log.read_text().splitlines()]


def test_full_flow_and_cleanup(tmp_path, fake_podman, monkeypatch):
    monkeypatch.setenv("FAKE_AGENT_RC", "3")
    o = opts(tmp_path)
    rc = launcher.run_session(o, parse_policy({"version": 1, "rule": [{"host": "pypi.org", "action": "tunnel"}]}))
    assert rc == 3  # agent exit code propagates
    calls = fake_podman()
    verbs = [c[0] if c[0] != "network" else f"network {c[1]}" for c in calls]
    assert verbs[:4] == ["network create", "network create", "network inspect", "run"]
    proxy = next(c for c in calls if c[:2] == ["run", "-d"])
    assert "HOBGOBLIN_CLIENT_CIDRS=10.89.7.0/24" in proxy
    agent = next(c for c in calls if c[0] == "run" and "-d" not in c)
    assert "HTTPS_PROXY=http://10.89.0.9:3128" in agent
    assert agent[-1] == "bash"
    # cleanup removes both containers and both networks, and the runtime dir
    rms = [c for c in calls if c[0] == "rm" or c[:2] == ["network", "rm"]]
    assert len(rms) == 4
    assert not list((tmp_path / "run" / "hobgoblin").iterdir())
    # the agent got a copy of the CA files, the proxy's dir is not shared
    assert any(":/etc/hobgoblin:ro" in x for x in agent)


@pytest.mark.parametrize("keep", [False, True])
def test_proxy_startup_failure_cleans_up_and_reports(tmp_path, fake_podman, monkeypatch, capsys, keep):
    monkeypatch.setenv("FAKE_PROXY_FAIL", "1")
    rc = launcher.run_session(opts(tmp_path, keep=keep), parse_policy(POLICY))
    assert rc == 125
    assert "missing secrets: api_key" in capsys.readouterr().err
    calls = fake_podman()
    proxy = next(c for c in calls if c[:2] == ["run", "-d"])
    assert "--rm" not in proxy  # preserve startup logs and honor --keep
    assert not any(c[0] == "run" and "-d" not in c for c in calls)  # agent never started
    assert sum(1 for c in calls if c[0] == "rm" or c[:2] == ["network", "rm"]) == (0 if keep else 4)
    if not keep:
        assert next(i for i, c in enumerate(calls) if c[0] == "logs") < next(
            i for i, c in enumerate(calls) if c[0] == "rm"
        )


def test_dry_run_touches_nothing(tmp_path, fake_podman, capsys):
    rc = launcher.run_session(opts(tmp_path), parse_policy(POLICY), dry_run=True)
    assert rc == 0
    err = capsys.readouterr().err
    assert "podman network create --internal --disable-dns" in err
    assert "--runtime krun" in err
    assert not (tmp_path / "podman.log").exists()


def test_cli_refuses_home_as_workspace(tmp_path, monkeypatch):
    from hobgoblin import cli

    pol = tmp_path / "p.toml"
    pol.write_text('version = 1\n[[rule]]\nhost = "pypi.org"\naction = "tunnel"\n')
    for bad in (str(Path.home()), "/tmp", "/", "/home"):
        assert cli.main(["run", "--policy", str(pol), "--workspace", bad, "--dry-run"]) == 2, bad


def test_cli_check_policy(capsys):
    from hobgoblin import cli

    example = Path(__file__).parent.parent / "examples" / "policy.toml"
    assert cli.main(["check-policy", str(example)]) == 0
    out = capsys.readouterr().out
    assert "inspect  github.com:443" in out and "github_token" in out


def test_audit_summary_and_suggest(tmp_path):
    from hobgoblin.audit import suggest_rules, summarize

    log = tmp_path / "audit.jsonl"
    log.write_text(
        "\n".join(
            json.dumps(r)
            for r in [
                {"event": "connect", "decision": "would_deny", "host": "crates.io", "port": 443, "reason": "x"},
                {"event": "connect", "decision": "deny", "host": "evil.com", "port": 443, "reason": "not allowed"},
                {"event": "upstream", "decision": "allow", "host": "pypi.org"},
            ]
        )
    )
    s = summarize(log)
    assert "evil.com: not allowed" in s and "pypi.org (1)" in s
    sug = suggest_rules(log)
    assert 'host = "crates.io"' in sug
    from hobgoblin.policy import parse_policy as pp
    import tomllib

    pp({"version": 1, **tomllib.loads(sug)})  # suggestions are valid policy


# ------------------------------------------------------------ --state


def test_state_is_mounted_and_tools_pointed_at_it(tmp_path, session):
    st = tmp_path / "agent-state"
    a = cmd_agent(session, opts(tmp_path, state=st), parse_policy(POLICY), "10.89.0.2")
    assert f"{st}:/state:Z" in mounts(a)
    env = flag_values(a, "-e")
    for want in ("XDG_DATA_HOME=/state/data", "XDG_CONFIG_HOME=/state/config",
                 "XDG_STATE_HOME=/state/state", "XDG_CACHE_HOME=/state/cache",
                 "CLAUDE_CONFIG_DIR=/state/claude", "HISTFILE=/state/bash_history"):
        assert want in env, want
    # the state mount carries nothing of the proxy's
    joined = " ".join(a)
    assert "/run/secrets" not in joined and str(session.state_dir) not in joined


def test_user_env_overrides_state_env(tmp_path, session):
    o = opts(tmp_path, state=tmp_path / "st", env=["XDG_DATA_HOME=/workspace/.data"])
    env = flag_values(cmd_agent(session, o, parse_policy(POLICY), "10.89.0.2"), "-e")
    # podman applies -e in order, so the later user value wins
    assert env.index("XDG_DATA_HOME=/workspace/.data") > env.index("XDG_DATA_HOME=/state/data")


def test_state_relabel_follows_workspace(tmp_path, session):
    a = cmd_agent(session, opts(tmp_path, state=tmp_path / "st", relabel="none"), parse_policy(POLICY), "x")
    assert f"{tmp_path / 'st'}:/state" in mounts(a)


def test_state_survives_session_and_is_private(tmp_path, fake_podman):
    st = tmp_path / "keep" / "proj"
    rc = launcher.run_session(opts(tmp_path, state=st), parse_policy({"version": 1, "rule": [{"host": "pypi.org", "action": "tunnel"}]}))
    assert rc == 0
    assert st.is_dir() and stat.S_IMODE(st.stat().st_mode) == 0o700
    (st / "data").mkdir()
    rc = launcher.run_session(opts(tmp_path, state=st), parse_policy({"version": 1, "rule": [{"host": "pypi.org", "action": "tunnel"}]}))
    assert rc == 0 and (st / "data").is_dir()  # second session reuses it, cleanup leaves it
    agent = [c for c in fake_podman() if c[0] == "run" and "-d" not in c][-1]
    assert f"{st}:/state:Z" in agent


def _cli_run(tmp_path, *extra):
    from hobgoblin import cli

    pol = tmp_path / "p.toml"
    pol.write_text('version = 1\n[[rule]]\nhost = "pypi.org"\naction = "tunnel"\n')
    ws = tmp_path / "proj"
    ws.mkdir(exist_ok=True)
    return cli.main(["run", "--policy", str(pol), "--workspace", str(ws), *extra, "--dry-run", "--", "bash"])


@pytest.mark.parametrize("flags", [(), ("--state",)])
def test_cli_state_default_is_per_project(tmp_path, fake_podman, capsys, flags):
    assert _cli_run(tmp_path, *flags) == 0
    err = capsys.readouterr().err
    base = tmp_path / "state" / "hobgoblin" / "state"
    line = next(x for x in err.splitlines() if x.startswith("hobgobs: agent state "))
    path = Path(line.split()[3])
    assert path.parent == base and path.name.startswith("proj-")
    assert f"{path}:/state:Z" in err
    assert not path.exists()  # dry run creates nothing


def test_cli_no_state(tmp_path, fake_podman, capsys):
    assert _cli_run(tmp_path, "--no-state") == 0
    err = capsys.readouterr().err
    assert ":/state" not in err and "XDG_DATA_HOME=" not in err and "CLAUDE_CONFIG_DIR=" not in err


def test_cli_state_explicit_dir(tmp_path, fake_podman, capsys):
    assert _cli_run(tmp_path, "--state", str(tmp_path / "mystate")) == 0
    assert f"{tmp_path / 'mystate'}:/state:Z" in capsys.readouterr().err


def test_cli_refuses_unsafe_state(tmp_path, fake_podman, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    bad = [
        str(tmp_path / "home"),              # home itself
        str(tmp_path),                       # contains home and the workspace
        "/",
        str(tmp_path / "proj" / ".state"),   # inside the workspace
        str(tmp_path / "state" / "hobgoblin"),            # holds every session's audit log
        str(tmp_path / "state" / "hobgoblin" / "sessions" / "x"),
        str(tmp_path / "a:b"),               # would break podman -v parsing
    ]
    for b in bad:
        assert _cli_run(tmp_path, "--state", b) == 2, b
