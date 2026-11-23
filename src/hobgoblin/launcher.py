"""Host-side orchestration with rootless podman. Standard library only.

Topology for one session <sid>::

    hobgoblin-<sid>-int     podman network, --internal, --disable-dns
                         (no route out, no resolver)
       |-- hobgoblin-<sid>-agent   runtime krun: the agent runs in a microVM.
       |                        Its VMM's sockets live in this namespace,
       |                        so the proxy is the only thing it can reach.
       `-- hobgoblin-<sid>-proxy   mitmdump + hobgoblin addon, listens :3128
                                also on:
    hobgoblin-<sid>-egress  podman network; rootless podman 5 routes it out
                         through pasta. Only the proxy is attached.

Secrets, the CA key and the audit log live only in the proxy container.
The agent gets the workspace, the proxy address and the CA certificate.
"""

from __future__ import annotations

import json
import os
import secrets as pysecrets
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from hobgoblin.policy import Policy

DEFAULT_PROXY_IMAGE = os.environ.get("HOBGOBLIN_PROXY_IMAGE", "localhost/hobgoblin-proxy:latest")
DEFAULT_AGENT_IMAGE = os.environ.get("HOBGOBLIN_AGENT_IMAGE", "localhost/hobgoblin-agent:latest")
PROXY_PORT = 3128
CA_ENV_VARS = (
    "SSL_CERT_FILE",  # OpenSSL-based tools, Python ssl, Go (also reads SSL_CERT_DIR)
    "REQUESTS_CA_BUNDLE",  # Python requests
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "PIP_CERT",
    "AWS_CA_BUNDLE",
    "CARGO_HTTP_CAINFO",
    "DENO_CERT",
)


def runtime_base() -> Path:
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    return Path(xdg) / "hobgoblin" if xdg else Path(f"/tmp/hobgoblin-{os.getuid()}")


def _private_dir(path: Path) -> None:
    """Create (or accept) a directory only we own, refusing symlinks. Matters
    for the /tmp fallback when XDG_RUNTIME_DIR is unset."""
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    st = os.lstat(path)
    import stat as _stat

    if _stat.S_ISLNK(st.st_mode) or not _stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        raise RuntimeError(f"{path} is not a directory owned by you; refusing to use it")
    os.chmod(path, 0o700)


def state_base() -> Path:
    xdg = os.environ.get("XDG_STATE_HOME")
    return (Path(xdg) if xdg else Path.home() / ".local" / "state") / "hobgoblin" / "sessions"


def agent_state_base() -> Path:
    """Parent of the default per-project agent state directories."""
    return state_base().parent / "state"


def default_agent_state(workspace: Path) -> Path:
    """A per-project state directory: the workspace name for readability, plus a
    hash of its full path so two projects called "app" never share history."""
    import hashlib

    digest = hashlib.sha256(str(workspace).encode()).hexdigest()[:10]
    return agent_state_base().resolve() / f"{workspace.name or 'root'}-{digest}"


# Where the agent's tools keep their state unless --no-state is given. The host
# directory is mounted at AGENT_STATE_DIR; user -e values still win.
AGENT_STATE_DIR = "/state"
AGENT_STATE_ENV = (
    f"XDG_CONFIG_HOME={AGENT_STATE_DIR}/config",  # opencode config, git, ...
    f"XDG_DATA_HOME={AGENT_STATE_DIR}/data",  # opencode sessions and database
    f"XDG_STATE_HOME={AGENT_STATE_DIR}/state",
    f"XDG_CACHE_HOME={AGENT_STATE_DIR}/cache",
    f"CLAUDE_CONFIG_DIR={AGENT_STATE_DIR}/claude",  # Claude Code settings and sessions
    f"HISTFILE={AGENT_STATE_DIR}/bash_history",
    f"HOBGOBLIN_STATE={AGENT_STATE_DIR}",
)


@dataclass
class Options:
    policy_path: Path
    workspace: Path
    agent_image: str = DEFAULT_AGENT_IMAGE
    proxy_image: str = DEFAULT_PROXY_IMAGE
    command: list[str] = field(default_factory=list)
    runtime: str = "krun"
    selinux: str = "default"  # default | hobgoblin
    relabel: str = "Z"  # Z | z | none
    cpus: str | None = None
    memory: str | None = "4g"
    env: list[str] = field(default_factory=list)
    upstream_ca: Path | None = None
    tty: bool = False
    keep: bool = False
    state: Path | None = None  # host directory kept between sessions, mounted at /state


@dataclass
class Session:
    sid: str
    runtime_dir: Path  # 0700; policy copy, pub/ (proxy output), agent/ (agent input)
    state_dir: Path  # audit log, survives the session

    @classmethod
    def new(cls, sid: str | None = None) -> "Session":
        sid = sid or pysecrets.token_hex(4)
        return cls(sid, runtime_base() / sid, state_base() / sid)

    @property
    def net_int(self) -> str:
        return f"hobgoblin-{self.sid}-int"

    @property
    def net_egress(self) -> str:
        return f"hobgoblin-{self.sid}-egress"

    @property
    def proxy_name(self) -> str:
        return f"hobgoblin-{self.sid}-proxy"

    @property
    def agent_name(self) -> str:
        return f"hobgoblin-{self.sid}-agent"

    @property
    def pub(self) -> Path:
        return self.runtime_dir / "pub"

    @property
    def agent_dir(self) -> Path:
        return self.runtime_dir / "agent"

    @property
    def policy_copy(self) -> Path:
        return self.runtime_dir / "policy.toml"

    @property
    def audit_log(self) -> Path:
        return self.state_dir / "audit.jsonl"


# --------------------------------------------------------------- commands


def _vol(src: Path, dst: str, *opts: str) -> list[str]:
    o = ",".join(x for x in opts if x)
    return ["-v", f"{src}:{dst}" + (f":{o}" if o else "")]


def cmd_networks(s: Session) -> list[list[str]]:
    label = f"hobgoblin.session={s.sid}"
    return [
        ["podman", "network", "create", "--internal", "--disable-dns", "--label", label, s.net_int],
        # isolate=strict: no traffic to or from other podman networks (netavark
        # nftables/iptables drivers; firewalld ignores it, hence also the
        # proxy-side client check).
        ["podman", "network", "create", "--opt", "isolate=strict", "--label", label, s.net_egress],
    ]


def cmd_proxy(
    s: Session, o: Options, policy: Policy, deny_cidrs: list[str], client_cidrs: list[str] | None = None
) -> list[str]:
    c = [
        # Keep exited proxies until cmd_cleanup, so wait_ready can read their
        # logs instead of racing Podman's automatic removal on startup failure.
        "podman", "run", "-d",
        "--name", s.proxy_name,
        "--label", f"hobgoblin.session={s.sid}",
        "--network", s.net_egress,
        "--network", s.net_int,
        "--userns=keep-id",
        # The image's USER otherwise takes precedence, leaving the proxy
        # unable to write the user-owned certificate and audit bind mounts.
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--read-only",  # /tmp and /run become tmpfs: the CA key lives in /tmp
        "--pids-limit=256",
        "--memory=1g",
        "-e", f"HOBGOBLIN_SESSION={s.sid}",
        "-e", "HOBGOBLIN_DENY_CIDRS=" + ",".join(deny_cidrs),
        "-e", "HOBGOBLIN_CLIENT_CIDRS=" + ",".join(client_cidrs or []),
    ]
    if o.selinux == "hobgoblin":
        c += ["--security-opt", "label=type:hobgoblin_proxy.process"]
    c += _vol(s.pub, "/run/hobgoblin/pub", "Z")
    c += _vol(s.state_dir, "/var/log/hobgoblin", "Z")
    c += _vol(s.policy_copy, "/etc/hobgoblin/policy.toml", "ro", "Z")
    if o.upstream_ca:
        c += _vol(s.runtime_dir / "upstream-ca.pem", "/etc/hobgoblin/upstream-ca.pem", "ro", "Z")
        c += ["-e", "HOBGOBLIN_UPSTREAM_CA=/etc/hobgoblin/upstream-ca.pem"]
    for name in policy.secret_names():
        c += ["--secret", name]
    c += [o.proxy_image]
    return c


def agent_env(proxy_ip: str, policy: Policy) -> list[str]:
    host = f"[{proxy_ip}]" if ":" in proxy_ip else proxy_ip
    url = f"http://{host}:{PROXY_PORT}"
    env = []
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        env.append(f"{k}={url}")
    env += ["NO_PROXY=localhost,127.0.0.1,::1", "no_proxy=localhost,127.0.0.1,::1"]
    env.append("NODE_USE_ENV_PROXY=1")  # Node >= 24 built-in fetch/http honour HTTP(S)_PROXY
    for k in CA_ENV_VARS:
        env.append(f"{k}=/etc/hobgoblin/ca-bundle.pem")
    if policy.inspect_hosts():
        env.append("NODE_EXTRA_CA_CERTS=/etc/hobgoblin/ca.pem")
    # Satisfy SDKs that require a key before making a request. Only the proxy
    # reads the real secret; never import a provider key from the host.
    for provider, header, key in (
        ("api.openai.com", "authorization", "OPENAI_API_KEY"),
        ("api.anthropic.com", "x-api-key", "ANTHROPIC_API_KEY"),
    ):
        rule = policy.match(provider, 443)
        if rule and any(inj.header.lower() == header for inj in rule.inject):
            env.append(f"{key}=injected-by-hobgoblin")
    env.append("HOBGOBLIN=1")
    return env


def cmd_agent(s: Session, o: Options, policy: Policy, proxy_ip: str) -> list[str]:
    c = ["podman", "run", "--rm", "-i"]
    if o.tty:
        c.append("-t")
    c += [
        "--name", s.agent_name,
        "--label", f"hobgoblin.session={s.sid}",
        "--hostname", "hobgoblin",
        "--network", s.net_int,
        "--security-opt=no-new-privileges",
    ]
    if o.runtime:
        c += ["--runtime", o.runtime]
    if o.cpus:
        c += ["--cpus", o.cpus]
    if o.memory:
        c += ["--memory", o.memory]  # krun sizes the VM's RAM from this limit
    relabel = "" if o.relabel == "none" else o.relabel
    c += _vol(o.workspace, "/workspace", relabel)
    c += ["-w", "/workspace"]
    c += _vol(s.agent_dir, "/etc/hobgoblin", "ro", "Z")
    state_env: list[str] = []
    if o.state:
        c += _vol(o.state, AGENT_STATE_DIR, relabel)
        state_env = list(AGENT_STATE_ENV)
    for e in agent_env(proxy_ip, policy) + state_env + list(o.env):
        c += ["-e", e]
    c += [o.agent_image] + list(o.command)
    return c


def cmd_cleanup(s: Session) -> list[list[str]]:
    return [
        ["podman", "rm", "-f", "--ignore", "-t", "5", s.agent_name],
        ["podman", "rm", "-f", "--ignore", "-t", "5", s.proxy_name],
        ["podman", "network", "rm", "-f", s.net_int],
        ["podman", "network", "rm", "-f", s.net_egress],
    ]


# ----------------------------------------------------------------- host info


def host_public_addresses() -> list[str]:
    """The host's own non-private addresses, as /32 or /128. The proxy blocks
    them so the agent cannot reach services listening on the host through the
    host's public IP. Private ranges are already blocked by default."""
    import ipaddress

    try:
        out = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True, timeout=5, check=True).stdout
        data = json.loads(out)
    except (OSError, subprocess.SubprocessError, ValueError):
        return []
    cidrs = []
    for iface in data:
        for a in iface.get("addr_info", []):
            try:
                ip = ipaddress.ip_address(a.get("local", ""))
            except ValueError:
                continue
            if ip.is_global:
                cidrs.append(f"{ip}/{ip.max_prefixlen}")
    return sorted(set(cidrs))


def network_subnets(inspect_json: str) -> list[str]:
    data = json.loads(inspect_json)
    if isinstance(data, list):
        data = data[0]
    subnets = [sn["subnet"] for sn in data.get("subnets") or [] if sn.get("subnet")]
    if not subnets:
        raise RuntimeError("internal network has no subnet")
    return subnets


def proxy_ip_on(network: str, inspect_json: str) -> str:
    data = json.loads(inspect_json)
    if isinstance(data, list):
        data = data[0]
    nets = data.get("NetworkSettings", {}).get("Networks", {})
    ip = (nets.get(network) or {}).get("IPAddress")
    if not ip:
        raise RuntimeError(f"proxy has no address on {network}")
    return ip


# -------------------------------------------------------------------- runner


class Runner:
    def __init__(self, dry_run: bool = False, verbose: bool = False):
        self.dry_run = dry_run
        self.verbose = verbose

    def show(self, argv: list[str]) -> None:
        import shlex

        print("+ " + shlex.join(argv), file=sys.stderr)

    def run(self, argv: list[str], check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
        if self.dry_run or self.verbose:
            self.show(argv)
        if self.dry_run:
            return subprocess.CompletedProcess(argv, 0, "", "")
        return subprocess.run(argv, check=check, text=True, capture_output=capture)


def prepare_dirs(s: Session, o: Options) -> None:
    _private_dir(runtime_base())
    _private_dir(s.runtime_dir)
    for d in (s.pub, s.agent_dir):
        d.mkdir(exist_ok=True)
    s.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Copy, so relabelling (:Z) never touches the user's own files.
    shutil.copyfile(o.policy_path, s.policy_copy)
    if o.upstream_ca:
        shutil.copyfile(o.upstream_ca, s.runtime_dir / "upstream-ca.pem")
    if o.state:
        # Created 0700 and never removed by cleanup: it outlives the session.
        _private_dir(o.state)


def wait_ready(r: Runner, s: Session, timeout: float = 60) -> None:
    if r.dry_run:
        return
    deadline = time.time() + timeout
    while not (s.pub / "ready").exists():
        state = r.run(
            ["podman", "inspect", "--format", "{{.State.Running}}", s.proxy_name], check=False, capture=True
        )
        if state.returncode != 0 or state.stdout.strip() != "true":
            logs = r.run(["podman", "logs", s.proxy_name], check=False, capture=True)
            raise RuntimeError("proxy exited during startup:\n" + (logs.stdout + logs.stderr).strip())
        if time.time() > deadline:
            raise RuntimeError("timed out waiting for the proxy to become ready")
        time.sleep(0.2)


def run_session(o: Options, policy: Policy, dry_run: bool = False, verbose: bool = False) -> int:
    r = Runner(dry_run=dry_run, verbose=verbose)
    s = Session.new()
    print(f"hobgobs: session {s.sid}", file=sys.stderr)
    if o.state:
        print(f"hobgobs: agent state {o.state} -> {AGENT_STATE_DIR} (kept after exit)", file=sys.stderr)
    deny = host_public_addresses()
    try:
        if not dry_run:
            prepare_dirs(s, o)
        for c in cmd_networks(s):
            r.run(c, capture=not verbose)
        if dry_run:
            clients = ["<internal-subnet>"]
        else:
            clients = network_subnets(r.run(["podman", "network", "inspect", s.net_int], capture=True).stdout)
        r.run(cmd_proxy(s, o, policy, deny, clients), capture=not verbose)
        wait_ready(r, s)
        if dry_run:
            proxy_ip = "<proxy-ip>"
        else:
            for name in ("ca-bundle.pem", "ca.pem"):
                shutil.copyfile(s.pub / name, s.agent_dir / name)
            out = r.run(["podman", "inspect", s.proxy_name], capture=True).stdout
            proxy_ip = proxy_ip_on(s.net_int, out)
        print(f"hobgobs: proxy ready at {proxy_ip}:{PROXY_PORT}; starting agent", file=sys.stderr)
        rc = r.run(cmd_agent(s, o, policy, proxy_ip), check=False).returncode
    except subprocess.CalledProcessError as e:
        print(f"hobgobs: command failed: {' '.join(e.cmd)}\n{(e.stderr or '').strip()}", file=sys.stderr)
        rc = 125
    except (RuntimeError, ValueError, OSError) as e:
        print(f"hobgobs: {e}", file=sys.stderr)
        rc = 125
    except KeyboardInterrupt:
        rc = 130
    finally:
        if not o.keep:
            for c in cmd_cleanup(s):
                r.run(c, check=False, capture=True)
            if not dry_run:
                shutil.rmtree(s.runtime_dir, ignore_errors=True)
    if not dry_run:
        from hobgoblin.audit import summarize

        print(summarize(s.audit_log), file=sys.stderr)
    return rc
