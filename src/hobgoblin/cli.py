"""hobgoblin command line."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from hobgoblin import __version__
from hobgoblin.policy import PolicyError, load_policy


def _default_policy() -> Path:
    for p in (Path("hobgoblin.toml"), Path(".hobgoblin/policy.toml")):
        if p.is_file():
            return p
    cfg = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "hobgoblin" / "policy.toml"
    return cfg


def cmd_run(a) -> int:
    from hobgoblin.launcher import Options, run_session

    try:
        policy = load_policy(a.policy)
    except (PolicyError, OSError) as e:
        print(f"hobgobs: {e}", file=sys.stderr)
        return 2
    ws = Path(a.workspace).resolve()
    if not ws.is_dir():
        print(f"hobgobs: workspace {ws} is not a directory", file=sys.stderr)
        return 2
    home = Path.home().resolve()
    system = {Path(p) for p in ("/", "/tmp", "/var", "/var/tmp", "/usr", "/etc", "/home", "/root", "/opt", "/srv")}
    if ws == home or ws in system or home.is_relative_to(ws):
        print(f"hobgobs: refusing to give the agent {ws}; pick a project directory", file=sys.stderr)
        return 2
    state = None
    if not a.no_state:
        state, why = _agent_state_dir(a.state, ws, home, system)
        if why:
            print(f"hobgobs: refusing --state {state}: {why}", file=sys.stderr)
            return 2
    cmd = list(a.command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    o = Options(
        policy_path=Path(a.policy),
        workspace=ws,
        agent_image=a.image,
        proxy_image=a.proxy_image,
        command=cmd,
        runtime=a.runtime,
        selinux=a.selinux,
        relabel=a.relabel,
        cpus=a.cpus,
        memory=a.memory,
        env=a.env or [],
        upstream_ca=Path(a.upstream_ca) if a.upstream_ca else None,
        tty=sys.stdin.isatty() and sys.stdout.isatty(),
        keep=a.keep,
        state=state,
    )
    return run_session(o, policy, dry_run=a.dry_run, verbose=a.verbose)


def _agent_state_dir(value: str | None, ws: Path, home: Path, system: set[Path]) -> tuple[Path, str | None]:
    """Resolve --state and say why it is unsafe, if it is. The directory is
    mounted read-write into the VM, so it must not expose more than itself."""
    from hobgoblin.launcher import default_agent_state, runtime_base, state_base

    p = Path(value).expanduser().resolve() if value else default_agent_state(ws)
    if ":" in str(p) or "," in str(p):
        return p, "':' and ',' are not allowed in the path (podman -v syntax)"
    if p == home or p in system or any(x.is_relative_to(p) for x in (home, ws)):
        return p, "it is, or contains, your home directory or the workspace"
    if p.is_relative_to(ws):
        return p, "it is inside the workspace; use a directory outside it"
    for own in (state_base(), runtime_base()):
        if own.resolve().is_relative_to(p) or p.is_relative_to(own.resolve()):
            return p, f"it overlaps hobgoblin's own files in {own}"
    return p, None


def cmd_check(a) -> int:
    try:
        p = load_policy(a.policy)
    except (PolicyError, OSError) as e:
        print(f"invalid: {e}", file=sys.stderr)
        return 1
    print(f"ok: {len(p.rules)} rules, mode={p.mode}")
    for r in p.rules:
        extra = []
        if r.allow:
            extra.append(f"{len(r.allow)} allow entries")
        if r.inject:
            extra.append("injects " + ", ".join(f"{i.header}<-{i.secret}" for i in r.inject))
        ports = ",".join(map(str, r.ports))
        print(f"  #{r.index + 1:<3} {r.action:<8} {r.host}:{ports}" + (f"  ({'; '.join(extra)})" if extra else ""))
    if p.secret_names():
        print("secrets needed (podman secret create NAME -): " + ", ".join(p.secret_names()))
    if p.audit_only:
        print("warning: audit mode - unlisted destinations are ALLOWED and only logged")
    return 0


def cmd_audit(a) -> int:
    from hobgoblin.audit import suggest_rules, summarize
    from hobgoblin.launcher import state_base

    path = Path(a.log)
    if not path.exists():
        path = state_base() / a.log / "audit.jsonl"
    if a.suggest:
        print(suggest_rules(path))
    else:
        print(summarize(path, top=a.top))
    return 0


def _check(label: str, ok: bool, detail: str = "") -> bool:
    print(f"  [{'ok' if ok else '!!'}] {label}" + (f" - {detail}" if detail else ""))
    return ok


def cmd_doctor(a) -> int:
    print("hobgobs doctor")
    good = True
    podman = shutil.which("podman")
    good &= _check("podman installed", bool(podman))
    if podman:
        v = subprocess.run(["podman", "version", "--format", "{{.Client.Version}}"], capture_output=True, text=True)
        ver = v.stdout.strip()
        major = int(ver.split(".")[0]) if ver[:1].isdigit() else 0
        good &= _check("podman >= 5 (pasta networking for rootless)", major >= 5, ver or "unknown")
        info = subprocess.run(
            ["podman", "info", "--format", "{{.Host.Security.Rootless}} {{.Host.NetworkBackend}}"],
            capture_output=True, text=True,
        ).stdout.split()
        if info:
            good &= _check("rootless", info[0] == "true")
            good &= _check("netavark network backend", len(info) > 1 and info[1] == "netavark", " ".join(info[1:]))
        imgs = {
            img: subprocess.run(["podman", "image", "exists", img]).returncode == 0
            for img in (a.proxy_image, a.image)
        }
        for img, ok in imgs.items():
            good &= _check(f"image {img}", ok, "" if ok else "build it: make images")
    krun = shutil.which("krun") or Path("/usr/bin/krun").exists()
    good &= _check("krun runtime (crun-krun)", bool(krun), "" if krun else "sudo dnf install crun-krun")
    kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
    good &= _check("/dev/kvm accessible", kvm, "" if kvm else "add yourself to the kvm group")
    passt = shutil.which("pasta")
    _check("pasta installed", bool(passt), "" if passt else "sudo dnf install passt")
    enforce = Path("/sys/fs/selinux/enforce")
    if enforce.exists():
        _check("SELinux enforcing", enforce.read_text().strip() == "1")
        seinfo = shutil.which("seinfo")
        if seinfo:
            r = subprocess.run([seinfo, "-t", "hobgoblin_proxy.process"], capture_output=True, text=True)
            _check(
                "hobgoblin_proxy SELinux type loaded",
                "hobgoblin_proxy.process" in r.stdout,
                "use --selinux hobgoblin" if "hobgoblin_proxy.process" in r.stdout else "make selinux-install",
            )
    else:
        _check("SELinux present", False, "no SELinux; MCS separation unavailable")
    print("ready" if good else "not ready: fix the items marked !!")
    return 0 if good else 1


def build_parser() -> argparse.ArgumentParser:
    from hobgoblin.launcher import DEFAULT_AGENT_IMAGE, DEFAULT_PROXY_IMAGE

    ap = argparse.ArgumentParser(prog="hobgobs", description="Run an agent in a krun microVM with policy-controlled egress.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="start a sandboxed agent session")
    r.add_argument("--policy", default=str(_default_policy()), help="policy TOML (default: ./hobgoblin.toml, else ~/.config/hobgoblin/policy.toml)")
    r.add_argument("--workspace", default=".", help="directory mounted at /workspace (default: .)")
    state = r.add_mutually_exclusive_group()
    state.add_argument(
        "--state",
        nargs="?",
        const="",
        metavar="DIR",
        help="mount DIR at /state for agent history and settings (default: a persistent per-project directory)",
    )
    state.add_argument("--no-state", action="store_true", help="run without loading or saving per-project agent state")
    r.add_argument("--image", default=DEFAULT_AGENT_IMAGE, help="agent image")
    r.add_argument("--proxy-image", default=DEFAULT_PROXY_IMAGE)
    r.add_argument("--runtime", default="krun", help="OCI runtime for the agent (default: krun)")
    r.add_argument("--selinux", choices=["default", "hobgoblin"], default="default",
                   help="'hobgoblin' runs the proxy as hobgoblin_proxy.process (make selinux-install)")
    r.add_argument("--relabel", choices=["Z", "z", "none"], default="Z", help="SELinux relabel for the workspace mount")
    r.add_argument("--cpus")
    r.add_argument("--memory", default="4g")
    r.add_argument("-e", "--env", action="append", help="extra KEY=VALUE for the agent (never put secrets here)")
    r.add_argument("--upstream-ca", help="PEM to verify upstream TLS with (corporate inspection CA)")
    r.add_argument("--keep", action="store_true", help="leave containers and networks for debugging")
    r.add_argument("--dry-run", action="store_true", help="print podman commands without running them")
    r.add_argument("-v", "--verbose", action="store_true")
    r.add_argument("command", nargs=argparse.REMAINDER, help="command to run in the agent (after --)")
    r.set_defaults(fn=cmd_run)

    c = sub.add_parser("check-policy", help="validate a policy and print what it allows")
    c.add_argument("policy")
    c.set_defaults(fn=cmd_check)

    au = sub.add_parser("audit", help="summarize a session's audit log")
    au.add_argument("log", help="audit.jsonl path or session id")
    au.add_argument("--top", type=int, default=15)
    au.add_argument("--suggest", action="store_true", help="draft rules from audit-mode would-be denials")
    au.set_defaults(fn=cmd_audit)

    d = sub.add_parser("doctor", help="check host prerequisites")
    d.add_argument("--image", default=DEFAULT_AGENT_IMAGE)
    d.add_argument("--proxy-image", default=DEFAULT_PROXY_IMAGE)
    d.set_defaults(fn=cmd_doctor)
    return ap


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
