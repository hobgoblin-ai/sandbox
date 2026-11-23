"""Entrypoint of the proxy container.

1. Validate the policy and check every referenced secret is present.
2. Generate the session CA into the container's tmpfs (never a volume) and
   publish the agent-facing certificate files.
3. exec mitmdump with the hobgoblin addon.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from hobgoblin import ca
from hobgoblin.policy import PolicyError, load_policy


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hobgoblin-proxy")
    ap.add_argument("--policy", default="/etc/hobgoblin/policy.toml")
    ap.add_argument("--listen-port", type=int, default=3128)
    ap.add_argument("--listen-host", default="0.0.0.0")
    ap.add_argument("--confdir", default="/tmp/hobgoblin-mitm", help="must be on tmpfs; holds the CA key")
    ap.add_argument("--pub-dir", default="/run/hobgoblin/pub", help="certificates for the agent + ready marker")
    ap.add_argument("--audit-log", default="/var/log/hobgoblin/audit.jsonl")
    ap.add_argument("--secrets-dir", default="/run/secrets")
    ap.add_argument("--session", default=os.environ.get("HOBGOBLIN_SESSION", ""))
    ap.add_argument("--deny-cidrs", default=os.environ.get("HOBGOBLIN_DENY_CIDRS", ""))
    ap.add_argument(
        "--client-cidrs",
        default=os.environ.get("HOBGOBLIN_CLIENT_CIDRS", ""),
        help="only accept clients from these CIDRs (the agent network)",
    )
    ap.add_argument(
        "--upstream-ca",
        default=os.environ.get("HOBGOBLIN_UPSTREAM_CA", ""),
        help="PEM bundle to verify upstream servers with (e.g. a corporate TLS-inspection CA)",
    )
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    try:
        policy = load_policy(args.policy)
    except (PolicyError, OSError) as e:
        print(f"hobgoblin-proxy: {e}", file=sys.stderr)
        return 2

    missing = [n for n in policy.secret_names() if not (Path(args.secrets_dir) / n).is_file()]
    if missing:
        print(
            "hobgoblin-proxy: missing secrets: " + ", ".join(missing) + f" (expected under {args.secrets_dir})",
            file=sys.stderr,
        )
        return 2

    pub = Path(args.pub_dir)
    ready = pub / "ready"
    ready.unlink(missing_ok=True)
    ca.write_session_ca(Path(args.confdir), pub, policy.inspect_hosts(), args.session or "local")

    addon = Path(__file__).with_name("addon.py")
    cmd = [
        "mitmdump",
        "--mode", f"regular@{args.listen_port}",
        "--listen-host", args.listen_host,
        "-s", str(addon),
        "--set", f"confdir={args.confdir}",
        "--set", "connection_strategy=lazy",  # never touch upstream before policy checks
        "--set", "upstream_cert=false",  # leaf certs name only the CONNECT host
        "--set", "ssl_insecure=false",
        "--set", "stream_large_bodies=32m",
        "--set", "block_global=true",  # refuse clients from public addresses
        "--set", "flow_detail=0",
        "--set", "termlog_verbosity=" + ("info" if args.verbose else "warn"),
        "--set", f"hobgoblin_policy={args.policy}",
        "--set", f"hobgoblin_audit_log={args.audit_log}",
        "--set", f"hobgoblin_secrets_dir={args.secrets_dir}",
        "--set", f"hobgoblin_deny_cidrs={args.deny_cidrs}",
        "--set", f"hobgoblin_session={args.session}",
        "--set", f"hobgoblin_ready_file={ready}",
        "--set", f"hobgoblin_client_cidrs={args.client_cidrs}",
    ]
    if args.upstream_ca:
        cmd += ["--set", f"ssl_verify_upstream_trusted_ca={args.upstream_ca}"]
    sys.stdout.flush()
    os.execvp(cmd[0], cmd)
    return 0  # not reached


if __name__ == "__main__":
    sys.exit(main())
