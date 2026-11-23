"""Summaries of the proxy's JSON-lines audit log."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


def load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def summarize(path: Path, top: int = 10) -> str:
    recs = load(path)
    if not recs:
        return f"hobgobs: no audit records ({path})"
    decisions = Counter(r.get("decision") for r in recs)
    hosts = Counter(r.get("host") for r in recs if r.get("decision") == "allow" and r.get("event") == "upstream")
    denied = Counter(
        (r.get("host") or "?", r.get("reason") or "")
        for r in recs
        if r.get("decision") in ("deny", "would_deny")
    )
    lines = [f"hobgobs: audit log {path}"]
    lines.append(
        "  "
        + ", ".join(f"{k}={v}" for k, v in sorted(decisions.items(), key=lambda kv: str(kv[0])) if k != "info")
    )
    if hosts:
        lines.append("  upstream connections: " + ", ".join(f"{h} ({n})" for h, n in hosts.most_common(top)))
    if denied:
        lines.append("  blocked (or would block, in audit mode):")
        for (host, reason), n in denied.most_common(top):
            lines.append(f"    {n:>4}  {host}: {reason}")
    if any(r.get("decision") == "redacted" for r in recs):
        lines.append("  note: an upstream echoed an injected credential; it was redacted")
    return "\n".join(lines)


def suggest_rules(path: Path) -> str:
    """Turn audit-mode would_deny CONNECTs into starter rules (as tunnel).
    A starting point for review, not a policy to apply blindly."""
    seen: dict[tuple[str, int], int] = {}
    for r in load(path):
        if r.get("event") == "connect" and r.get("decision") == "would_deny" and r.get("host"):
            key = (r["host"], int(r.get("port") or 443))
            seen[key] = seen.get(key, 0) + 1
    if not seen:
        return "# no would-be denials recorded"
    out = ["# Suggested from audit log; review before use. Consider inspect + allow for", "# anything that can write (git hosts, APIs, paste sites)."]
    for (host, port), n in sorted(seen.items()):
        out += ["", f"# seen {n}x", "[[rule]]", f'host = "{host}"', 'action = "tunnel"']
        if port != 443:
            out.append(f"ports = [{port}]")
    return "\n".join(out)
