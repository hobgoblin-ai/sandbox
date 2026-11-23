"""Egress policy: loading, validation and matching.

Standard library only, so the host-side launcher needs nothing beyond Python
and podman. The same module is used inside the proxy container.

Policy file (TOML)::

    version = 1

    [defaults]
    mode = "enforce"        # "enforce" | "audit" (log would-be denials, allow them)
    allow_ech = false       # refuse TLS ClientHellos carrying Encrypted Client Hello

    [network]
    allow_cidrs = []        # escape hatch for internal services (beats built-in blocks)
    deny_cidrs  = []        # extra blocks (beats allow_cidrs)

    [[rule]]
    host = "pypi.org"       # exact host, or "*.example.com" for subdomains only
    action = "tunnel"       # tunnel | inspect | tcp
    ports = [443]

    [[rule]]
    host = "api.github.com"
    action = "inspect"
      [[rule.allow]]
      methods = ["GET"]
      paths = ["/repos/myorg/**"]
      [[rule.inject]]
      header = "Authorization"
      secret = "github_token"
      prefix = "Bearer "

Actions:
  tunnel  - TLS passthrough. SNI must equal the CONNECT host. No path control.
  inspect - TLS is terminated with a per-session, name-constrained CA so that
            method/path rules apply and credentials can be injected.
  tcp     - opaque TCP passthrough to an explicit port (e.g. ssh to :22).
"""

from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ACTIONS = ("tunnel", "inspect", "tcp")
MODES = ("enforce", "audit")
_HOST_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
_SECRET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$")
_METHOD = re.compile(r"^[A-Z]+$")


class PolicyError(ValueError):
    """The policy file is invalid. Message says where and why."""


# --------------------------------------------------------------------------
# Hosts


def normalize_host(host: str) -> str | None:
    """Lower-case, strip one trailing dot. Returns None for anything that is
    not a plain ASCII DNS name or IP literal (so it can never match a rule)."""
    if not host:
        return None
    h = host.strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if h.endswith("."):
        h = h[:-1]
    if is_ip_literal(h):
        return str(ipaddress.ip_address(h))
    if not h.isascii() or len(h) > 253:
        return None
    labels = h.split(".")
    if not all(_HOST_LABEL.match(label) for label in labels):
        return None
    return h


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Paths


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """`**` matches anything (including '/'), `*` matches within one path
    segment, `?` matches one non-'/' character. Everything else is literal."""
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


_AMBIGUOUS_ENCODINGS = ("%2f", "%5c", "%2e", "%00")


def path_is_ambiguous(path: str) -> str | None:
    """Reject paths whose meaning may differ between us and the upstream
    server (dot segments, encoded separators, backslashes). Returns a reason
    or None. Only applied when a rule restricts paths."""
    if not path.startswith("/"):
        return "path does not start with /"
    low = path.lower()
    for enc in _AMBIGUOUS_ENCODINGS:
        if enc in low:
            return f"path contains encoded {enc}"
    if "\\" in path:
        return "path contains backslash"
    if "//" in path:
        return "path contains empty segment"
    for seg in path.split("/"):
        if seg in (".", ".."):
            return "path contains dot segment"
    return None


# --------------------------------------------------------------------------
# Rules


@dataclass(frozen=True)
class AllowEntry:
    methods: tuple[str, ...]  # empty = any method
    paths: tuple[str, ...]
    _regexes: tuple[re.Pattern[str], ...] = field(compare=False, repr=False)

    def matches(self, method: str, path: str) -> bool:
        if self.methods and method.upper() not in self.methods:
            return False
        return any(rx.match(path) for rx in self._regexes)


@dataclass(frozen=True)
class Inject:
    header: str
    secret: str
    prefix: str = ""
    basic_user: str | None = None  # if set: "Basic base64(user:secret)"


@dataclass(frozen=True)
class Rule:
    host: str  # normalized; "*.example.com" for wildcard
    action: str
    ports: tuple[int, ...]
    allow: tuple[AllowEntry, ...] = ()  # empty = everything (inspect only)
    inject: tuple[Inject, ...] = ()
    websocket: bool = False
    index: int = 0  # position in file, for messages

    @property
    def is_wildcard(self) -> bool:
        return self.host.startswith("*.")

    def matches_host(self, host: str) -> bool:
        if self.is_wildcard:
            suffix = self.host[1:]  # ".example.com"
            return host.endswith(suffix) and len(host) > len(suffix)
        return host == self.host

    def permits_request(self, method: str, path: str) -> tuple[bool, str]:
        """For inspect/plain-http requests. Returns (allowed, reason)."""
        if not self.allow:
            return True, "rule allows all paths"
        bad = path_is_ambiguous(path)
        if bad:
            return False, bad
        for entry in self.allow:
            if entry.matches(method, path):
                return True, "matched allow entry"
        return False, f"{method} {path} not in allow list for {self.host}"


@dataclass(frozen=True)
class Policy:
    rules: tuple[Rule, ...]
    mode: str = "enforce"
    allow_ech: bool = False
    allow_cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    deny_cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()

    @property
    def audit_only(self) -> bool:
        return self.mode == "audit"

    def match(self, host: str, port: int | None = None) -> Rule | None:
        """Most specific rule wins: exact host, then longest wildcard suffix.
        If port is given, the rule must list it."""
        h = normalize_host(host)
        if h is None:
            return None
        candidates = [r for r in self.rules if r.matches_host(h)]
        if port is not None:
            candidates = [r for r in candidates if port in r.ports]
        if not candidates:
            return None
        exact = [r for r in candidates if not r.is_wildcard]
        if exact:
            return exact[0]
        return max(candidates, key=lambda r: len(r.host))

    def inspect_hosts(self) -> list[str]:
        return [r.host for r in self.rules if r.action == "inspect"]

    def secret_names(self) -> list[str]:
        names: list[str] = []
        for r in self.rules:
            for inj in r.inject:
                if inj.secret not in names:
                    names.append(inj.secret)
        return names


# --------------------------------------------------------------------------
# Loading


def _err(where: str, msg: str) -> PolicyError:
    return PolicyError(f"{where}: {msg}")


def _str_list(value, where: str, key: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise _err(where, f"'{key}' must be a list of strings")
    return value


def _cidrs(value, where: str, key: str):
    out = []
    for c in _str_list(value, where, key):
        try:
            out.append(ipaddress.ip_network(c, strict=False))
        except ValueError as e:
            raise _err(where, f"bad CIDR in '{key}': {c!r} ({e})") from None
    return tuple(out)


def _parse_rule_host(raw, where: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise _err(where, "'host' is required")
    if raw.startswith("*."):
        base = normalize_host(raw[2:])
        if base is None or is_ip_literal(base):
            raise _err(where, f"invalid wildcard host {raw!r}")
        if "." not in base:
            raise _err(where, f"wildcard {raw!r} is too broad (covers a whole TLD)")
        return "*." + base
    if "*" in raw:
        raise _err(where, f"only a leading '*.' wildcard is supported, got {raw!r}")
    h = normalize_host(raw)
    if h is None:
        raise _err(where, f"invalid host {raw!r}")
    return h


def _parse_rule(raw: dict, i: int) -> Rule:
    where = f"rule #{i + 1}"
    if not isinstance(raw, dict):
        raise _err(where, "must be a table")
    known = {"host", "action", "ports", "allow", "inject", "websocket", "comment"}
    unknown = set(raw) - known
    if unknown:
        raise _err(where, f"unknown keys: {', '.join(sorted(unknown))}")

    host = _parse_rule_host(raw.get("host"), where)
    where = f"rule #{i + 1} ({host})"
    action = raw.get("action")
    if action not in ACTIONS:
        raise _err(where, f"'action' must be one of {', '.join(ACTIONS)}")

    if "ports" in raw:
        ports = raw["ports"]
        if (
            not isinstance(ports, list)
            or not ports
            or not all(isinstance(p, int) and 0 < p < 65536 for p in ports)
        ):
            raise _err(where, "'ports' must be a non-empty list of port numbers")
        ports = tuple(ports)
    elif action == "tcp":
        raise _err(where, "action 'tcp' requires explicit 'ports'")
    else:
        ports = (443,)

    allow_raw = raw.get("allow", [])
    inject_raw = raw.get("inject", [])
    websocket = raw.get("websocket", False)
    if not isinstance(websocket, bool):
        raise _err(where, "'websocket' must be true or false")

    if action != "inspect":
        # tunnel/tcp cannot see requests; refuse config that implies it can.
        if allow_raw:
            raise _err(where, f"'allow' needs action = \"inspect\" (a {action} rule cannot see paths)")
        if inject_raw:
            raise _err(where, f"'inject' needs action = \"inspect\" (a {action} rule cannot add headers)")
        if websocket:
            raise _err(where, "'websocket' only applies to inspect rules")
    if action == "inspect" and is_ip_literal(host):
        raise _err(where, "inspect is not supported for IP literals (the session CA only signs DNS names)")

    allow = []
    if not isinstance(allow_raw, list):
        raise _err(where, "'allow' must be an array of tables")
    for j, a in enumerate(allow_raw):
        w = f"{where} allow #{j + 1}"
        if not isinstance(a, dict):
            raise _err(w, "must be a table")
        if set(a) - {"methods", "paths"}:
            raise _err(w, f"unknown keys: {', '.join(sorted(set(a) - {'methods', 'paths'}))}")
        methods = tuple(m.upper() for m in _str_list(a.get("methods", []), w, "methods"))
        for m in methods:
            if not _METHOD.match(m):
                raise _err(w, f"bad method {m!r}")
        paths = tuple(_str_list(a.get("paths", ["/**"]), w, "paths"))
        if not paths:
            raise _err(w, "'paths' must not be empty")
        for p in paths:
            if not p.startswith("/"):
                raise _err(w, f"path pattern must start with '/': {p!r}")
        allow.append(AllowEntry(methods, paths, tuple(glob_to_regex(p) for p in paths)))

    inject = []
    if not isinstance(inject_raw, list):
        raise _err(where, "'inject' must be an array of tables")
    for j, inj in enumerate(inject_raw):
        w = f"{where} inject #{j + 1}"
        if not isinstance(inj, dict):
            raise _err(w, "must be a table")
        extra = set(inj) - {"header", "secret", "prefix", "basic_user"}
        if extra:
            raise _err(w, f"unknown keys: {', '.join(sorted(extra))}")
        header, secret = inj.get("header"), inj.get("secret")
        if not isinstance(header, str) or not _HEADER_NAME.match(header):
            raise _err(w, "'header' must be a valid header name")
        if header.lower() in ("host", "content-length", "transfer-encoding", "connection"):
            raise _err(w, f"refusing to inject framing header {header!r}")
        if not isinstance(secret, str) or not _SECRET_NAME.match(secret):
            raise _err(w, "'secret' must be a podman secret name")
        prefix = inj.get("prefix", "")
        basic_user = inj.get("basic_user")
        if not isinstance(prefix, str) or any(c in prefix for c in "\r\n"):
            raise _err(w, "'prefix' must be a single-line string")
        if basic_user is not None and (not isinstance(basic_user, str) or ":" in basic_user):
            raise _err(w, "'basic_user' must be a string without ':'")
        if basic_user is not None and prefix:
            raise _err(w, "use either 'prefix' or 'basic_user', not both")
        inject.append(Inject(header, secret, prefix, basic_user))

    return Rule(
        host=host,
        action=action,
        ports=ports,
        allow=tuple(allow),
        inject=tuple(inject),
        websocket=websocket,
        index=i,
    )


def parse_policy(data: dict) -> Policy:
    if not isinstance(data, dict):
        raise PolicyError("policy must be a TOML document")
    known = {"version", "defaults", "network", "rule"}
    unknown = set(data) - known
    if unknown:
        raise PolicyError(f"unknown top-level keys: {', '.join(sorted(unknown))}")
    if data.get("version") != 1:
        raise PolicyError("'version = 1' is required")

    defaults = data.get("defaults", {})
    if set(defaults) - {"mode", "allow_ech"}:
        raise PolicyError(f"[defaults]: unknown keys: {', '.join(sorted(set(defaults) - {'mode', 'allow_ech'}))}")
    mode = defaults.get("mode", "enforce")
    if mode not in MODES:
        raise PolicyError(f"[defaults]: 'mode' must be one of {', '.join(MODES)}")
    allow_ech = defaults.get("allow_ech", False)
    if not isinstance(allow_ech, bool):
        raise PolicyError("[defaults]: 'allow_ech' must be true or false")

    net = data.get("network", {})
    if set(net) - {"allow_cidrs", "deny_cidrs"}:
        raise PolicyError(f"[network]: unknown keys: {', '.join(sorted(set(net) - {'allow_cidrs', 'deny_cidrs'}))}")
    allow_cidrs = _cidrs(net.get("allow_cidrs", []), "[network]", "allow_cidrs")
    deny_cidrs = _cidrs(net.get("deny_cidrs", []), "[network]", "deny_cidrs")

    rules_raw = data.get("rule", [])
    if not isinstance(rules_raw, list):
        raise PolicyError("'rule' must be an array of tables ([[rule]])")
    rules = tuple(_parse_rule(r, i) for i, r in enumerate(rules_raw))

    seen: dict[tuple[str, int], int] = {}
    for r in rules:
        for p in r.ports:
            key = (r.host, p)
            if key in seen:
                raise PolicyError(
                    f"rule #{r.index + 1}: {r.host}:{p} already covered by rule #{seen[key] + 1}"
                )
            seen[key] = r.index

    return Policy(
        rules=rules,
        mode=mode,
        allow_ech=allow_ech,
        allow_cidrs=allow_cidrs,
        deny_cidrs=deny_cidrs,
    )


def load_policy(path: str | Path) -> Policy:
    p = Path(path)
    try:
        data = tomllib.loads(p.read_text())
    except tomllib.TOMLDecodeError as e:
        raise PolicyError(f"{p}: {e}") from None
    try:
        return parse_policy(data)
    except PolicyError as e:
        raise PolicyError(f"{p}: {e}") from None
