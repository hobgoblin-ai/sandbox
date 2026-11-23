"""mitmproxy addon that enforces a hobgoblin egress policy.

Decision points, in the order traffic meets them:

  http_connect     CONNECT host:port must match a rule (else 403).
  tls_clienthello  SNI must be present and equal the CONNECT host; ECH is
                   refused. tunnel/tcp rules -> passthrough (no decryption),
                   inspect rules -> intercepted with the session CA.
  tcp_start        opaque (non-TLS, non-HTTP) streams only for tcp rules.
  request          Host header and request target must equal the tunnel
                   host; method/path allow-list; websocket gate; credentials
                   injected (HTTPS only), replacing anything the agent sent.
  server_connect   the proxy resolves the name itself, every address must be
                   public (or in allow_cidrs) and not in deny_cidrs, and the
                   connection is pinned to a checked IP. Enforced in audit
                   mode too.
  response         injected secrets echoed back by the server are redacted.

Loaded into mitmdump through hobgoblin/addon.py (see proxy_main.py).
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import logging
import os
import socket
import time
from dataclasses import dataclass
from pathlib import Path

from mitmproxy import exceptions, http, tcp, tls
from mitmproxy.proxy import server_hooks

from hobgoblin import netguard
from hobgoblin.policy import Policy, PolicyError, Rule, is_ip_literal, load_policy, normalize_host

log = logging.getLogger("hobgoblin")

ECH_EXTENSION = 0xFE0D
MAX_LOGGED_PATH = 512
REDACTED = b"[hobgoblin-redacted]"


@dataclass
class Tunnel:
    host: str
    port: int
    rule: Rule | None  # None only in audit mode for an unlisted host
    doomed: str | None = None  # set when the tunnel must not reach upstream


def _strip_port(host_header: str) -> str:
    h = host_header.strip()
    if h.startswith("["):
        return h[: h.find("]") + 1] if "]" in h else h
    if h.count(":") == 1:
        return h.split(":", 1)[0]
    return h


class Hobgoblin:
    def __init__(self) -> None:
        self.policy: Policy | None = None
        self.secrets: dict[str, str] = {}
        self.tunnels: dict[str, Tunnel] = {}
        self.pins: dict[str, tuple[str, int, str]] = {}
        self.extra_deny: tuple = ()
        self.client_cidrs: tuple = ()
        self.audit_fh = None
        self.session = ""

    # ------------------------------------------------------------------ setup

    def load(self, loader) -> None:
        loader.add_option("hobgoblin_policy", str, "/etc/hobgoblin/policy.toml", "Path to the hobgoblin policy (TOML).")
        loader.add_option("hobgoblin_audit_log", str, "", "Append JSON audit records to this file.")
        loader.add_option("hobgoblin_secrets_dir", str, "/run/secrets", "Directory holding secrets named in the policy.")
        loader.add_option("hobgoblin_deny_cidrs", str, "", "Extra comma-separated CIDRs to block (e.g. host addresses).")
        loader.add_option("hobgoblin_session", str, "", "Session id, copied into audit records.")
        loader.add_option("hobgoblin_ready_file", str, "", "File to create once the proxy is listening.")
        loader.add_option(
            "hobgoblin_client_cidrs", str, "",
            "Comma-separated CIDRs clients must come from (the session's internal network). Empty = any.",
        )

    def configure(self, updated) -> None:
        from mitmproxy import ctx

        o = ctx.options
        if "hobgoblin_policy" in updated or self.policy is None:
            try:
                self.policy = load_policy(o.hobgoblin_policy)
            except (PolicyError, OSError) as e:
                raise exceptions.OptionsError(f"hobgoblin: {e}") from None
            self.secrets = self._load_secrets(Path(o.hobgoblin_secrets_dir))
        if "hobgoblin_deny_cidrs" in updated:
            try:
                self.extra_deny = netguard.parse_cidrs(o.hobgoblin_deny_cidrs.split(","))
            except ValueError as e:
                raise exceptions.OptionsError(f"hobgoblin: bad hobgoblin_deny_cidrs: {e}") from None
        if "hobgoblin_client_cidrs" in updated:
            try:
                self.client_cidrs = netguard.parse_cidrs(o.hobgoblin_client_cidrs.split(","))
            except ValueError as e:
                raise exceptions.OptionsError(f"hobgoblin: bad hobgoblin_client_cidrs: {e}") from None
        if "hobgoblin_audit_log" in updated and o.hobgoblin_audit_log:
            path = Path(o.hobgoblin_audit_log)
            path.parent.mkdir(parents=True, exist_ok=True)
            self.audit_fh = open(path, "a", buffering=1, encoding="utf-8")
        self.session = o.hobgoblin_session

    def running(self) -> None:
        from mitmproxy import ctx

        mode = self.policy.mode if self.policy else "?"
        self._audit("proxy_started", "info", mode=mode, rules=len(self.policy.rules) if self.policy else 0)
        if ctx.options.hobgoblin_ready_file:
            Path(ctx.options.hobgoblin_ready_file).write_text(str(os.getpid()))

    def _load_secrets(self, secrets_dir: Path) -> dict[str, str]:
        assert self.policy is not None
        out: dict[str, str] = {}
        for name in self.policy.secret_names():
            p = secrets_dir / name
            try:
                value = p.read_text().rstrip("\r\n")
            except OSError as e:
                raise exceptions.OptionsError(
                    f"hobgoblin: policy needs secret {name!r} but {p} is unreadable ({e.strerror}). "
                    f"Create it with: podman secret create {name} -"
                ) from None
            if not value or any(c in value for c in "\r\n\0"):
                raise exceptions.OptionsError(f"hobgoblin: secret {name!r} is empty or spans multiple lines")
            out[name] = value
        return out

    # ---------------------------------------------------------------- helpers

    @property
    def allow_cidrs(self):
        return self.policy.allow_cidrs if self.policy else ()

    @property
    def deny_cidrs(self):
        return (self.policy.deny_cidrs if self.policy else ()) + self.extra_deny

    def _audit(self, event: str, decision: str, **fields) -> None:
        rec = {"ts": round(time.time(), 3), "session": self.session, "event": event, "decision": decision}
        rec.update({k: v for k, v in fields.items() if v is not None})
        line = json.dumps(rec, separators=(",", ":"))
        if self.audit_fh:
            self.audit_fh.write(line + "\n")
        level = logging.WARNING if decision in ("deny", "would_deny") else logging.INFO
        log.log(level, line)

    def _deny(self, flow: http.HTTPFlow, status: int, reason: str, **fields) -> bool:
        """Deny, or in audit mode log and let it through. Returns True if denied."""
        if self.policy and self.policy.audit_only:
            self._audit("request", "would_deny", reason=reason, **fields)
            return False
        self._audit("request", "deny", reason=reason, status=status, **fields)
        flow.response = http.Response.make(
            status,
            f"hobgoblin: blocked by egress policy: {reason}\n".encode(),
            {"Content-Type": "text/plain; charset=utf-8", "X-Hobgoblin-Denied": "1"},
        )
        return True

    def _injected_value(self, inj) -> str:
        secret = self.secrets[inj.secret]
        if inj.basic_user is not None:
            token = base64.b64encode(f"{inj.basic_user}:{secret}".encode()).decode()
            return f"Basic {token}"
        return f"{inj.prefix}{secret}"

    # ------------------------------------------------------------------ hooks

    def client_connected(self, client) -> None:
        """Only the agent's internal network may use the proxy. Without this,
        another container able to route to the proxy's egress address could
        borrow its credential injection."""
        if not self.client_cidrs:
            return
        try:
            ip = netguard._canonical(ipaddress.ip_address(client.peername[0].split("%", 1)[0]))
        except (ValueError, TypeError, IndexError):
            client.error = "hobgoblin: unknown client address"
            return
        if not any(ip.version == n.version and ip in n for n in self.client_cidrs):
            client.error = "hobgoblin: client not on the session network"
            self._audit("client", "deny", client=str(ip), reason="client not on the session network")

    def client_disconnected(self, client) -> None:
        self.tunnels.pop(client.id, None)

    def http_connect(self, flow: http.HTTPFlow) -> None:
        assert self.policy is not None
        raw_host, port = flow.request.host, flow.request.port
        if flow.client_conn.id in self.tunnels:
            # A CONNECT inside an existing tunnel (nested CONNECT, or HTTP/2
            # extended CONNECT) would replace this connection's tunnel state.
            reason = "CONNECT inside an existing tunnel"
            self._audit("connect", "deny", host=raw_host, port=port, reason=reason)
            flow.response = http.Response.make(
                403,
                f"hobgoblin: blocked by egress policy: {reason}\n".encode(),
                {"Content-Type": "text/plain; charset=utf-8", "X-Hobgoblin-Denied": "1"},
            )
            return
        host = normalize_host(raw_host)
        rule = self.policy.match(host, port) if host else None
        if rule is None:
            reason = f"{raw_host}:{port} is not allowed by policy"
            if self.policy.audit_only and host:
                self._audit("connect", "would_deny", host=host, port=port, reason=reason)
                self.tunnels[flow.client_conn.id] = Tunnel(host, port, None)
                return
            self._audit("connect", "deny", host=raw_host, port=port, reason=reason)
            flow.response = http.Response.make(
                403,
                f"hobgoblin: blocked by egress policy: {reason}\n".encode(),
                {"Content-Type": "text/plain; charset=utf-8", "X-Hobgoblin-Denied": "1"},
            )
            return
        self.tunnels[flow.client_conn.id] = Tunnel(host, port, rule)
        self._audit("connect", "allow", host=host, port=port, action=rule.action, rule=rule.index + 1)

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        assert self.policy is not None
        client = data.context.client
        t = self.tunnels.get(client.id)
        if t is None:
            # TLS that did not arrive through CONNECT (e.g. TLS to the proxy itself).
            self.tunnels[client.id] = Tunnel("", 0, None, doomed="TLS without CONNECT")
            data.ignore_connection = True
            self._audit("tls", "deny", reason="TLS without CONNECT")
            return

        sni = normalize_host(data.client_hello.sni or "")
        ech = any(ext == ECH_EXTENSION for ext, _ in data.client_hello.extensions)
        problem = None
        if t.rule is not None and t.rule.action == "tcp":
            problem = None  # tcp rules are opaque by design
        elif ech and not self.policy.allow_ech:
            problem = "TLS Encrypted Client Hello hides the real destination"
        elif not sni:
            problem = "TLS ClientHello without SNI"
        elif sni != t.host:
            problem = f"SNI {sni} does not match CONNECT host {t.host}"

        if problem:
            if self.policy.audit_only:
                self._audit("tls", "would_deny", host=t.host, sni=sni, reason=problem)
                data.ignore_connection = True
                return
            t.doomed = problem
            data.ignore_connection = True  # server_connect will refuse to open upstream
            self._audit("tls", "deny", host=t.host, port=t.port, sni=sni, reason=problem)
            return

        if t.rule is None or t.rule.action in ("tunnel", "tcp"):
            data.ignore_connection = True
            self._audit("tls", "allow", host=t.host, port=t.port, mode="passthrough")
        else:
            self._audit("tls", "allow", host=t.host, port=t.port, mode="inspect")

    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        assert self.policy is not None
        t = self.tunnels.get(flow.client_conn.id)
        if t is not None and t.rule is not None and t.rule.action == "tcp":
            return
        reason = "raw TCP stream to a host without a tcp rule"
        if self.policy.audit_only:
            self._audit("tcp", "would_deny", host=t.host if t else None, reason=reason)
            return
        self._audit("tcp", "deny", host=t.host if t else None, reason=reason)
        flow.kill()

    def request(self, flow: http.HTTPFlow) -> None:
        assert self.policy is not None
        req = flow.request
        if req.method == "CONNECT":
            return
        host = normalize_host(req.host)
        port = req.port
        t = self.tunnels.get(flow.client_conn.id)
        path = req.path
        path_only = path.split("?", 1)[0]
        fields = dict(host=host or req.host, port=port, method=req.method, path=path[:MAX_LOGGED_PATH])

        for h in ("Proxy-Authorization", "Proxy-Connection"):
            req.headers.pop(h, None)

        if t is not None:
            if t.doomed:
                self._deny(flow, 403, t.doomed, **fields)
                return
            if host != t.host or port != t.port:
                self._deny(flow, 421, f"request for {req.host}:{port} inside tunnel to {t.host}:{t.port}", **fields)
                return
            rule = t.rule
        else:
            rule = self.policy.match(host, port) if host else None
            if rule is None:
                self._deny(flow, 403, f"{req.host}:{port} is not allowed by policy", **fields)
                return

        host_header = normalize_host(_strip_port(req.host_header or ""))
        if host_header != host:
            # A mismatched Host lets a CDN route the request somewhere else
            # (domain fronting). Refuse rather than rewrite.
            if self._deny(flow, 421, f"Host header {req.host_header!r} does not match {host}", **fields):
                return

        if rule is None:  # audit mode, unlisted host
            self._audit("request", "would_deny", reason="no rule for host", **fields)
            return

        if "upgrade" in req.headers and not rule.websocket:
            if self._deny(flow, 403, f"protocol upgrade ({req.headers['upgrade']}) not enabled for {rule.host}", **fields):
                return

        ok, why = rule.permits_request(req.method, path_only)
        if not ok:
            if self._deny(flow, 403, why, **fields):
                return

        injected: list[str] = []
        if rule.inject:
            if req.scheme == "https":
                for inj in rule.inject:
                    value = self._injected_value(inj)
                    req.headers[inj.header] = value  # replaces any agent-supplied value
                    injected.append(value)
                    injected.append(self.secrets[inj.secret])
                flow.metadata["hobgoblin_secrets"] = injected
            else:
                self._audit("request", "info", reason="credentials not injected over plaintext HTTP", **fields)

        self._audit(
            "request",
            "allow",
            rule=rule.index + 1,
            injected=[i.header for i in rule.inject] if injected else None,
            **fields,
        )

    def response(self, flow: http.HTTPFlow) -> None:
        secrets: list[str] = flow.metadata.get("hobgoblin_secrets") or []
        if not secrets or flow.response is None:
            return
        needles = [s.encode() for s in sorted(set(secrets), key=len, reverse=True) if len(s) >= 8]
        hit = False
        fields = []
        for name, value in flow.response.headers.fields:
            for n in needles:
                if n in value:
                    value = value.replace(n, REDACTED)
                    hit = True
            fields.append((name, value))
        if hit:
            flow.response.headers.fields = tuple(fields)
        body = flow.response.raw_content  # None when streamed
        if body is not None and flow.response.content is not None:
            content = flow.response.content
            if any(n in content for n in needles):
                for n in needles:
                    content = content.replace(n, REDACTED)
                flow.response.content = content
                hit = True
        if hit:
            self._audit(
                "response",
                "redacted",
                host=flow.request.host,
                path=flow.request.path[:MAX_LOGGED_PATH],
                reason="upstream echoed an injected credential",
            )

    async def server_connect(self, data: server_hooks.ServerConnectionHookData) -> None:
        assert self.policy is not None
        if data.server.address is None:
            return
        raw_host, port = data.server.address
        host = normalize_host(str(raw_host))
        t = self.tunnels.get(data.client.id)
        if t is not None:
            if t.doomed:
                data.server.error = f"hobgoblin: {t.doomed}"
                return
            if host != t.host or port != t.port:
                reason = f"upstream {raw_host}:{port} differs from CONNECT target {t.host}:{t.port}"
                self._audit("upstream", "deny", host=str(raw_host), port=port, reason=reason)
                data.server.error = f"hobgoblin: {reason}"
                return
        elif not self.policy.audit_only and (host is None or self.policy.match(host, port) is None):
            reason = f"{raw_host}:{port} is not allowed by policy"
            self._audit("upstream", "deny", host=str(raw_host), port=port, reason=reason)
            data.server.error = f"hobgoblin: {reason}"
            return
        if host is None:
            data.server.error = "hobgoblin: invalid upstream host"
            return

        # Network guard: enforced in every mode.
        try:
            if is_ip_literal(host):
                ips = [host]
            else:
                infos = await asyncio.wait_for(
                    asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM),
                    timeout=10,
                )
                ips = [str(ipaddress.ip_address(i[4][0].split("%", 1)[0])) for i in infos]
        except (OSError, asyncio.TimeoutError, ValueError) as e:
            reason = f"cannot resolve {host}: {e}"
            self._audit("upstream", "deny", host=host, port=port, reason=reason)
            data.server.error = f"hobgoblin: {reason}"
            return

        ip, why = netguard.check_all(ips, self.allow_cidrs, self.deny_cidrs)
        if ip is None:
            self._audit("upstream", "deny", host=host, port=port, reason=why, resolved=ips)
            data.server.error = f"hobgoblin: {host} blocked: {why}"
            return

        self.pins[data.server.id] = (str(raw_host), port, ip)
        data.server.address = (ip, port)

    def server_connected(self, data: server_hooks.ServerConnectionHookData) -> None:
        pin = self.pins.pop(data.server.id, None)
        if pin is None:
            return
        host, port, ip = pin
        peer = data.server.peername[0] if data.server.peername else None
        if peer is not None and str(netguard._canonical(ipaddress.ip_address(peer.split("%", 1)[0]))) != str(
            netguard._canonical(ipaddress.ip_address(ip))
        ):
            # Should be impossible: we connected to a literal. Log loudly.
            self._audit("upstream", "error", host=host, reason=f"peer {peer} != pinned {ip}")
        self._audit("upstream", "allow", host=host, port=port, ip=ip)
        # Put the name back so mitmproxy can reuse this connection for later
        # requests to the same host (it matches connections by address). The
        # socket is already connected to the checked IP; this only changes
        # the label. Server.__setattr__ forbids changing address on an open
        # connection, so bypass it. If that ever fails, we just lose reuse.
        try:
            object.__setattr__(data.server, "address", (host, port))
        except Exception as e:  # pragma: no cover
            log.debug("hobgoblin: could not restore server address: %s", e)

    def server_connect_error(self, data: server_hooks.ServerConnectionHookData) -> None:
        self.pins.pop(data.server.id, None)

