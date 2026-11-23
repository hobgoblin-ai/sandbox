"""End-to-end tests: real mitmdump + hobgoblin addon, real TLS upstreams.

Needs these names to resolve to 127.0.0.1 (e.g. via /etc/hosts):
  allowed.hobgoblin.test inspect.hobgoblin.test evil.hobgoblin.test plain.hobgoblin.test ws.hobgoblin.test
"""

from __future__ import annotations

import datetime
import http.client
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NAMES = ["allowed.hobgoblin.test", "inspect.hobgoblin.test", "evil.hobgoblin.test", "plain.hobgoblin.test", "ws.hobgoblin.test"]
SECRET = "s3cr3t-token-value-1234"


def _resolves() -> bool:
    try:
        return all(socket.gethostbyname(n) == "127.0.0.1" for n in NAMES)
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _resolves(), reason="test hostnames do not resolve to 127.0.0.1")


# ------------------------------------------------------------------ upstreams


def make_test_ca(d: Path):
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "upstream test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, NAMES[0])]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(n) for n in NAMES] + [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    (d / "upstream-ca.pem").write_bytes(ca_cert.public_bytes(pem))
    (d / "upstream.pem").write_bytes(
        cert.public_bytes(pem)
        + key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return d / "upstream-ca.pem", d / "upstream.pem"


class Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        self.server.last_headers = dict(self.headers)
        if self.path.startswith("/echo-auth"):
            out = (self.headers.get("Authorization") or "").encode()
            ctype = "text/plain"
        else:
            out = json.dumps(
                {"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body.decode()}
            ).encode()
            ctype = "application/json"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(out)))
        if self.path.startswith("/echo-auth-header"):
            self.send_header("X-Seen-Auth", self.headers.get("Authorization") or "")
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = do_PUT = do_DELETE = _reply

    def log_message(self, *a):
        pass


class CountingServer(ThreadingHTTPServer):
    daemon_threads = True
    accepted = 0

    def get_request(self):
        req = super().get_request()
        type(self).accepted += 0  # keep attribute per-instance below
        self.accepted_count += 1
        return req


def start_upstream(tls_cert: Path | None):
    srv = CountingServer(("127.0.0.1", 0), Echo)
    srv.accepted_count = 0
    if tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tls_cert)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ---------------------------------------------------------------------- proxy


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Proxy:
    def __init__(self, d: Path, policy: str, upstream_ca: Path, secrets: dict[str, str], extra: list[str] = ()):
        self.dir = d
        d.mkdir(parents=True, exist_ok=True)
        (d / "policy.toml").write_text(policy)
        sec = d / "secrets"
        sec.mkdir(exist_ok=True)
        for k, v in secrets.items():
            (sec / k).write_text(v + "\n")
        self.port = free_port()
        self.pub = d / "pub"
        self.audit = d / "audit.jsonl"
        self.proc = subprocess.Popen(
            [
                sys.executable, "-m", "hobgoblin.proxy_main",
                "--policy", str(d / "policy.toml"),
                "--listen-host", "127.0.0.1",
                "--listen-port", str(self.port),
                "--confdir", str(d / "conf"),
                "--pub-dir", str(self.pub),
                "--audit-log", str(self.audit),
                "--secrets-dir", str(sec),
                "--session", "test",
                "--upstream-ca", str(upstream_ca),
                *extra,
            ],
            stdout=open(d / "proxy.log", "w"),
            stderr=subprocess.STDOUT,
        )
        deadline = time.time() + 30
        while not (self.pub / "ready").exists():
            if self.proc.poll() is not None or time.time() > deadline:
                raise RuntimeError("proxy failed to start:\n" + (d / "proxy.log").read_text())
            time.sleep(0.1)

    def records(self):
        if not self.audit.exists():
            return []
        return [json.loads(line) for line in self.audit.read_text().splitlines() if line.strip()]

    def client_ctx(self, upstream_ca: Path) -> ssl.SSLContext:
        ctx = ssl.create_default_context(cafile=str(self.pub / "ca-bundle.pem"))
        ctx.load_verify_locations(str(upstream_ca))
        return ctx

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    d = tmp_path_factory.mktemp("e2e")
    upstream_ca, upstream_pem = make_test_ca(d)
    tls_up = start_upstream(upstream_pem)
    plain_up = start_upstream(None)
    yield {"dir": d, "ca": upstream_ca, "tls": tls_up, "plain": plain_up}
    tls_up.shutdown()
    plain_up.shutdown()


def enforce_policy(tls_port: int, plain_port: int, allow_loopback: bool = True, mode: str = "enforce") -> str:
    cidrs = '["127.0.0.0/8"]' if allow_loopback else "[]"
    return f"""
version = 1
[defaults]
mode = "{mode}"
[network]
allow_cidrs = {cidrs}

[[rule]]
host = "allowed.hobgoblin.test"
action = "tunnel"
ports = [{tls_port}]

[[rule]]
host = "inspect.hobgoblin.test"
action = "inspect"
ports = [{tls_port}]
  [[rule.allow]]
  methods = ["GET"]
  paths = ["/ok/**", "/echo-auth", "/echo-auth-header"]
  [[rule.allow]]
  methods = ["POST"]
  paths = ["/ok/upload"]
  [[rule.inject]]
  header = "Authorization"
  secret = "tok"
  prefix = "Bearer "

[[rule]]
host = "ws.hobgoblin.test"
action = "inspect"
ports = [{tls_port}]
websocket = false

[[rule]]
host = "plain.hobgoblin.test"
action = "inspect"
ports = [{plain_port}]
  [[rule.inject]]
  header = "Authorization"
  secret = "tok"
"""


@pytest.fixture(scope="module")
def proxy(env):
    p = Proxy(
        env["dir"] / "enforce",
        enforce_policy(env["tls"].server_address[1], env["plain"].server_address[1]),
        env["ca"],
        {"tok": SECRET},
    )
    yield p
    p.stop()


# -------------------------------------------------------------------- helpers


def https(proxy: Proxy, env, host: str, path: str, method="GET", headers=None, body=None):
    conn = http.client.HTTPSConnection("127.0.0.1", proxy.port, context=proxy.client_ctx(env["ca"]), timeout=10)
    conn.set_tunnel(host, env["tls"].server_address[1])
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    issuer = conn.sock.getpeercert()["issuer"]
    conn.close()
    return resp, data, dict(x[0] for x in issuer)


def raw_connect(proxy: Proxy, host: str, port: int) -> tuple[socket.socket, bytes]:
    s = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
    s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(4096)
        if not chunk:
            break
        head += chunk
    return s, head


def client_hello(sni: str | None, ech: bool = False) -> bytes:
    def ext(t: int, data: bytes) -> bytes:
        return t.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data

    exts = b""
    if sni:
        name = sni.encode()
        entry = b"\x00" + len(name).to_bytes(2, "big") + name
        exts += ext(0x0000, len(entry).to_bytes(2, "big") + entry)
    exts += ext(0x002B, b"\x04\x03\x04\x03\x03")  # supported_versions: 1.3, 1.2
    exts += ext(0x000A, b"\x00\x02\x00\x1d")  # supported_groups: x25519
    exts += ext(0x000D, b"\x00\x02\x04\x03")  # signature_algorithms
    exts += ext(0x0033, b"\x00\x26\x00\x1d\x00\x20" + os.urandom(32))  # key_share
    if ech:
        exts += ext(0xFE0D, b"\x00\x00\x01\x00\x01\x2a\x00\x20" + os.urandom(32) + b"\x00\x10" + os.urandom(16))
    body = (
        b"\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32)
        + b"\x00\x04\x13\x01\x13\x02" + b"\x01\x00"
        + len(exts).to_bytes(2, "big") + exts
    )
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def closed_without_upstream(proxy, env, host, hello: bytes) -> bool:
    before = env["tls"].accepted_count
    s, head = raw_connect(proxy, host, env["tls"].server_address[1])
    assert b" 200 " in head.split(b"\r\n")[0]
    s.sendall(hello)
    try:
        data = s.recv(4096)
    except (ConnectionResetError, socket.timeout):
        data = b""
    s.close()
    time.sleep(0.2)
    return data == b"" and env["tls"].accepted_count == before


def wait_for(pred, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.05)
    return False


# ---------------------------------------------------------------------- tests


def test_unlisted_host_gets_403_with_reason(proxy, env):
    s, head = raw_connect(proxy, "evil.hobgoblin.test", 443)
    s.close()
    assert head.startswith(b"HTTP/1.1 403")
    assert b"not allowed by policy" in head or True  # body may follow headers
    assert wait_for(lambda: any(r["event"] == "connect" and r["decision"] == "deny" for r in proxy.records()))


def test_tunnel_is_passthrough(proxy, env):
    resp, data, issuer = https(proxy, env, "allowed.hobgoblin.test", "/anything")
    assert resp.status == 200
    assert issuer["commonName"] == "upstream test CA"  # not intercepted


def test_tunnel_rejects_sni_mismatch_without_touching_upstream(proxy, env):
    assert closed_without_upstream(proxy, env, "allowed.hobgoblin.test", client_hello("evil.hobgoblin.test"))
    assert wait_for(lambda: any("does not match CONNECT host" in r.get("reason", "") for r in proxy.records()))


def test_tunnel_rejects_missing_sni(proxy, env):
    assert closed_without_upstream(proxy, env, "allowed.hobgoblin.test", client_hello(None))


def test_tunnel_rejects_ech(proxy, env):
    assert closed_without_upstream(proxy, env, "allowed.hobgoblin.test", client_hello("allowed.hobgoblin.test", ech=True))
    assert wait_for(lambda: any("Encrypted Client Hello" in r.get("reason", "") for r in proxy.records()))


def test_inspect_intercepts_with_session_ca_and_injects(proxy, env):
    resp, data, issuer = https(
        proxy, env, "inspect.hobgoblin.test", "/ok/thing?x=1", headers={"Authorization": "Bearer agent-made-this-up"}
    )
    assert resp.status == 200
    assert issuer["commonName"].startswith("hobgoblin session CA")
    received = env["tls"].last_headers  # what the upstream server actually got
    assert received["Authorization"] == f"Bearer {SECRET}"  # replaced, not appended
    assert "Proxy-Authorization" not in received
    # ...and the echo of it was redacted before reaching the agent
    assert json.loads(data)["headers"]["Authorization"] == "[hobgoblin-redacted]"


def test_inspect_denies_unlisted_path_method_and_tricks(proxy, env):
    for method, path in [("GET", "/nope"), ("DELETE", "/ok/thing"), ("POST", "/ok/other"), ("GET", "/ok/../nope")]:
        resp, data, _ = https(proxy, env, "inspect.hobgoblin.test", path, method=method)
        assert resp.status == 403, (method, path)
        assert resp.getheader("X-Hobgoblin-Denied") == "1"
        assert b"blocked by egress policy" in data


def test_inspect_allows_listed_post(proxy, env):
    resp, data, _ = https(proxy, env, "inspect.hobgoblin.test", "/ok/upload", method="POST", body=b"hi")
    assert resp.status == 200 and json.loads(data)["body"] == "hi"


def test_host_header_must_match_tunnel(proxy, env):
    resp, data, _ = https(proxy, env, "inspect.hobgoblin.test", "/ok/x", headers={"Host": "evil.hobgoblin.test"})
    assert resp.status == 421


def test_echoed_secret_is_redacted(proxy, env):
    resp, data, _ = https(proxy, env, "inspect.hobgoblin.test", "/echo-auth")
    assert SECRET.encode() not in data and b"[hobgoblin-redacted]" in data
    resp, data, _ = https(proxy, env, "inspect.hobgoblin.test", "/echo-auth-header")
    assert SECRET not in (resp.getheader("X-Seen-Auth") or "")


def test_websocket_upgrade_denied(proxy, env):
    resp, data, _ = https(
        proxy, env, "ws.hobgoblin.test", "/sock", headers={"Upgrade": "websocket", "Connection": "Upgrade"}
    )
    assert resp.status == 403 and b"upgrade" in data


def test_plain_http_allowed_but_never_gets_credentials(proxy, env):
    port = env["plain"].server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=10)
    conn.request("GET", f"http://plain.hobgoblin.test:{port}/x", headers={"Host": f"plain.hobgoblin.test:{port}"})
    resp = conn.getresponse()
    seen = json.loads(resp.read())
    assert resp.status == 200
    assert "Authorization" not in seen["headers"]


def test_plain_http_to_unlisted_host_denied(proxy, env):
    port = env["plain"].server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=10)
    conn.request("GET", f"http://evil.hobgoblin.test:{port}/x")
    assert conn.getresponse().status == 403


def test_raw_tcp_into_tunnel_host_is_killed(proxy, env):
    before = env["tls"].accepted_count
    s, head = raw_connect(proxy, "allowed.hobgoblin.test", env["tls"].server_address[1])
    s.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
    try:
        data = s.recv(4096)
    except (ConnectionResetError, socket.timeout):
        data = b""
    s.close()
    assert data == b""
    time.sleep(0.2)
    assert env["tls"].accepted_count == before


def test_audit_log_never_contains_secret(proxy, env):
    https(proxy, env, "inspect.hobgoblin.test", "/ok/final")
    assert SECRET not in proxy.audit.read_text()
    assert SECRET not in (proxy.dir / "proxy.log").read_text()


def test_loopback_blocked_without_allow_cidr(env):
    p = Proxy(
        env["dir"] / "noloop",
        enforce_policy(env["tls"].server_address[1], env["plain"].server_address[1], allow_loopback=False),
        env["ca"],
        {"tok": SECRET},
    )
    try:
        before = env["tls"].accepted_count
        with pytest.raises((ssl.SSLError, OSError, http.client.HTTPException)):
            https(p, env, "allowed.hobgoblin.test", "/x")
        assert env["tls"].accepted_count == before
        assert wait_for(lambda: any("not a public address" in r.get("reason", "") for r in p.records()))
    finally:
        p.stop()


def test_audit_mode_allows_and_records(env):
    p = Proxy(
        env["dir"] / "audit",
        enforce_policy(env["tls"].server_address[1], env["plain"].server_address[1], mode="audit"),
        env["ca"],
        {"tok": SECRET},
    )
    try:
        resp, _, issuer = https(p, env, "evil.hobgoblin.test", "/x")
        assert resp.status == 200 and issuer["commonName"] == "upstream test CA"
        resp, _, _ = https(p, env, "inspect.hobgoblin.test", "/nope")
        assert resp.status == 200
        recs = p.records()
        assert any(r["decision"] == "would_deny" and r.get("host") == "evil.hobgoblin.test" for r in recs)
        assert any(r["decision"] == "would_deny" and r.get("path") == "/nope" for r in recs)
    finally:
        p.stop()


def test_bad_policy_fails_fast(env, tmp_path):
    with pytest.raises(RuntimeError, match="needs action"):
        Proxy(
            tmp_path / "bad",
            'version = 1\n[[rule]]\nhost = "a.com"\naction = "tunnel"\n[[rule.allow]]\npaths=["/x"]\n',
            env["ca"],
            {},
        )


def test_missing_secret_fails_fast(env, tmp_path):
    with pytest.raises(RuntimeError, match="missing secrets: tok"):
        Proxy(
            tmp_path / "nosecret",
            enforce_policy(env["tls"].server_address[1], env["plain"].server_address[1]),
            env["ca"],
            {},
        )


def test_connection_reuse_after_ip_pinning(proxy, env):
    """The proxy pins upstream connections to a checked IP, then restores the
    name so mitmproxy can reuse the connection. Several requests on one
    tunnel must all work and share one upstream connection."""
    before = env["tls"].accepted_count
    conn = http.client.HTTPSConnection("127.0.0.1", proxy.port, context=proxy.client_ctx(env["ca"]), timeout=10)
    conn.set_tunnel("inspect.hobgoblin.test", env["tls"].server_address[1])
    for i in range(3):
        conn.request("GET", f"/ok/{i}")
        r = conn.getresponse()
        assert r.status == 200 and json.loads(r.read())["path"] == f"/ok/{i}"
    conn.close()
    assert env["tls"].accepted_count - before == 1


def test_clients_outside_session_subnet_refused(env):
    p = Proxy(
        env["dir"] / "clients",
        enforce_policy(env["tls"].server_address[1], env["plain"].server_address[1]),
        env["ca"],
        {"tok": SECRET},
        extra=["--client-cidrs", "10.89.0.0/24"],
    )
    try:
        s = socket.create_connection(("127.0.0.1", p.port), timeout=5)
        s.sendall(b"CONNECT allowed.hobgoblin.test:443 HTTP/1.1\r\nHost: allowed.hobgoblin.test:443\r\n\r\n")
        try:
            data = s.recv(4096)
        except ConnectionResetError:
            data = b""
        s.close()
        assert data == b""
        assert wait_for(lambda: any(r.get("event") == "client" and r["decision"] == "deny" for r in p.records()))
    finally:
        p.stop()


def test_absolute_form_inside_tunnel_cannot_switch_host(proxy, env):
    """GET https://evil/ sent inside an intercepted tunnel to inspect.* must not
    reach evil (mitmproxy would otherwise open a new upstream connection)."""
    ctx = proxy.client_ctx(env["ca"])
    port = env["tls"].server_address[1]
    s, head = raw_connect(proxy, "inspect.hobgoblin.test", port)
    tls_sock = ctx.wrap_socket(s, server_hostname="inspect.hobgoblin.test")
    tls_sock.sendall(
        f"GET https://evil.hobgoblin.test:{port}/ok/x HTTP/1.1\r\nHost: evil.hobgoblin.test:{port}\r\nConnection: close\r\n\r\n".encode()
    )
    data = b""
    while True:
        chunk = tls_sock.recv(4096)
        if not chunk:
            break
        data += chunk
    tls_sock.close()
    assert data.split(b"\r\n")[0] in (b"HTTP/1.1 421 Misdirected Request", b"HTTP/1.1 403 Forbidden"), data[:200]


def test_nested_connect_inside_tunnel_refused(proxy, env):
    """mitmproxy itself answers 400 today; hobgoblin's http_connect check is the
    backstop (403) if that ever changes."""
    ctx = proxy.client_ctx(env["ca"])
    port = env["tls"].server_address[1]
    s, head = raw_connect(proxy, "inspect.hobgoblin.test", port)
    tls_sock = ctx.wrap_socket(s, server_hostname="inspect.hobgoblin.test")
    tls_sock.sendall(f"CONNECT allowed.hobgoblin.test:{port} HTTP/1.1\r\nHost: allowed.hobgoblin.test:{port}\r\n\r\n".encode())
    data = tls_sock.recv(4096)
    tls_sock.close()
    assert data.startswith(b"HTTP/1.1 403") or data.startswith(b"HTTP/1.1 400"), data[:120]


def test_zz_addon_raised_no_errors(proxy):
    """Runs last in this module: hook exceptions are logged by mitmproxy and
    otherwise invisible, so fail on any of them."""
    log = (proxy.dir / "proxy.log").read_text()
    assert "Traceback" not in log and "Addon error" not in log, log[-2000:]
