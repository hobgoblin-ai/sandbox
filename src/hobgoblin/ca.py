"""Per-session interception CA.

Generated inside the proxy container on every start and written only to the
container's tmpfs (mitmproxy reads it from its confdir). The agent receives
the certificate, never the key.

The CA carries a critical NameConstraints extension: it can only vouch for
the hosts that have `action = "inspect"` rules, and never for IP addresses.
If the key leaked, it still could not be used to impersonate anything else
to clients that enforce name constraints (OpenSSL, Go, NSS, rustls, ...).
"""

from __future__ import annotations

import datetime
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# A name nothing can legitimately have (RFC 2606). Used when the policy has
# no inspect rules, so the CA can sign nothing useful.
NOTHING = "hobgoblin.invalid"

SYSTEM_BUNDLES = (
    "/etc/pki/tls/certs/ca-bundle.crt",  # Fedora/RHEL/UBI
    "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu/Alpine
    "/etc/ssl/cert.pem",
)


def constraint_names(inspect_hosts: list[str]) -> list[str]:
    """`api.github.com` -> `api.github.com` (covers it and its subdomains, per
    RFC 5280). `*.example.com` -> `example.com`."""
    names: list[str] = []
    for h in inspect_hosts:
        name = h[2:] if h.startswith("*.") else h
        if name not in names:
            names.append(name)
    return names or [NOTHING]


def make_ca(inspect_hosts: list[str], session: str, days: int = 2):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "hobgoblin"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"hobgoblin session CA {session}"),
        ]
    )
    constraints = x509.NameConstraints(
        permitted_subtrees=[x509.DNSName(n) for n in constraint_names(inspect_hosts)],
        excluded_subtrees=[
            x509.IPAddress(ipaddress.ip_network("0.0.0.0/0")),
            x509.IPAddress(ipaddress.ip_network("::/0")),
        ],
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(constraints, critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def system_bundle_path() -> Path | None:
    env = os.environ.get("SSL_CERT_FILE")
    if env and Path(env).is_file():
        return Path(env)
    for p in SYSTEM_BUNDLES:
        if Path(p).is_file():
            return Path(p)
    try:
        import certifi

        return Path(certifi.where())
    except ImportError:
        return None


def write_session_ca(
    confdir: Path,
    out_dir: Path,
    inspect_hosts: list[str],
    session: str,
) -> dict[str, Path]:
    """Write `mitmproxy-ca.pem` (key+cert, 0600) into confdir, and the public
    files the agent needs into out_dir:

      ca.pem         - session CA certificate only (NODE_EXTRA_CA_CERTS)
      ca-bundle.pem  - system roots + session CA (SSL_CERT_FILE and friends)
    """
    confdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    out_dir.mkdir(parents=True, exist_ok=True)
    key, cert = make_ca(inspect_hosts, session)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    ca_store = confdir / "mitmproxy-ca.pem"
    fd = os.open(ca_store, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key_pem + cert_pem)

    roots = system_bundle_path()
    if roots is None:
        raise RuntimeError("no system CA bundle found; cannot build ca-bundle.pem")
    bundle = roots.read_bytes().rstrip(b"\n") + b"\n"
    if inspect_hosts:
        bundle += cert_pem

    # Write-then-rename so the launcher never sees a partial bundle.
    paths = {"ca": out_dir / "ca.pem", "bundle": out_dir / "ca-bundle.pem"}
    for kind, data in (("ca", cert_pem if inspect_hosts else b""), ("bundle", bundle)):
        tmp = paths[kind].with_suffix(".tmp")
        tmp.write_bytes(data)
        os.chmod(tmp, 0o644)
        tmp.rename(paths[kind])
    return {"ca_store": ca_store, **paths}
