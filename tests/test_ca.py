"""The session CA must be unable to vouch for anything outside the inspect
hosts. Verified with the real OpenSSL CLI, not just our own reading."""

import datetime
import shutil
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from hobgoblin import ca

openssl = shutil.which("openssl")


def leaf(ca_key, ca_cert, *names, ip=None):
    key = ec.generate_private_key(ec.SECP256R1())
    sans = [x509.DNSName(n) for n in names]
    if ip:
        import ipaddress

        sans.append(x509.IPAddress(ipaddress.ip_address(ip)))
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0] if names else "ip")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(ca_key, hashes.SHA256())
    )


def verify(tmp_path, ca_cert, cert) -> bool:
    (tmp_path / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "leaf.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    r = subprocess.run(
        [openssl, "verify", "-CAfile", tmp_path / "ca.pem", tmp_path / "leaf.pem"],
        capture_output=True,
        text=True,
    )
    return r.returncode == 0


@pytest.mark.skipif(not openssl, reason="openssl CLI not installed")
def test_name_constraints_enforced_by_openssl(tmp_path):
    key, cert = ca.make_ca(["api.github.com", "*.example.org"], "t")
    assert verify(tmp_path, cert, leaf(key, cert, "api.github.com"))
    assert verify(tmp_path, cert, leaf(key, cert, "x.example.org"))
    assert not verify(tmp_path, cert, leaf(key, cert, "github.com"))
    assert not verify(tmp_path, cert, leaf(key, cert, "accounts.google.com"))
    assert not verify(tmp_path, cert, leaf(key, cert, "api.github.com", "evil.com"))
    assert not verify(tmp_path, cert, leaf(key, cert, "api.github.com", ip="140.82.112.3"))


@pytest.mark.skipif(not openssl, reason="openssl CLI not installed")
def test_no_inspect_hosts_means_ca_signs_nothing(tmp_path):
    key, cert = ca.make_ca([], "t")
    assert not verify(tmp_path, cert, leaf(key, cert, "github.com"))
    assert ca.constraint_names([]) == [ca.NOTHING]


def test_write_session_ca(tmp_path):
    out = ca.write_session_ca(tmp_path / "conf", tmp_path / "pub", ["api.github.com"], "s1")
    assert (out["ca_store"].stat().st_mode & 0o777) == 0o600
    store = out["ca_store"].read_bytes()
    assert b"PRIVATE KEY" in store
    assert b"PRIVATE KEY" not in out["bundle"].read_bytes()
    assert b"PRIVATE KEY" not in out["ca"].read_bytes()
    assert out["bundle"].read_bytes().count(b"BEGIN CERTIFICATE") > 10  # system roots + session CA
    assert not list((tmp_path / "pub").glob("*.tmp"))


def test_write_session_ca_without_inspect_does_not_trust_session_ca(tmp_path):
    out = ca.write_session_ca(tmp_path / "conf", tmp_path / "pub", [], "s1")
    store_cert = out["ca_store"].read_bytes().split(b"-----END RSA PRIVATE KEY-----")[1].strip()
    assert store_cert not in out["bundle"].read_bytes()
    assert out["ca"].read_bytes() == b""
