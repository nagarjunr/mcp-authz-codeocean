"""
ca.py -- local, control-plane-optional certificate authority for agent identity.

Per SCOPE.md's revised design (post stress-test): agent identity is established via a
locally-rooted PKI, not shared-secret HMAC tokens. The reasoning (see STRESS_TEST.md
section 3): HMAC means every verifier holds the same secret that was used to sign a
token, so any verifier can also forge one -- a real problem the moment there is more than
one verification point. Ed25519 signature verification costs ~0.05-0.2ms, negligible next
to any realistic middleware overhead, so there's no remaining performance argument for
HMAC in 2026.

This module implements:
  - Root CA generation (once, offline, at site commissioning -- never needs to be
    reachable again afterwards; this is what makes the design "control-plane-optional")
  - Per-agent leaf certificate issuance, binding an agent identity to a role and a
    short validity window (default 8 hours -- see ISSUED_CERT_VALIDITY)
  - Leaf certificate verification against the root, used by the policy enforcement
    middleware to establish "who is calling, and what role were they issued" before
    any policy lookup happens

Deliberately NOT implemented here (see SCOPE.md "explicitly scoped OUT of v1"):
  - Cross-site federation
  - Revocation broadcast / CRL / OCSP-equivalent (there's no live channel to broadcast
    over in a disconnected deployment -- exposure is bounded by the short validity
    window instead; see tests/test_ca.py for the exposure-window measurement)
  - TPM-backed root key sealing (flagged in SCOPE.md as a "where hardware permits"
    enhancement, not a hard v1 requirement -- this module stores the root private key
    as a local file with restrictive permissions, which is the honest, stated v1
    boundary, not a claim of hardware-backed protection)
"""

from __future__ import annotations

import datetime
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import NameOID

# Default leaf certificate validity window. Short by design: since there is no live
# revocation channel, the worst-case exposure of a compromised credential is bounded by
# this TTL, not by however long it takes an administrator to notice and manually
# intervene. See STRESS_TEST.md section 2.1 ("no revocation mechanism... short-lived
# tokens partially mitigate this") and evaluation scenario #8 (revocation-window
# measurement) in SCOPE.md.
ISSUED_CERT_VALIDITY = datetime.timedelta(hours=8)

# Root CA validity is much longer -- it's generated once at commissioning and is meant
# to last the deployment's operational lifetime without needing reissuance (reissuing
# the root would invalidate every previously-issued leaf cert, which is exactly the kind
# of disruptive, connectivity-requiring operation this design tries to avoid).
ROOT_CA_VALIDITY = datetime.timedelta(days=3650)  # 10 years


class CertificateError(Exception):
    """Raised for any CA/certificate operation failure. Callers verifying an agent's
    identity MUST treat any exception here as "identity not established" -> deny,
    consistent with this project's fail-closed design throughout."""


@dataclass
class RootCA:
    """An in-memory representation of a generated or loaded root CA. The private key is
    only ever needed at commissioning time (to sign new leaf certs) -- for day-to-day
    tool-call verification, only root_cert_pem (the public certificate) is needed."""

    private_key: Ed25519PrivateKey
    certificate: x509.Certificate
    site_id: str

    @property
    def cert_pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)


@dataclass
class AgentCertificate:
    """A leaf certificate binding an agent identity to a role, issued by a RootCA."""

    private_key: Ed25519PrivateKey
    certificate: x509.Certificate
    agent_id: str
    role: str

    @property
    def cert_pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    @property
    def private_key_pem(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )


def generate_root_ca(site_id: str) -> RootCA:
    """Generate a new, self-signed root CA. Intended to be run exactly once, offline, at
    site commissioning. The resulting private key never needs to leave the local host
    and the CA never needs network reachability again -- this is the core property that
    makes the design "control-plane-optional" rather than merely "data-plane air-gapped"
    (see SCOPE.md's taxonomy).
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, f"mcp-local-authz-root-ca-{site_id}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, site_id),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + ROOT_CA_VALIDITY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, algorithm=None)  # Ed25519 does not use a separate hash algo
    )

    return RootCA(private_key=private_key, certificate=certificate, site_id=site_id)


def write_private_file(path: str | Path, data: bytes) -> None:
    """Write secret material so it is owner-only (0600) from the moment it exists, safely.

    The data goes to a fresh temp file in the same directory, created exclusively
    (O_EXCL, O_NOFOLLOW, mode 0600), and is then moved into place with os.replace(). This avoids
    the weaknesses of open(O_TRUNC) on the final path: a symlink or hard link planted at `path`
    is replaced rather than followed or truncated, and there is no window in which the key is
    readable by other users or half-written.
    """
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def ensure_private_dir(path: str | Path) -> Path:
    """Create `path` (if needed) as an owner-only (0700) directory and return it.

    Missing parent directories are created 0700 as well. The final component must be a real
    directory (a symlink is refused, not followed), owned by the current user; if it is
    accessible to group or others it is tightened to 0700. The checks and the chmod run on an
    open descriptor, so they cannot be raced. Use this only for directories that hold key
    material.
    """
    path = Path(path)
    missing = []
    probe = path
    while not os.path.lexists(probe) and probe != probe.parent:
        missing.append(probe)
        probe = probe.parent
    for d in reversed(missing):
        try:
            os.mkdir(d, 0o700)
        except FileExistsError:
            pass
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        dir_fd = os.open(path, flags)
    except OSError as e:
        raise CertificateError(f"{path} is not a usable private directory (symlink or not a directory): {e}") from e
    try:
        st = os.fstat(dir_fd)
        if not stat.S_ISDIR(st.st_mode):
            raise CertificateError(f"{path} is not a directory")
        if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
            raise CertificateError(f"{path} is not owned by the current user; refusing to store keys there")
        if stat.S_IMODE(st.st_mode) & 0o077:
            os.fchmod(dir_fd, 0o700)
    finally:
        os.close(dir_fd)
    return path


def save_root_ca(ca: RootCA, directory: str | Path) -> None:
    """Persist a root CA's certificate and private key to disk. The private key file is
    written with owner-only permissions (0600) -- this is the stated, honest v1 boundary:
    filesystem-level protection, not hardware-backed (TPM) protection. See module
    docstring for why TPM sealing is named as future work rather than implemented here.
    """
    directory = Path(directory)
    directory = ensure_private_dir(directory)

    cert_path = directory / "root_ca.crt.pem"
    key_path = directory / "root_ca.key.pem"

    cert_path.write_bytes(ca.cert_pem)

    key_bytes = ca.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    write_private_file(key_path, key_bytes)


def load_root_ca(directory: str | Path, site_id: str) -> RootCA:
    """Load a previously-generated root CA from disk. Raises CertificateError if either
    file is missing or malformed -- callers must treat this as "CA unavailable" and
    fail closed (refuse to issue or verify any certificates), not fall back to an
    unauthenticated mode.
    """
    directory = Path(directory)
    cert_path = directory / "root_ca.crt.pem"
    key_path = directory / "root_ca.key.pem"

    try:
        cert_bytes = cert_path.read_bytes()
        key_bytes = key_path.read_bytes()
    except OSError as e:
        raise CertificateError(f"cannot read root CA files from {directory}: {e}") from e

    try:
        certificate = x509.load_pem_x509_certificate(cert_bytes)
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
    except ValueError as e:
        raise CertificateError(f"root CA files in {directory} are malformed: {e}") from e

    if not isinstance(private_key, Ed25519PrivateKey):
        raise CertificateError("root CA private key is not an Ed25519 key")

    return RootCA(private_key=private_key, certificate=certificate, site_id=site_id)


def issue_agent_certificate(
    ca: RootCA,
    *,
    agent_id: str,
    role: str,
    validity: datetime.timedelta = ISSUED_CERT_VALIDITY,
) -> AgentCertificate:
    """Issue a new leaf certificate for an agent, signed by the given root CA. The role
    is embedded directly in the certificate's Common Name in the form
    "<agent_id>|role=<role>" -- a deliberately simple encoding (no custom X.509
    extension OID registration needed) that keeps verify_agent_certificate() and the
    policy engine's role lookup trivial to audit. See tests/test_ca.py for round-trip
    verification that the embedded role survives issuance and verification correctly.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, f"{agent_id}|role={role}"),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.certificate.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + validity)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca.private_key, algorithm=None)
    )

    return AgentCertificate(
        private_key=private_key, certificate=certificate, agent_id=agent_id, role=role
    )


@dataclass
class VerifiedIdentity:
    agent_id: str
    role: str
    not_valid_after: datetime.datetime


def verify_agent_certificate(
    ca: RootCA,
    agent_cert_pem: bytes,
    *,
    now: datetime.datetime | None = None,
) -> VerifiedIdentity:
    """Verify that a leaf certificate was genuinely signed by the given root CA, has not
    expired, and extract the agent_id/role it was issued for. Raises CertificateError on
    ANY failure (bad signature, expired, malformed PEM, wrong issuer) -- per this
    project's fail-closed design, callers (the FastMCP middleware) must treat any
    exception from this function as "identity not established," never fall back to a
    default role or an unauthenticated allow.
    """
    now = now or datetime.datetime.now(datetime.timezone.utc)

    try:
        leaf_cert = x509.load_pem_x509_certificate(agent_cert_pem)
    except ValueError as e:
        raise CertificateError(f"agent certificate is not valid PEM: {e}") from e

    if leaf_cert.issuer != ca.certificate.subject:
        raise CertificateError("agent certificate was not issued by this root CA (issuer mismatch)")

    root_public_key = ca.certificate.public_key()
    if not isinstance(root_public_key, Ed25519PublicKey):
        raise CertificateError("root CA public key is not Ed25519 -- cannot verify")

    try:
        root_public_key.verify(leaf_cert.signature, leaf_cert.tbs_certificate_bytes)
    except Exception as e:  # cryptography raises InvalidSignature, a bare Exception subclass
        raise CertificateError(f"agent certificate signature verification failed: {e}") from e

    if now < leaf_cert.not_valid_before_utc or now > leaf_cert.not_valid_after_utc:
        raise CertificateError(
            f"agent certificate is not valid at {now.isoformat()} "
            f"(valid window: {leaf_cert.not_valid_before_utc.isoformat()} "
            f"to {leaf_cert.not_valid_after_utc.isoformat()})"
        )

    common_name_attrs = leaf_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not common_name_attrs:
        raise CertificateError("agent certificate has no Common Name to parse identity from")

    cn = str(common_name_attrs[0].value)
    if "|role=" not in cn:
        raise CertificateError(f"agent certificate Common Name {cn!r} is not in the expected format")

    agent_id, _, role = cn.partition("|role=")
    if not agent_id or not role:
        raise CertificateError(f"agent certificate Common Name {cn!r} did not parse to a valid identity")

    return VerifiedIdentity(
        agent_id=agent_id, role=role, not_valid_after=leaf_cert.not_valid_after_utc
    )
