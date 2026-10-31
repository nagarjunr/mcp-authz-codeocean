"""
policy_signing.py -- integrity protection for the policy document itself.

Per STRESS_TEST.md section 2.2: "Policy document integrity is not addressed... an
attacker (or a misbehaving agent with any filesystem-adjacent capability) can edit it to
escalate privileges directly, bypassing the entire credential/token layer." This module
closes that gap by signing the policy file with the same root CA used for agent
certificates (ca/ca.py), and verifying that signature at load time.

Design choice: detached signature (a separate .sig file next to the policy YAML), not an
embedded signature inside the YAML itself. This keeps the policy document human-readable
and diffable (an operator can `cat policy.yaml` and understand it directly) while still
being tamper-evident -- the signature file's presence and validity is checked
independently of parsing the policy content.

This is a detection control at load time (a tampered policy simply fails to load, fail-
closed), not a prevention control against someone with filesystem write access -- see
STRESS_TEST.md's explicit framing: "either (a) the policy document itself
signed/hash-chained ... or (b) explicit statement that filesystem access control (OS
permissions) is assumed and out of scope." This module implements (a); OS-level
permissions on the policy+signature files remain a deployment-time operational concern,
explicitly out of scope for this code (same boundary as the CA's private key file).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ca.ca import CertificateError, RootCA


class PolicySignatureError(Exception):
    """Raised when a policy document's signature is missing, malformed, or does not
    verify against the trusted root CA. Callers MUST treat this as fail-closed --
    refuse to load the policy at all, do not fall back to an unsigned/default policy."""


@dataclass
class SignedPolicyFile:
    policy_path: Path
    signature_path: Path


def signature_path_for(policy_path: str | Path) -> Path:
    """The convention: a policy file `foo.yaml` is signed by a detached signature file
    `foo.yaml.sig` in the same directory."""
    return Path(str(policy_path) + ".sig")


def sign_policy_file(ca: RootCA, policy_path: str | Path) -> Path:
    """Sign a policy document's raw bytes with the root CA's private key, writing a
    detached signature file alongside it. Intended to be run by an operator/technician
    at policy-authoring time (locally, at the site -- never requires network
    reachability, consistent with the control-plane-optional design).
    """
    policy_path = Path(policy_path)
    raw_bytes = policy_path.read_bytes()

    signature = ca.private_key.sign(raw_bytes)

    sig_path = signature_path_for(policy_path)
    sig_path.write_bytes(signature)
    return sig_path


def verify_policy_signature(ca: RootCA, policy_path: str | Path) -> None:
    """Verify that the policy file at policy_path has a valid detached signature from
    the given root CA. Raises PolicySignatureError on any failure -- missing signature
    file, malformed signature, or a signature that does not verify (which is exactly
    what happens if the policy file's content was modified after signing, since Ed25519
    signatures are over the exact byte content).

    This function does NOT parse or validate the policy's semantic content (schema,
    roles, etc.) -- that remains policy_engine.policy.load_policy()'s job. Callers
    (e.g. a server's startup sequence) MUST call this function and let it succeed
    BEFORE calling load_policy(), so that a tampered-but-still-valid-YAML policy is
    rejected before any of its rules are even parsed, let alone applied.
    """
    policy_path = Path(policy_path)
    sig_path = signature_path_for(policy_path)

    try:
        raw_bytes = policy_path.read_bytes()
    except OSError as e:
        raise PolicySignatureError(f"cannot read policy file {policy_path}: {e}") from e

    try:
        signature = sig_path.read_bytes()
    except OSError as e:
        raise PolicySignatureError(
            f"no signature file found at {sig_path} -- refusing to load an unsigned "
            "policy document"
        ) from e

    root_public_key = ca.certificate.public_key()
    if not isinstance(root_public_key, Ed25519PublicKey):
        raise PolicySignatureError("root CA public key is not Ed25519 -- cannot verify policy signature")

    try:
        root_public_key.verify(signature, raw_bytes)
    except Exception as e:  # cryptography raises InvalidSignature, a bare Exception subclass
        raise PolicySignatureError(
            f"policy file {policy_path} failed signature verification -- it may have "
            f"been tampered with since it was signed: {e}"
        ) from e


def load_and_verify_policy(ca: RootCA, policy_path: str | Path):
    """Convenience wrapper: verify the policy's signature, THEN load and validate its
    content. This is the function server startup code should actually call -- it
    enforces the correct order (signature check strictly before semantic parsing) so
    that call sites can't accidentally skip the integrity check.

    Returns a policy_engine.policy.Policy object, same as load_policy() -- imported
    lazily inside the function body to avoid a circular import between policy.py and
    this module (policy.py doesn't need to know about signing; this module depends on
    both policy.py and ca.py).
    """
    from policy_engine.policy import load_policy  # local import: see docstring

    verify_policy_signature(ca, policy_path)  # raises PolicySignatureError, fail-closed
    return load_policy(policy_path)  # raises PolicyLoadError, also fail-closed
