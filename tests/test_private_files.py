"""Owner-only handling of secret files and directories in ca.ca (POSIX permissions)."""
import os
import stat

import pytest

from ca.ca import CertificateError, ensure_private_dir, generate_root_ca, save_root_ca, write_private_file, write_public_file

pytestmark = pytest.mark.skipif(not hasattr(os, "fchmod"), reason="POSIX permissions required")


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_write_private_file_is_owner_only(tmp_path):
    f = tmp_path / "k.pem"
    write_private_file(f, b"secret")
    assert f.read_bytes() == b"secret"
    assert _mode(f) == 0o600


def test_overwrite_tightens_an_existing_loose_file(tmp_path):
    f = tmp_path / "k.pem"
    f.write_bytes(b"old")
    f.chmod(0o644)
    write_private_file(f, b"new")
    assert f.read_bytes() == b"new"
    assert _mode(f) == 0o600


def test_symlink_at_destination_is_replaced_not_followed(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    victim.chmod(0o644)
    link = tmp_path / "k.pem"
    link.symlink_to(victim)
    write_private_file(link, b"secret")
    assert victim.read_text() == "keep me"
    assert _mode(victim) == 0o644
    assert not link.is_symlink()
    assert link.read_bytes() == b"secret"
    assert _mode(link) == 0o600


def test_hard_link_at_destination_does_not_modify_the_other_name(tmp_path):
    other = tmp_path / "other.txt"
    other.write_text("keep me")
    link = tmp_path / "k.pem"
    os.link(other, link)
    write_private_file(link, b"secret")
    assert other.read_text() == "keep me"
    assert link.read_bytes() == b"secret"


def test_no_temp_files_are_left_behind(tmp_path):
    write_private_file(tmp_path / "k.pem", b"x")
    assert [p.name for p in tmp_path.iterdir()] == ["k.pem"]


def test_ensure_private_dir_creates_owner_only_directory(tmp_path):
    d = ensure_private_dir(tmp_path / "a" / "b")
    assert d.is_dir()
    assert _mode(d) == 0o700


def test_ensure_private_dir_tightens_an_existing_directory(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    d.chmod(0o775)
    ensure_private_dir(d)
    assert _mode(d) == 0o700


def test_ensure_private_dir_rejects_a_regular_file(tmp_path):
    f = tmp_path / "f"
    f.write_text("x")
    with pytest.raises(CertificateError):
        ensure_private_dir(f)


def test_ensure_private_dir_refuses_a_symlink_and_leaves_the_target_alone(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    target.chmod(0o755)
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(CertificateError):
        ensure_private_dir(link)
    assert _mode(target) == 0o755


def test_ensure_private_dir_creates_missing_parents_owner_only(tmp_path):
    ensure_private_dir(tmp_path / "a" / "b" / "c")
    for name in ("a", "a/b", "a/b/c"):
        assert _mode(tmp_path / name) == 0o700


def test_ensure_private_dir_does_not_touch_existing_parents(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir()
    parent.chmod(0o755)
    ensure_private_dir(parent / "child")
    assert _mode(parent) == 0o755
    assert _mode(parent / "child") == 0o700


def test_save_root_ca_key_and_directory_are_owner_only(tmp_path):
    ca = generate_root_ca(site_id="test-site")
    d = tmp_path / "ca"
    d.mkdir()
    d.chmod(0o755)
    save_root_ca(ca, d)
    assert _mode(d) == 0o700
    assert _mode(d / "root_ca.key.pem") == 0o600


def test_refuses_to_store_keys_without_posix_hardening(monkeypatch, tmp_path):
    monkeypatch.delattr(os, "O_NOFOLLOW")
    with pytest.raises(CertificateError):
        write_private_file(tmp_path / "k.pem", b"x")
    with pytest.raises(CertificateError):
        ensure_private_dir(tmp_path / "d")


def test_write_public_file_is_atomic_and_world_readable_regardless_of_umask(tmp_path):
    old_umask = os.umask(0o077)
    try:
        f = tmp_path / "root_ca.crt.pem"
        write_public_file(f, b"cert")
    finally:
        os.umask(old_umask)
    assert f.read_bytes() == b"cert"
    assert _mode(f) == 0o644
    assert [p.name for p in tmp_path.iterdir()] == ["root_ca.crt.pem"]


def test_write_public_file_replaces_a_planted_symlink(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    link = tmp_path / "root_ca.crt.pem"
    link.symlink_to(victim)
    write_public_file(link, b"cert")
    assert victim.read_text() == "keep me"
    assert not link.is_symlink()
    assert link.read_bytes() == b"cert"


def test_save_root_ca_certificate_is_public_and_key_is_private(tmp_path):
    ca = generate_root_ca(site_id="test-site")
    save_root_ca(ca, tmp_path / "ca")
    assert _mode(tmp_path / "ca" / "root_ca.crt.pem") == 0o644
    assert _mode(tmp_path / "ca" / "root_ca.key.pem") == 0o600
