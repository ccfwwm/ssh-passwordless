#!/usr/bin/env python3
"""Local, credential-free primitives for bootstrapping a dedicated SSH key.

Used by ssh_passwordless.py. Every function here is pure or filesystem-local except
the explicit paramiko connection helpers, so the module never stores a password.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import errno
import getpass
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import weakref

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from typing import Iterable, Mapping, NamedTuple, Optional, Protocol, Set


_HOST_PATTERN_CHARS = frozenset("*?[]!")
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}\$?$")
_ALIAS = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$")
_KEY_ALGORITHM = re.compile(
    r"^(?:ssh-(?:ed25519|rsa)|ecdsa-sha2-nistp(?:256|384|521)|"
    r"sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)$"
)
_BEGIN_INCLUDE = b"# BEGIN SSH-PASSWORDLESS MANAGED INCLUDE"
_END_INCLUDE = b"# END SSH-PASSWORDLESS MANAGED INCLUDE"
_DEFAULT_SECURITY = object()
_THREAD_LOCKS = weakref.WeakValueDictionary()
_THREAD_LOCKS_GUARD = threading.Lock()


class Target(NamedTuple):
    host: str
    user: str
    alias: str
    port: int
    target_id: str


class IdentityMaterial(NamedTuple):
    private_path: Path
    public_path: Path
    public_key: str
    fingerprint: str
    created: bool


class HostKeyChangedError(RuntimeError):
    """Raised when a pinned or previously trusted host key changes."""


class HostKeyRevokedError(HostKeyChangedError):
    """Raised when the target matches an OpenSSH @revoked record."""


class BootstrapStageError(RuntimeError):
    def __init__(self, stage: str, message: str):
        self.stage = stage
        super().__init__(message)


class SecurityDescriptorBackend(Protocol):
    def get_sddl(self, path: Path) -> str: ...

    def set_sddl(self, path: Path, sddl: str) -> None: ...


class WindowsAclBackend:
    """Read and restore Windows security descriptors without pywin32."""

    def __init__(self, executable: Optional[str] = None):
        self.executable = executable or shutil.which("pwsh.exe") or shutil.which("pwsh") or shutil.which("powershell.exe")
        if not self.executable:
            raise RuntimeError("PowerShell is required to preserve Windows ACLs")

    def _run(self, script: str, *, environment: Mapping[str, str]) -> str:
        child_environment = os.environ.copy()
        child_environment.update(environment)
        completed = subprocess.run(
            [
                self.executable,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            check=False,
            capture_output=True,
            text=True,
            env=child_environment,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or "unknown PowerShell ACL error"
            raise RuntimeError(f"PowerShell ACL operation failed: {detail}")
        return completed.stdout.strip()

    def get_sddl(self, path: Path) -> str:
        script = (
            "$ErrorActionPreference='Stop'; "
            "(Get-Acl -LiteralPath $env:SSHPL_ACL_PATH).Sddl"
        )
        sddl = self._run(script, environment={"SSHPL_ACL_PATH": str(path)})
        if not sddl:
            raise RuntimeError("PowerShell returned an empty security descriptor")
        return sddl

    def set_sddl(self, path: Path, sddl: str) -> None:
        script = (
            "$ErrorActionPreference='Stop'; "
            "$acl=Get-Acl -LiteralPath $env:SSHPL_ACL_PATH; "
            "$acl.SetSecurityDescriptorSddlForm($env:SSHPL_ACL_SDDL); "
            "Set-Acl -LiteralPath $env:SSHPL_ACL_PATH -AclObject $acl"
        )
        self._run(
            script,
            environment={"SSHPL_ACL_PATH": str(path), "SSHPL_ACL_SDDL": sddl},
        )


def _reject_unsafe_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{field} contains whitespace or control characters")
    if any(character in _HOST_PATTERN_CHARS for character in value):
        raise ValueError(f"{field} contains SSH Host pattern syntax")
    return value


def _canonical_host(host: object) -> str:
    value = _reject_unsafe_text(host, "host")
    try:
        return ipaddress.ip_address(value).compressed.lower()
    except ValueError:
        pass
    if value.count(".") == 3 and all(character.isdigit() or character == "." for character in value):
        raise ValueError("host resembles an invalid IPv4 address")
    if len(value) > 253 or value.startswith(".") or value.endswith("."):
        raise ValueError("invalid DNS host")
    labels = value.split(".")
    if not labels or any(not _DNS_LABEL.fullmatch(label) for label in labels):
        raise ValueError("invalid DNS host")
    return value.lower()


def _validated_port(port: object) -> int:
    if isinstance(port, bool):
        raise ValueError("port must be an integer from 1 to 65535")
    if isinstance(port, str):
        if not port or not port.isascii() or not port.isdigit():
            raise ValueError("port must be an integer from 1 to 65535")
        parsed = int(port, 10)
    elif isinstance(port, int):
        parsed = port
    else:
        raise ValueError("port must be an integer from 1 to 65535")
    if not 1 <= parsed <= 65535:
        raise ValueError("port must be an integer from 1 to 65535")
    return parsed


def validate_target(host: object, user: object, alias: object = None, port: object = 22) -> Target:
    canonical_host = _canonical_host(host)
    valid_user = _reject_unsafe_text(user, "user")
    if not _USER.fullmatch(valid_user):
        raise ValueError("invalid SSH user")
    valid_port = _validated_port(port)
    identity = f"{valid_user}@{canonical_host}:{valid_port}".encode("utf-8")
    suffix = hashlib.sha256(identity).hexdigest()[:16]
    if alias is None:
        valid_alias = f"sshpl-{suffix}"
        return Target(canonical_host, valid_user, valid_alias, valid_port, valid_alias)
    valid_alias = _reject_unsafe_text(alias, "alias")
    if not _ALIAS.fullmatch(valid_alias):
        raise ValueError("invalid SSH alias")
    return Target(canonical_host, valid_user, valid_alias, valid_port, f"{valid_alias.lower()}-{suffix}")


def _key_identity(text: str) -> tuple[str, str]:
    if "\r" in text or "\n" in text or "\x00" in text:
        raise ValueError("public key must be one line")
    try:
        tokens = shlex.split(text, comments=False, posix=True)
    except ValueError as error:
        raise ValueError("invalid quoting in public key line") from error
    if len(tokens) >= 2 and _KEY_ALGORITHM.fullmatch(tokens[0]):
        index = 0
    elif len(tokens) >= 3 and _KEY_ALGORITHM.fullmatch(tokens[1]):
        index = 1
    else:
        raise ValueError("public key algorithm and blob not found")
    algorithm = tokens[index]
    blob = tokens[index + 1]
    try:
        decoded = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("invalid public key base64") from error
    if not decoded:
        raise ValueError("empty public key blob")
    if len(decoded) < 4:
        raise ValueError("truncated SSH public key algorithm length")
    algorithm_length = int.from_bytes(decoded[:4], byteorder="big", signed=False)
    if not 1 <= algorithm_length <= 256 or 4 + algorithm_length > len(decoded):
        raise ValueError("invalid SSH public key algorithm length")
    try:
        wire_algorithm = decoded[4 : 4 + algorithm_length].decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("SSH public key wire algorithm is not ASCII") from error
    if wire_algorithm != algorithm:
        raise ValueError("declared public key algorithm does not match wire algorithm")
    try:
        load_ssh_public_key(f"{algorithm} {blob}".encode("ascii"))
    except (ValueError, UnsupportedAlgorithm) as error:
        raise ValueError("invalid or incomplete SSH public key wire structure") from error
    return algorithm, blob


def _newline_for(data: bytes) -> bytes:
    return b"\r\n" if b"\r\n" in data else b"\n"


def merge_authorized_key(existing: bytes, candidate: str) -> bytes:
    if not isinstance(existing, bytes):
        raise TypeError("existing authorized_keys data must be bytes")
    candidate_line = candidate.strip()
    if candidate_line.startswith("#"):
        raise ValueError("candidate public key cannot be a comment")
    identity = _key_identity(candidate_line)
    for raw_line in existing.splitlines():
        if raw_line.lstrip().startswith(b"#"):
            continue
        try:
            line_identity = _key_identity(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            continue
        if line_identity == identity:
            return existing
    newline = _newline_for(existing)
    separator = b"" if not existing or existing.endswith((b"\n", b"\r")) else newline
    return existing + separator + candidate_line.encode("utf-8") + newline


def _normalized_config_path(path: object) -> str:
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("config path must be path-like")
    value = os.fspath(path).replace("\\", "/")
    if not value or any(character in "\r\n\x00" for character in value):
        raise ValueError("invalid config path")
    return value


def ensure_managed_include(existing: bytes, include_path: object) -> bytes:
    if not isinstance(existing, bytes):
        raise TypeError("SSH config data must be bytes")
    newline = _newline_for(existing)
    path_bytes = _quoted_config_value(include_path, "include_path").encode("utf-8")
    block = newline.join((_BEGIN_INCLUDE, b"Include " + path_bytes, _END_INCLUDE)) + newline
    begin_ranges = []
    end_ranges = []
    offset = 0
    for line in existing.splitlines(keepends=True):
        content = line.rstrip(b"\r\n")
        line_end = offset + len(line)
        if _BEGIN_INCLUDE in content:
            if content != _BEGIN_INCLUDE:
                raise ValueError("managed Include begin marker must occupy a complete line")
            begin_ranges.append((offset, line_end))
        if _END_INCLUDE in content:
            if content != _END_INCLUDE:
                raise ValueError("managed Include end marker must occupy a complete line")
            end_ranges.append((offset, line_end))
        offset = line_end
    if len(begin_ranges) > 1 or len(end_ranges) > 1:
        raise ValueError("multiple managed Include blocks are not allowed")
    if bool(begin_ranges) != bool(end_ranges):
        raise ValueError("incomplete managed Include block")
    if begin_ranges:
        begin = begin_ranges[0][0]
        suffix_start = end_ranges[0][1]
        if begin >= end_ranges[0][0]:
            raise ValueError("managed Include markers are out of order")
        return existing[:begin] + block + existing[suffix_start:]
    separator = b"" if not existing or existing.endswith((b"\n", b"\r")) else newline
    return existing + separator + block


def _quoted_config_value(value: object, field: str) -> str:
    if not isinstance(value, (str, os.PathLike)):
        raise TypeError(f"{field} must be path-like")
    text = os.fspath(value).replace("\\", "/")
    if not text or any(character in "\r\n\x00" for character in text):
        raise ValueError(f"invalid {field}")
    if '"' in text:
        raise ValueError(f"invalid {field}")
    return f'"{text}"' if any(character.isspace() for character in text) else text


def render_managed_config(entries: Iterable[Mapping[str, object]]) -> bytes:
    validated = []
    aliases: Set[str] = set()
    for entry in entries:
        target = validate_target(entry["host"], entry["user"], entry["alias"], entry.get("port", 22))
        folded = target.alias.casefold()
        if folded in aliases:
            raise ValueError(f"duplicate SSH alias: {target.alias}")
        aliases.add(folded)
        identity_file = _quoted_config_value(entry["identity_file"], "identity_file")
        validated.append((target, identity_file))
    output = []
    for target, identity_file in sorted(validated, key=lambda item: item[0].alias.casefold()):
        output.extend(
            (
                f"Host {target.alias}",
                f"  HostName {target.host}",
                f"  User {target.user}",
                f"  Port {target.port}",
                "  IdentitiesOnly yes",
                "  IdentityAgent none",
                f"  IdentityFile {identity_file}",
                "  BatchMode yes",
                "",
            )
        )
    return "\n".join(output).encode("utf-8")


def find_alias_conflicts(config: bytes, aliases: Iterable[str]) -> Set[str]:
    requested = list(aliases)
    folded = {alias.casefold(): alias for alias in requested}
    conflicts: Set[str] = set()
    for index, raw_line in enumerate(config.splitlines()):
        line = raw_line.decode("utf-8", errors="surrogateescape")
        if index == 0:
            line = line.removeprefix("\ufeff")
        match = re.match(r"^\s*host(?:\s+|=)(.*?)\s*$", line, flags=re.IGNORECASE)
        if not match:
            continue
        try:
            patterns = shlex.split(match.group(1), comments=False, posix=True)
        except ValueError as error:
            raise ValueError("invalid quoting in SSH Host declaration") from error
        for pattern in patterns:
            if any(character in _HOST_PATTERN_CHARS for character in pattern):
                continue
            original = folded.get(pattern.casefold())
            if original is not None:
                conflicts.add(original)
    return conflicts


def atomic_write_bytes(
    path: Path | str,
    data: bytes,
    *,
    security: Optional[SecurityDescriptorBackend] | object = _DEFAULT_SECURITY,
) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if security is _DEFAULT_SECURITY:
        security = WindowsAclBackend() if os.name == "nt" else None
    existed = destination.exists()
    sddl = security.get_sddl(destination) if security is not None and existed else None
    mode = destination.stat().st_mode if existed else None
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=destination.parent, prefix=f".{destination.name}.", delete=False) as handle:
            temporary_name = handle.name
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path = Path(temporary_name)
        if mode is not None:
            os.chmod(temporary_path, stat.S_IMODE(mode))
        if security is not None and sddl is not None:
            security.set_sddl(temporary_path, sddl)
        os.replace(temporary_name, destination)
        temporary_name = None
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def _normalized_identity_path(value: str) -> str:
    unquoted = value.strip().strip('"')
    expanded = os.path.expandvars(os.path.expanduser(unquoted))
    return os.path.normcase(os.path.abspath(os.path.normpath(expanded)))


def validate_effective_identity_files(ssh_g_output: str, target_identity_file: object) -> Set[str]:
    if not isinstance(ssh_g_output, str):
        raise TypeError("ssh -G output must be text")
    target = _normalized_identity_path(os.fspath(target_identity_file))
    identities: Set[str] = set()
    identities_only = False
    for line in ssh_g_output.splitlines():
        key, separator, value = line.strip().partition(" ")
        if not separator:
            continue
        if key.casefold() == "identityfile":
            identities.add(_normalized_identity_path(value))
        elif key.casefold() == "identitiesonly":
            identities_only = value.strip().casefold() == "yes"
    if identities != {target} or not identities_only:
        raise ValueError("effective SSH config must use only the target IdentityFile with IdentitiesOnly yes")
    return identities


def validate_effective_alias_config(
    ssh_g_output: str,
    target_identity_file: object,
    target: Optional[Target] = None,
) -> Set[str]:
    identities = validate_effective_identity_files(ssh_g_output, target_identity_file)
    settings = {}
    for line in ssh_g_output.splitlines():
        key, separator, value = line.strip().partition(" ")
        if separator:
            settings.setdefault(key.casefold(), value.strip())
    if settings.get("batchmode", "").casefold() != "yes":
        raise ValueError("effective SSH alias must enable BatchMode")
    if settings.get("identityagent", "").casefold() != "none":
        raise ValueError("effective SSH alias must disable IdentityAgent")
    if target is not None:
        if settings.get("hostname") != target.host:
            raise ValueError("effective SSH alias HostName does not match the target")
        if settings.get("user") != target.user:
            raise ValueError("effective SSH alias User does not match the target")
        try:
            effective_port = _validated_port(settings.get("port"))
        except ValueError as error:
            raise ValueError("effective SSH alias Port is invalid") from error
        if effective_port != target.port:
            raise ValueError("effective SSH alias Port does not match the target")
    return identities


def format_known_hosts_endpoint(host: object, port: object = 22) -> str:
    canonical_host = _canonical_host(host)
    valid_port = _validated_port(port)
    return canonical_host if valid_port == 22 else f"[{canonical_host}]:{valid_port}"


def sha256_fingerprint(key_blob: str) -> str:
    if not isinstance(key_blob, str):
        raise TypeError("key blob must be text")
    try:
        decoded = base64.b64decode(key_blob, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("invalid host key base64") from error
    if not decoded:
        raise ValueError("empty host key blob")
    digest = hashlib.sha256(decoded).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def verify_host_key_fingerprint(key_blob: str, expected: str) -> None:
    actual = sha256_fingerprint(key_blob)
    if not isinstance(expected, str) or not hmac.compare_digest(actual, expected):
        raise HostKeyChangedError(f"host key fingerprint mismatch: expected {expected!r}, got {actual!r}")


def redact_sensitive(message: object, *, secrets: Iterable[str] = ()) -> str:
    redacted = str(message)
    for secret in secrets:
        if secret:
            redacted = redacted.replace(str(secret), "[REDACTED]")
    redacted = re.sub(
        r"(?i)\b(token|password|passwd|secret|api[_-]?key|key)\s*=\s*([^\s,;]+)",
        lambda match: f"{match.group(1)}=[REDACTED]",
        redacted,
    )
    redacted = re.sub(r"(?i)(Authorization\s*:\s*Bearer\s+)[^\s,;]+", r"\1[REDACTED]", redacted)
    return redacted


_STAGE_MESSAGES = {
    "validate": "SSH target validation failed",
    "keygen": "SSH key generation failed",
    "connect": "SSH connection failed",
    "hostkey": "SSH host-key verification failed",
    "install": "SSH public-key installation failed",
    "config": "SSH configuration update failed",
    "verify": "SSH verification failed",
}


def map_stage_error(stage: str, error: BaseException, *, secrets: Iterable[str] = ()) -> BootstrapStageError:
    if stage not in _STAGE_MESSAGES:
        raise ValueError(f"unknown bootstrap stage: {stage}")
    if isinstance(error, PermissionError):
        detail = "permission denied"
    elif isinstance(error, OSError):
        detail = f"operating system error (errno={error.errno})"
    else:
        detail = redact_sensitive(error, secrets=secrets)
    return BootstrapStageError(stage, f"{_STAGE_MESSAGES[stage]}: {detail}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bootstrap dedicated SSH key authentication")
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--alias")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--expected-host-key-sha256")
    parser.add_argument("--key-path", type=Path)
    parser.add_argument("--known-hosts", type=Path, default=Path.home() / ".ssh" / "known_hosts")
    parser.add_argument("--ssh-config", type=Path, default=Path.home() / ".ssh" / "config")
    return parser


@contextlib.contextmanager
def _file_lock(lock_path: Path):
    lock_key = os.path.normcase(os.path.abspath(lock_path))
    with _THREAD_LOCKS_GUARD:
        thread_lock = _THREAD_LOCKS.setdefault(lock_key, threading.Lock())
    with thread_lock:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+b") as handle:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
                os.fsync(handle.fileno())
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _validate_known_hosts_endpoint(endpoint: object) -> str:
    if not isinstance(endpoint, str) or not endpoint or not endpoint.isascii():
        raise ValueError("invalid known_hosts endpoint")
    if endpoint.startswith("["):
        match = re.fullmatch(r"\[([^\[\]]+)\]:(\d+)", endpoint)
        if not match:
            raise ValueError("invalid known_hosts endpoint")
        host, port_text = match.groups()
        port = _validated_port(port_text)
        if port == 22 or format_known_hosts_endpoint(host, port) != endpoint:
            raise ValueError("known_hosts endpoint is not canonical")
    elif format_known_hosts_endpoint(endpoint, 22) != endpoint:
        raise ValueError("known_hosts endpoint is not canonical")
    return endpoint


def _hashed_host_matches(host: bytes, endpoint: bytes) -> bool:
    try:
        empty, version, salt_text, digest_text = host.split(b"|", 3)
        if empty or version != b"1":
            return False
        salt = base64.b64decode(salt_text, validate=True)
        stored_digest = base64.b64decode(digest_text, validate=True)
    except (ValueError, binascii.Error):
        return False
    if not salt or len(stored_digest) != hashlib.sha1().digest_size:
        return False
    actual_digest = hmac.new(salt, endpoint, hashlib.sha1).digest()
    return hmac.compare_digest(actual_digest, stored_digest)


def _host_field_matches(host_field: bytes, endpoint: bytes) -> bool:
    for host in host_field.split(b","):
        if host == endpoint or (host.startswith(b"|1|") and _hashed_host_matches(host, endpoint)):
            return True
    return False


def _known_host_records(data: bytes, endpoint: str):
    endpoint_bytes = endpoint.encode("ascii")
    for raw_line in data.splitlines():
        fields = raw_line.split()
        if len(fields) < 3 or raw_line.lstrip().startswith(b"#"):
            continue
        marker = None
        if fields[0].startswith(b"@"):
            if len(fields) < 4:
                continue
            marker = fields[0].decode("ascii", errors="replace")
            host_field, algorithm, blob = fields[1:4]
        else:
            host_field, algorithm, blob = fields[:3]
        if _host_field_matches(host_field, endpoint_bytes):
            yield marker, algorithm.decode("ascii", errors="replace"), blob.decode("ascii", errors="replace")


def update_known_hosts(
    path: Path | str,
    endpoint: str,
    key_algorithm: str,
    key_blob: str,
    expected_fingerprint: str,
    *,
    lock_factory=_file_lock,
) -> bool:
    if not _KEY_ALGORITHM.fullmatch(key_algorithm):
        raise ValueError("unsupported host key algorithm")
    _key_identity(f"{key_algorithm} {key_blob}")
    verify_host_key_fingerprint(key_blob, expected_fingerprint)
    endpoint = _validate_known_hosts_endpoint(endpoint)

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    lock_path = destination.with_name(destination.name + ".lock")
    with lock_factory(lock_path):
        existing = destination.read_bytes() if destination.exists() else b""
        records = list(_known_host_records(existing, endpoint))
        if any(marker == "@revoked" for marker, _algorithm, _blob in records):
            raise HostKeyRevokedError(f"host key is revoked for {endpoint}")
        ordinary_records = [
            (algorithm, blob) for marker, algorithm, blob in records if marker is None
        ]
        if ordinary_records:
            if any(record != (key_algorithm, key_blob) for record in ordinary_records):
                raise HostKeyChangedError(f"host key changed for {endpoint}")
            return False

        newline = _newline_for(existing)
        separator = b"" if not existing or existing.endswith((b"\n", b"\r")) else newline
        record = f"{endpoint} {key_algorithm} {key_blob}".encode("ascii") + newline
        with destination.open("ab") as handle:
            handle.write(separator + record)
            handle.flush()
            os.fsync(handle.fileno())
        return True


_GENERIC_KEY_NAMES = frozenset(
    {
        "id_rsa", "id_dsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk",
        "identity",
    }
)
_STAGE_EXIT_CODES = {
    "validate": 2,
    "keygen": 3,
    "connect": 4,
    "hostkey": 5,
    "install": 6,
    "config": 7,
    "verify": 8,
    "credential": 9,
}
_STAGE_MESSAGES["credential"] = "SSH password input failed"


def _completed(command, *, runner=subprocess.run, timeout: float = 15.0):
    try:
        result = runner(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise map_stage_error("keygen", error) from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "command failed").strip()
        raise map_stage_error("keygen", RuntimeError(detail))
    return result


def restrict_windows_private_key_acl(path: Path | str) -> None:
    """Restrict a private key to the current Windows SID and LocalSystem."""
    if os.name != "nt":
        os.chmod(path, 0o600)
        return
    import ctypes
    from ctypes import wintypes

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class TokenUser(ctypes.Structure):
        _fields_ = [("User", SidAndAttributes)]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.CreateWellKnownSid.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
    advapi32.CreateWellKnownSid.restype = wintypes.BOOL
    advapi32.GetLengthSid.argtypes = [ctypes.c_void_p]
    advapi32.GetLengthSid.restype = wintypes.DWORD
    advapi32.InitializeAcl.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
    advapi32.InitializeAcl.restype = wintypes.BOOL
    advapi32.AddAccessAllowedAceEx.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    advapi32.AddAccessAllowedAceEx.restype = wintypes.BOOL
    advapi32.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        required = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
        token_buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(token, 1, token_buffer, required, ctypes.byref(required)):
            raise ctypes.WinError(ctypes.get_last_error())
        user_sid = ctypes.cast(token_buffer, ctypes.POINTER(TokenUser)).contents.User.Sid
        system_sid_size = wintypes.DWORD(68)
        system_sid = ctypes.create_string_buffer(system_sid_size.value)
        if not advapi32.CreateWellKnownSid(22, None, system_sid, ctypes.byref(system_sid_size)):
            raise ctypes.WinError(ctypes.get_last_error())
        user_sid_size = advapi32.GetLengthSid(user_sid)
        acl_size = 8 + (8 + user_sid_size) + (8 + system_sid_size.value)
        acl = ctypes.create_string_buffer(acl_size)
        if not advapi32.InitializeAcl(acl, acl_size, 2):
            raise ctypes.WinError(ctypes.get_last_error())
        file_all_access = 0x001F01FF
        for sid in (user_sid, ctypes.cast(system_sid, ctypes.c_void_p)):
            if not advapi32.AddAccessAllowedAceEx(acl, 2, 0, file_all_access, sid):
                raise ctypes.WinError(ctypes.get_last_error())
        result = advapi32.SetNamedSecurityInfoW(
            str(Path(path).resolve()), 1, 0x00000004 | 0x80000000,
            None, None, acl, None,
        )
        if result:
            raise ctypes.WinError(result)
    finally:
        kernel32.CloseHandle(token)


def _public_key_fingerprint(public_path: Path, *, runner=subprocess.run) -> str:
    result = _completed(["ssh-keygen", "-lf", str(public_path), "-E", "sha256"], runner=runner)
    fields = result.stdout.strip().split()
    if len(fields) < 2 or not fields[1].startswith("SHA256:"):
        raise map_stage_error("keygen", RuntimeError("ssh-keygen returned an invalid fingerprint"))
    return fields[1]


def choose_or_create_identity(
    key_path: Path | str,
    target: Target,
    *,
    runner=subprocess.run,
    acl_setter=restrict_windows_private_key_acl,
) -> IdentityMaterial:
    private_path = Path(key_path).expanduser().resolve()
    public_path = Path(str(private_path) + ".pub")
    if private_path.name.casefold() in _GENERIC_KEY_NAMES:
        raise map_stage_error("keygen", ValueError("a generic SSH identity cannot be reused or overwritten"))
    private_exists, public_exists = private_path.exists(), public_path.exists()
    if private_exists != public_exists:
        raise map_stage_error("keygen", FileExistsError("dedicated key pair is incomplete; refusing to overwrite it"))
    if private_exists:
        acl_setter(private_path)
        derived = _completed(["ssh-keygen", "-y", "-f", str(private_path)], runner=runner).stdout.strip()
        stored = public_path.read_text(encoding="utf-8").strip()
        try:
            if _key_identity(derived) != _key_identity(stored):
                raise ValueError("dedicated private/public key pair does not match")
        except ValueError as error:
            raise map_stage_error("keygen", error) from error
        return IdentityMaterial(private_path, public_path, stored, _public_key_fingerprint(public_path, runner=runner), False)

    private_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ssh-passwordless-key-") as temporary_directory:
        generated = Path(temporary_directory) / "identity"
        _completed(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"ssh-passwordless:{target.target_id}", "-f", str(generated)],
            runner=runner,
            timeout=30,
        )
        generated_public = Path(str(generated) + ".pub")
        if not generated.is_file() or not generated_public.is_file():
            raise map_stage_error("keygen", RuntimeError("ssh-keygen did not create a complete key pair"))
        installed_private = False
        try:
            os.link(generated, private_path)
            installed_private = True
            os.link(generated_public, public_path)
        except FileExistsError as error:
            if installed_private:
                private_path.unlink(missing_ok=True)
            raise map_stage_error("keygen", FileExistsError("dedicated key path appeared concurrently; refusing to overwrite")) from error
        except OSError as error:
            if installed_private:
                private_path.unlink(missing_ok=True)
            public_path.unlink(missing_ok=True)
            raise map_stage_error("keygen", error) from error
    try:
        acl_setter(private_path)
        public_key = public_path.read_text(encoding="utf-8").strip()
        key_fingerprint = _public_key_fingerprint(public_path, runner=runner)
    except BaseException:
        private_path.unlink(missing_ok=True)
        public_path.unlink(missing_ok=True)
        raise
    return IdentityMaterial(private_path, public_path, public_key, key_fingerprint, True)


def read_password(stdin=None, environ: Optional[Mapping[str, str]] = None) -> str:
    stream = stdin if stdin is not None else sys.stdin
    environment = os.environ if environ is None else environ
    if stream.isatty():
        password = getpass.getpass("SSH password: ")
    else:
        if environment.get("SSH_PASSWORDLESS_CHANNEL") != "gui-pipe-v1":
            raise map_stage_error("credential", RuntimeError("redirected stdin is not an authorized password channel"))
        password = stream.readline().rstrip("\r\n")
    if not password:
        raise map_stage_error("credential", RuntimeError("empty SSH password"))
    return password


def verify_direct_ssh(
    target: Target,
    private_key: Path | str,
    known_hosts: Path | str,
    *,
    runner=subprocess.run,
    timeout: float = 15.0,
) -> bool:
    with tempfile.TemporaryDirectory(prefix="ssh-passwordless-verify-") as temporary_directory:
        empty_config = Path(temporary_directory) / "empty_config"
        empty_config.write_bytes(b"")
        command = [
            "ssh", "-F", str(empty_config),
            "-o", "IdentityAgent=none",
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={Path(known_hosts).resolve()}",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-i", str(Path(private_key).resolve()),
            "-p", str(target.port),
            f"{target.user}@{target.host}",
            "hostname; id -un; id -u",
        ]
        try:
            result = runner(command, check=False, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            return False
    if result.returncode != 0:
        return False
    lines = result.stdout.splitlines()
    return (
        len(lines) == 3
        and bool(lines[0].strip())
        and not any(character.isspace() for character in lines[0].strip())
        and hmac.compare_digest(lines[1].strip(), target.user)
        and lines[2].strip().isascii()
        and lines[2].strip().isdigit()
    )


def validate_written_config(
    config_path: Path | str,
    target: Target,
    private_key: Path | str,
    *,
    runner=subprocess.run,
    timeout: float = 15.0,
) -> Set[str]:
    command = ["ssh", "-F", str(Path(config_path).expanduser().resolve()), "-G", target.alias]
    try:
        result = runner(command, check=False, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as error:
        raise map_stage_error("config", error) from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "ssh -G failed").strip()
        raise map_stage_error("config", RuntimeError(detail))
    try:
        return validate_effective_alias_config(result.stdout, private_key, target)
    except (TypeError, ValueError) as error:
        raise map_stage_error("config", error) from error


def build_target_host_keys(data: bytes, endpoint: str, *, paramiko_module=None):
    if paramiko_module is None:
        import paramiko as paramiko_module
    endpoint = _validate_known_hosts_endpoint(endpoint)
    records = list(_known_host_records(data, endpoint))
    if any(marker == "@revoked" for marker, _algorithm, _blob in records):
        raise HostKeyRevokedError(f"host key is revoked for {endpoint}")
    ordinary = [(algorithm, blob) for marker, algorithm, blob in records if marker is None]
    blobs_by_algorithm = {}
    for algorithm, blob in ordinary:
        blobs_by_algorithm.setdefault(algorithm, set()).add(blob)
    if any(len(blobs) > 1 for blobs in blobs_by_algorithm.values()):
        raise HostKeyChangedError(f"conflicting host keys for {endpoint}")
    host_keys = paramiko_module.HostKeys()
    for algorithm, blobs in blobs_by_algorithm.items():
        blob = next(iter(blobs))
        _key_identity(f"{algorithm} {blob}")
        key = paramiko_module.PKey.from_type_string(algorithm, base64.b64decode(blob, validate=True))
        host_keys.add(endpoint, algorithm, key)
    return host_keys


def connect_with_password(
    target: Target,
    password: str,
    known_hosts: Path | str,
    expected_fingerprint: Optional[str],
    *,
    timeout: float = 15.0,
    paramiko_module=None,
):
    if paramiko_module is None:
        import paramiko as paramiko_module
    path = Path(known_hosts).expanduser().resolve()
    existing = path.read_bytes() if path.exists() else b""
    endpoint = format_known_hosts_endpoint(target.host, target.port)
    records = list(_known_host_records(existing, endpoint))
    if any(marker == "@revoked" for marker, _algorithm, _blob in records):
        raise map_stage_error("hostkey", HostKeyRevokedError(f"host key is revoked for {endpoint}"), secrets=(password,))
    known_records = [record for record in records if record[0] is None]
    if not known_records and not expected_fingerprint:
        raise map_stage_error("hostkey", ValueError("unknown host requires --expected-host-key-sha256"), secrets=(password,))
    path.parent.mkdir(parents=True, exist_ok=True)
    client = paramiko_module.SSHClient()
    if known_records:
        filtered = build_target_host_keys(existing, endpoint, paramiko_module=paramiko_module)
        destination = client.get_host_keys()
        destination.clear()
        for hostname, keys in filtered.items():
            for algorithm, key in keys.items():
                destination.add(hostname, algorithm, key)

    outer_expected = expected_fingerprint

    class ExpectedHostKeyPolicy(paramiko_module.MissingHostKeyPolicy):
        def missing_host_key(self, _client, hostname, key):
            algorithm, blob = key.get_name(), key.get_base64()
            if not outer_expected:
                raise HostKeyChangedError(f"untrusted host key for {hostname}")
            verify_host_key_fingerprint(blob, outer_expected)
            update_known_hosts(path, endpoint, algorithm, blob, outer_expected)

    client.set_missing_host_key_policy(ExpectedHostKeyPolicy())
    try:
        client.connect(
            hostname=target.host,
            port=target.port,
            username=target.user,
            password=password,
            allow_agent=False,
            look_for_keys=False,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            channel_timeout=timeout,
        )
    except BaseException as error:
        with contextlib.suppress(BaseException):
            client.close()
        stage = "hostkey" if isinstance(error, (HostKeyChangedError, HostKeyRevokedError, getattr(paramiko_module, "BadHostKeyException", ()))) else "connect"
        raise map_stage_error(stage, error, secrets=(password,)) from error
    return client


def _sftp_read(sftp, path: str) -> bytes:
    if hasattr(sftp, "read_bytes"):
        return sftp.read_bytes(path)
    with sftp.open(path, "rb") as handle:
        return handle.read()


def _sftp_write_exclusive(sftp, path: str, data: bytes, mode: int) -> None:
    if hasattr(sftp, "write_exclusive"):
        sftp.write_exclusive(path, data, mode)
        return
    with sftp.open(path, "wx") as handle:
        handle.write(data)
        handle.flush()
    sftp.chmod(path, mode)


def _missing_remote(error: BaseException) -> bool:
    return getattr(error, "errno", None) == 2 or (getattr(error, "args", ()) and error.args[0] == 2)


def _checked_remote_node(sftp, path: str, uid: int, kind: str, mode: Optional[int], *, create: bool = False):
    try:
        attributes = sftp.lstat(path)
    except (IOError, OSError) as error:
        if not create or not _missing_remote(error):
            raise
        if kind == "directory":
            if mode is None:
                raise ValueError("a creation mode is required")
            sftp.mkdir(path, mode)
        else:
            if mode is None:
                raise ValueError("a creation mode is required")
            _sftp_write_exclusive(sftp, path, b"", mode)
        attributes = sftp.lstat(path)
    expected = stat.S_ISDIR if kind == "directory" else stat.S_ISREG
    if stat.S_ISLNK(attributes.st_mode) or not expected(attributes.st_mode):
        raise ValueError(f"remote {kind} path has an unsafe file type")
    if attributes.st_uid != uid:
        raise PermissionError(f"remote {kind} path has an unexpected owner")
    if mode is not None and stat.S_IMODE(attributes.st_mode) != mode:
        sftp.chmod(path, mode)
        attributes = sftp.lstat(path)
        if attributes.st_uid != uid or stat.S_IMODE(attributes.st_mode) != mode:
            raise PermissionError(f"remote {kind} permissions could not be secured")
    return attributes


class _RemoteChannelLockHolder:
    def __init__(self, acquired, pid, stdin, stdout, stderr, timeout):
        self.acquired = acquired
        self.pid = pid
        self._stdin = stdin
        self._stdout = stdout
        self._stderr = stderr
        self._timeout = timeout
        self._released = False

    def release(self):
        if self._released:
            return
        self._released = True
        try:
            if self.acquired:
                self._stdin.write("RELEASE\n")
                self._stdin.flush()
            else:
                self._stdin.close()
            deadline = time.monotonic() + max(0.0, self._timeout)
            while not self._stdout.channel.exit_status_ready():
                if time.monotonic() >= deadline:
                    self._stdout.channel.close()
                    raise TimeoutError("remote lock holder did not exit after release")
                time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
            self._stdout.channel.recv_exit_status()
        finally:
            for stream in (self._stdin, self._stdout, self._stderr):
                with contextlib.suppress(BaseException):
                    stream.close()


def _start_remote_lock_holder(client, lock_path: str, timeout: float):
    quoted_lock = shlex.quote(lock_path)
    command = (
        "umask 077; lock=" + quoted_lock + "; "
        "if mkdir \"$lock\" 2>/dev/null; then "
        "trap 'rm -f \"$lock/pid\"; rmdir \"$lock\"' EXIT HUP INT TERM; "
        "printf '%s\\n' \"$$\" > \"$lock/pid\" || exit 74; "
        "chmod 600 \"$lock/pid\" || exit 74; "
        "printf 'READY %s\\n' \"$$\"; "
        "while IFS= read -r line; do [ \"$line\" = RELEASE ] && exit 0; done; exit 75; "
        "else printf 'BUSY\\n'; exit 73; fi"
    )
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    try:
        stdout.channel.settimeout(timeout)
        line = stdout.readline()
        if isinstance(line, bytes):
            line = line.decode("ascii", errors="strict")
    except BaseException:
        with contextlib.suppress(BaseException):
            stdout.channel.close()
        for stream in (stdin, stdout, stderr):
            with contextlib.suppress(BaseException):
                stream.close()
        raise
    line = line.strip()
    if line == "BUSY":
        return _RemoteChannelLockHolder(False, None, stdin, stdout, stderr, timeout)
    match = re.fullmatch(r"READY ([1-9][0-9]*)", line)
    if not match or stdout.channel.exit_status_ready():
        holder = _RemoteChannelLockHolder(False, None, stdin, stdout, stderr, timeout)
        holder.release()
        raise RuntimeError("remote lock holder did not remain alive")
    return _RemoteChannelLockHolder(True, int(match.group(1)), stdin, stdout, stderr, timeout)


def _probe_remote_pid(client, pid: int, timeout: float) -> str:
    numeric_pid = int(pid)
    command = (
        f"if kill -0 {numeric_pid} 2>/dev/null; then printf ALIVE; "
        f"elif [ -d /proc/{numeric_pid} ]; then printf UNKNOWN; "
        "elif [ -d /proc ]; then printf DEAD; else printf UNKNOWN; fi"
    )
    result = _read_remote_command(client, command, timeout=timeout)
    normalized = result.strip().lower()
    if normalized not in {"alive", "dead", "unknown"}:
        raise RuntimeError("remote PID probe returned invalid output")
    return normalized


def _strict_lock_node(sftp, path: str, uid: int, kind: str, mode: int):
    attributes = sftp.lstat(path)
    expected = stat.S_ISDIR if kind == "directory" else stat.S_ISREG
    if stat.S_ISLNK(attributes.st_mode) or not expected(attributes.st_mode):
        raise ValueError(f"remote lock {kind} has an unsafe file type")
    if attributes.st_uid != uid:
        raise PermissionError(f"remote lock {kind} has an unexpected owner")
    if stat.S_IMODE(attributes.st_mode) != mode:
        raise PermissionError(f"remote lock {kind} has unsafe permissions")


@contextlib.contextmanager
def remote_live_lock(
    client,
    sftp,
    uid: int,
    ssh_dir: str,
    *,
    timeout: float = 15.0,
    holder_factory=_start_remote_lock_holder,
    pid_probe=None,
    clock=time.monotonic,
    sleeper=time.sleep,
):
    lock_path = ssh_dir.rstrip("/") + "/.ssh-passwordless.lock"
    pid_path = lock_path + "/pid"
    deadline = clock() + max(0.0, timeout)
    probe = pid_probe or (lambda pid: _probe_remote_pid(client, pid, max(0.1, deadline - clock())))
    try:
        while True:
            remaining = max(0.1, deadline - clock())
            holder = holder_factory(client, lock_path, remaining)
            if holder.acquired:
                try:
                    _strict_lock_node(sftp, lock_path, uid, "directory", 0o700)
                    _strict_lock_node(sftp, pid_path, uid, "file", 0o600)
                    recorded = _sftp_read(sftp, pid_path).decode("ascii").strip()
                    if not recorded.isdigit() or int(recorded) != holder.pid:
                        raise ValueError("remote live-lock PID record does not match its holder")
                    yield holder
                finally:
                    holder.release()
                return
            holder.release()
            try:
                _strict_lock_node(sftp, lock_path, uid, "directory", 0o700)
                _strict_lock_node(sftp, pid_path, uid, "file", 0o600)
                recorded = _sftp_read(sftp, pid_path).decode("ascii").strip()
            except (IOError, OSError) as error:
                if not _missing_remote(error):
                    raise
                if clock() >= deadline:
                    raise TimeoutError("remote authorized_keys live lock timed out") from error
                continue
            if not recorded.isdigit() or int(recorded) <= 0:
                raise ValueError("remote lock PID is invalid")
            state = probe(int(recorded))
            if state == "dead":
                try:
                    sftp.remove(pid_path)
                    sftp.rmdir(lock_path)
                except (IOError, OSError) as error:
                    if not _missing_remote(error):
                        raise
                    if clock() >= deadline:
                        raise TimeoutError("remote authorized_keys live lock timed out") from error
                    continue
                if clock() <= deadline:
                    continue
            if clock() >= deadline:
                raise TimeoutError("remote authorized_keys live lock timed out")
            sleeper(min(0.1, max(0.0, deadline - clock())))
    except BootstrapStageError:
        raise
    except BaseException as error:
        raise map_stage_error("install", error) from error


def install_authorized_key_sftp(
    sftp,
    uid: int,
    public_key: str,
    *,
    lock_factory,
) -> bool:
    old_data = None
    temporary = None
    try:
        home = sftp.normalize(".")
        if not isinstance(home, str) or not home.startswith("/") or home == "/" or any(c in home for c in "\r\n\x00"):
            raise ValueError("SFTP home normalization did not return a safe absolute path")
        _checked_remote_node(sftp, home, uid, "directory", None)
        ssh_dir = home.rstrip("/") + "/.ssh"
        _checked_remote_node(sftp, ssh_dir, uid, "directory", 0o700, create=True)
        authorized = ssh_dir + "/authorized_keys"
        _checked_remote_node(sftp, authorized, uid, "file", 0o600, create=True)
        with lock_factory(ssh_dir):
            old_data = _sftp_read(sftp, authorized)
            new_data = merge_authorized_key(old_data, public_key)
            if new_data == old_data:
                return False
            temporary = ssh_dir + f"/.authorized_keys.sshpl.{uuid.uuid4().hex}.tmp"
            _sftp_write_exclusive(sftp, temporary, new_data, 0o600)
            temp_attributes = sftp.lstat(temporary)
            if temp_attributes.st_uid != uid or not stat.S_ISREG(temp_attributes.st_mode) or stat.S_IMODE(temp_attributes.st_mode) != 0o600:
                raise PermissionError("remote temporary authorized_keys metadata is unsafe")
            if not hasattr(sftp, "posix_rename"):
                raise RuntimeError("OpenSSH/Linux server with the posix-rename SFTP extension is required")
            try:
                sftp.posix_rename(temporary, authorized)
            except (IOError, OSError) as error:
                unsupported_errnos = {errno.ENOSYS, errno.ENOTSUP}
                if hasattr(errno, "EOPNOTSUPP"):
                    unsupported_errnos.add(errno.EOPNOTSUPP)
                message = str(error).strip().casefold()
                if error.errno in unsupported_errnos or message == "operation unsupported":
                    raise RuntimeError(
                        "OpenSSH/Linux server with a working posix-rename SFTP extension is required"
                    ) from error
                raise
            temporary = None
            final = sftp.lstat(authorized)
            if final.st_uid != uid or not stat.S_ISREG(final.st_mode) or stat.S_IMODE(final.st_mode) != 0o600:
                rollback = ssh_dir + f"/.authorized_keys.sshpl.rollback.{uuid.uuid4().hex}.tmp"
                _sftp_write_exclusive(sftp, rollback, old_data, 0o600)
                sftp.posix_rename(rollback, authorized)
                raise PermissionError("remote authorized_keys metadata changed after replacement")
            return True
    except BootstrapStageError:
        raise
    except BaseException as error:
        raise map_stage_error("install", error) from error
    finally:
        if temporary:
            with contextlib.suppress(BaseException):
                sftp.remove(temporary)


def _read_remote_command(client, command: str, *, timeout: float = 15.0) -> str:
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    status = stdout.channel.recv_exit_status()
    output = stdout.read().decode("utf-8", errors="strict").strip()
    if status != 0:
        detail = stderr.read().decode("utf-8", errors="replace").strip()
        raise RuntimeError(detail or f"remote command failed: {command}")
    return output


def _install_via_client(client, public_key: str, *, timeout: float = 15.0) -> bool:
    uid_text = _read_remote_command(client, "id -u", timeout=timeout)
    if not uid_text.isascii() or not uid_text.isdigit():
        raise map_stage_error("install", RuntimeError("remote id -u returned invalid output"))
    sftp = client.open_sftp()
    try:
        sftp.get_channel().settimeout(timeout)
        return install_authorized_key_sftp(
            sftp,
            int(uid_text),
            public_key,
            lock_factory=lambda ssh_dir: remote_live_lock(
                client, sftp, int(uid_text), ssh_dir, timeout=timeout
            ),
        )
    finally:
        sftp.close()


def write_target_config(config_path: Path | str, target: Target, identity_file: Path | str) -> None:
    path = Path(config_path).expanduser().resolve()
    existing = path.read_bytes() if path.exists() else b""
    conflicts = find_alias_conflicts(existing, [target.alias])
    if conflicts:
        raise map_stage_error("config", ValueError(f"SSH alias already exists outside the managed entry: {target.alias}"))
    managed = path.with_name(f"config.sshpl.{target.target_id}")
    atomic_write_bytes(managed, render_managed_config([{
        "host": target.host, "user": target.user, "alias": target.alias,
        "port": target.port, "identity_file": identity_file,
    }]))
    restrict_windows_private_key_acl(managed)
    atomic_write_bytes(path, ensure_managed_include(existing, managed))
    restrict_windows_private_key_acl(path)


def bootstrap_target(
    target: Target,
    key_path: Path,
    known_hosts: Path,
    ssh_config: Path,
    expected_fingerprint: Optional[str],
    *,
    stdin=None,
    environ: Optional[Mapping[str, str]] = None,
    dependencies: Optional[Mapping[str, object]] = None,
) -> int:
    injected = dict(dependencies or {})
    choose_identity = injected.get("choose_identity", choose_or_create_identity)
    verify = injected.get("verify", verify_direct_ssh)
    password_reader = injected.get("read_password", lambda: read_password(stdin, environ))
    connect = injected.get("connect", connect_with_password)
    install = injected.get("install", _install_via_client)
    write_config = injected.get("write_config", write_target_config)
    validate_config = injected.get("validate_config", validate_written_config)

    def stage_call(stage, callable_object, *args, secrets=()):
        try:
            return callable_object(*args)
        except BootstrapStageError:
            raise
        except BaseException as error:
            raise map_stage_error(stage, error, secrets=secrets) from error

    identity = stage_call("keygen", choose_identity, key_path, target)
    if not identity.created and stage_call("verify", verify, target, identity.private_path, known_hosts):
        return 0
    password = stage_call("credential", password_reader)
    client = None
    try:
        client = stage_call("connect", connect, target, password, known_hosts, expected_fingerprint, secrets=(password,))
        stage_call("install", install, client, identity.public_key, secrets=(password,))
        stage_call("config", write_config, ssh_config, target, identity.private_path, secrets=(password,))
        stage_call("config", validate_config, ssh_config, target, identity.private_path, secrets=(password,))
    finally:
        password = ""
        if client is not None:
            with contextlib.suppress(BaseException):
                client.close()
    if not stage_call("verify", verify, target, identity.private_path, known_hosts):
        raise map_stage_error("verify", RuntimeError("isolated public-key authentication check failed"))
    return 0


def main(
    argv: Optional[Iterable[str]] = None,
    *,
    stdin=None,
    environ: Optional[Mapping[str, str]] = None,
    dependencies: Optional[Mapping[str, object]] = None,
) -> int:
    try:
        args = build_parser().parse_args(argv)
        target = validate_target(args.host, args.user, args.alias, args.port)
        key_path = args.key_path or (Path.home() / ".ssh" / f"sshpl_{target.target_id}")
        return bootstrap_target(
            target,
            key_path,
            args.known_hosts,
            args.ssh_config,
            args.expected_host_key_sha256,
            stdin=stdin,
            environ=environ,
            dependencies=dependencies,
        )
    except BootstrapStageError as error:
        print(redact_sensitive(error), file=sys.stderr)
        return _STAGE_EXIT_CODES.get(error.stage, 1)
    except (ValueError, TypeError) as error:
        print(redact_sensitive(map_stage_error("validate", error)), file=sys.stderr)
        return _STAGE_EXIT_CODES["validate"]
    except SystemExit as error:
        return int(error.code) if isinstance(error.code, int) else _STAGE_EXIT_CODES["validate"]


if __name__ == "__main__":
    raise SystemExit(main())
