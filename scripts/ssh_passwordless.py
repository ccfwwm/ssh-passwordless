#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ssh-passwordless: one-time password setup, then permanent key authentication.

Commands
--------
setup    Generate a dedicated Ed25519 key, install it over SFTP with the server
         password typed into a masked window, then write a managed SSH alias.
verify   Re-check a configured target without using any password.
list     Show the targets this skill manages inside the current SSH config.
doctor   Report the local runtime prerequisites.
selftest Run the built-in contract checks (no network access).

Design rules kept from the original hardened implementation: the password is
never accepted as an argument, environment variable, file or chat message; it
only travels from the masked window over a pipe the parent process owns, and it
is dropped as soon as the key is installed.
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import bootstrap_ssh_key as core  # noqa: E402  (path bootstrap above)

CHANNEL_ENV = "SSH_PASSWORDLESS_CHANNEL"
CHANNEL_VALUE = "gui-pipe-v1"
MANAGED_PREFIX = "config.sshpl."
DIALOG_SCRIPT = SCRIPT_DIR / "password_dialog.py"
SETTINGS_FILE = Path.home() / ".ssh" / "ssh-passwordless.json"
SKILL_VERSION = "1.0.0"

STAGE_LABELS = {
    "validate": "参数校验",
    "keygen": "生成专用密钥",
    "credential": "等待输入密码",
    "connect": "密码登录服务器",
    "hostkey": "校验主机指纹",
    "install": "写入远端公钥",
    "config": "写入本地 SSH 配置",
    "verify": "免密登录复核",
}

STAGE_HINTS = {
    "validate": "主机/用户名/端口格式不合法，检查后重试。",
    "keygen": "本机 ssh-keygen 不可用，或目标密钥路径已存在但不成对。",
    "credential": "密码窗口被取消，或当前会话无法安全收集密码。",
    "connect": "密码错误、账号被限制，或服务器未开放密码登录。",
    "hostkey": "主机指纹未确认或与 known_hosts 记录不一致；确认服务器指纹后再试。",
    "install": "远端 ~/.ssh 权限、磁盘或 SFTP posix-rename 扩展不支持。",
    "config": "本地 ~/.ssh/config 解析失败或别名已被非托管条目占用。",
    "verify": "公钥认证复核失败，请查看上面的 stderr 明细。",
}


# --------------------------------------------------------------------------- #
# terminal output
# --------------------------------------------------------------------------- #
def say(message: str = "") -> None:
    print(message, flush=True)


def step(index: int, total: int, text: str) -> None:
    say(f"[{index}/{total}] {text}")


def warn(message: str) -> None:
    print(f"  ! {message}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# password acquisition
# --------------------------------------------------------------------------- #
def _has_inprocess_tk() -> bool:
    return importlib.util.find_spec("tkinter") is not None


def _interpreter_has_tk(executable: str) -> bool:
    try:
        result = subprocess.run(
            [executable, "-c", "import tkinter"],
            capture_output=True, timeout=20, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def find_gui_interpreter(explicit: Optional[str] = None) -> Optional[str]:
    """Return a Python executable that can open the Tk window, if any."""
    if explicit:
        return explicit if _interpreter_has_tk(explicit) else None
    candidates = [sys.executable]
    for name in ("python", "python3"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    if os.name == "nt":
        roots = [Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Python",
                 Path("C:/Program Files")]
        for root in roots:
            if not root.is_dir():
                continue
            for child in sorted(root.glob("Python3*"), reverse=True):
                candidates.append(str(child / "python.exe"))
    launcher = shutil.which("py")
    if launcher:
        candidates.append(launcher)
    seen = set()
    for candidate in candidates:
        key = os.path.normcase(os.path.abspath(candidate))
        if key in seen or not Path(candidate).exists():
            continue
        seen.add(key)
        if _interpreter_has_tk(candidate):
            return candidate
    return None


def _dialog_via_subprocess(executable: str, prefill: dict, alias: str, error: str) -> dict:
    environment = os.environ.copy()
    environment[CHANNEL_ENV] = CHANNEL_VALUE
    environment["PYTHONIOENCODING"] = "utf-8"
    command = [
        executable, str(DIALOG_SCRIPT),
        "--host", str(prefill.get("host", "")),
        "--user", str(prefill.get("user", "")),
        "--port", str(prefill.get("port", 22)),
        "--alias", alias or "",
        "--probe-python", sys.executable,
        "--probe-script", str(Path(__file__).resolve()),
    ]
    if error:
        command += ["--error", error]
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                encoding="utf-8", env=environment, check=False)
    except (OSError, subprocess.SubprocessError) as failure:
        raise core.BootstrapStageError("credential", f"cannot open the connection window: {failure}")
    if result.returncode == 3:
        raise core.BootstrapStageError("credential", "connection window was cancelled")
    if result.returncode != 0:
        detail = (result.stderr or "").strip().splitlines()
        raise core.BootstrapStageError(
            "credential",
            detail[-1] if detail else "the connection window failed to open",
        )
    lines = [line for line in (result.stdout or "").splitlines() if line.strip()]
    if not lines:
        raise core.BootstrapStageError("credential", "connection window returned no data")
    try:
        payload = json.loads(lines[-1])
    except json.JSONDecodeError as failure:
        raise core.BootstrapStageError("credential", f"connection window returned invalid data: {failure}")
    if not isinstance(payload, dict):
        raise core.BootstrapStageError("credential", "connection window returned invalid data")
    return payload


def collect_credentials(args, *, error: str = "", prefill: Optional[dict] = None):
    """Collect host / port / user / password and return (target, password).

    Every value comes from the masked window so the user can correct a typo in
    the address without restarting. The password never leaves this function.
    """
    prefill = dict(prefill or {})
    if args.port is not None:
        prefill["port"] = args.port
    if args.host:
        prefill["host"] = args.host
    if args.user:
        prefill["user"] = args.user
    prefill.setdefault("port", 22)

    if args.terminal:
        if not args.host or not args.user:
            raise SystemExit("--terminal 模式必须同时给出 --host 与 --user（密码不接受命令行参数）。")
        target = core.validate_target(args.host, args.user, args.alias, args.port or 22)
        if sys.stdin is None or not sys.stdin.isatty():
            raise core.BootstrapStageError("credential", "当前会话没有交互终端，无法隐藏输入密码。")
        password = getpass.getpass(f"{target.user}@{target.host} 的 SSH 密码（不回显）：")
        if not password:
            raise core.BootstrapStageError("credential", "empty password")
        return target, password, None

    payload = None
    has_tk = _has_inprocess_tk()
    interpreter = None if has_tk else find_gui_interpreter(args.gui_python)
    if has_tk:
        import password_dialog  # local sibling module

        try:
            payload = password_dialog.run_dialog(
                str(prefill.get("host", "")), str(prefill.get("user", "")),
                prefill.get("port", 22), args.alias or "", error, "配置 SSH 免密登录",
                probe_python=sys.executable, probe_script=str(Path(__file__).resolve()),
            )
        except Exception as failure:  # noqa: BLE001 - report as a stage error
            raise core.BootstrapStageError("credential", f"connection window failed: {failure}")
        if payload is None:
            raise core.BootstrapStageError("credential", "connection window was cancelled")
    elif interpreter:
        payload = _dialog_via_subprocess(interpreter, prefill, args.alias, error)
    else:
        warn("没有找到带 tcl/tk 的 Python，改用终端隐藏输入（地址与用户名必须由参数给出）。")
        if not (args.host and args.user):
            raise core.BootstrapStageError(
                "credential",
                "没有图形界面时需要在命令行给出 --host 与 --user，然后在终端输入密码。",
            )
        if sys.stdin is None or not sys.stdin.isatty():
            raise core.BootstrapStageError(
                "credential",
                "当前会话既没有图形界面也没有交互终端；请在本地终端运行，"
                "或安装带 tcl/tk 的官方 Python 后重试。",
            )
        target = core.validate_target(args.host, args.user, args.alias, args.port or 22)
        password = getpass.getpass(f"{target.user}@{target.host} 的 SSH 密码（不回显）：")
        if not password:
            raise core.BootstrapStageError("credential", "empty password")
        return target, password, None

    try:
        target = core.validate_target(
            payload.get("host"), payload.get("user"), args.alias, payload.get("port", 22)
        )
    except (ValueError, TypeError) as bad:
        raise core.BootstrapStageError("validate", f"填写的主机/用户名/端口不合法：{bad}")
    password = str(payload.get("password") or "")
    if not password:
        raise core.BootstrapStageError("credential", "empty password")
    accept_host_key = str(payload.get("accept_host_key") or "").strip() or None
    return target, password, accept_host_key


def remember_target(target) -> None:
    """Persist only the non-secret parts so the next window is prefilled."""
    try:
        SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        SETTINGS_FILE.write_text(
            json.dumps({"host": target.host, "user": target.user, "port": target.port},
                       ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError:
        pass


def last_target() -> dict:
    try:
        data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def default_paths(args) -> tuple[Path, Path]:
    raw_known = getattr(args, "known_hosts", None)
    raw_config = getattr(args, "ssh_config", None)
    known_hosts = Path(raw_known) if raw_known else Path.home() / ".ssh" / "known_hosts"
    ssh_config = Path(raw_config) if raw_config else Path.home() / ".ssh" / "config"
    return known_hosts, ssh_config


def key_path_for(target, explicit: Optional[str]) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    return Path.home() / ".ssh" / f"sshpl_{target.target_id}"


def managed_config_path(ssh_config: Path, target) -> Path:
    return ssh_config.expanduser().with_name(f"{MANAGED_PREFIX}{target.target_id}")


def parse_managed_entries(path: Path) -> dict:
    entry: dict = {}
    if not path.exists():
        return entry
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(" ")
        key = key.strip().lower()
        value = value.strip()
        if key == "host":
            entry["alias"] = value
        elif key == "hostname":
            entry["host"] = value
        elif key == "user":
            entry["user"] = value
        elif key == "port":
            entry["port"] = value
        elif key == "identityfile":
            entry["identity_file"] = value
    return entry


MIRRORS = (
    ("清华 TUNA", "https://pypi.tuna.tsinghua.edu.cn/simple", "pypi.tuna.tsinghua.edu.cn"),
    ("阿里云", "https://mirrors.aliyun.com/pypi/simple", "mirrors.aliyun.com"),
    ("腾讯云", "https://mirrors.cloud.tencent.com/pypi/simple", "mirrors.cloud.tencent.com"),
    ("中科大 USTC", "https://mirrors.ustc.edu.cn/pypi/simple", "mirrors.ustc.edu.cn"),
    ("官方 PyPI", "https://pypi.org/simple", "pypi.org"),
)


def missing_dependencies() -> list:
    missing = []
    for name in ("paramiko", "cryptography"):
        if importlib.util.find_spec(name) is None:
            missing.append(name)
    return missing


def install_dependencies(packages=None, *, quiet: bool = False) -> int:
    """Install missing runtime packages, preferring domestic mirrors."""
    packages = packages or missing_dependencies()
    if not packages:
        say("依赖已齐备，无需安装。")
        return 0
    say(f"准备安装：{', '.join(packages)}（优先使用国内镜像）")
    for label, url, host in MIRRORS:
        command = [
            sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
            "--no-input", "-i", url, f"--trusted-host={host}", *packages,
        ]
        say(f"  尝试 {label} · {url}")
        result = subprocess.run(command, check=False)
        if result.returncode == 0:
            say(f"  安装完成（{label}）。")
            return 0
        warn(f"{label} 安装失败（退出码 {result.returncode}），换下一个镜像。")
    say("所有镜像都失败了。请检查网络或代理，然后手动执行：")
    say(f'  "{sys.executable}" -m pip install -i {MIRRORS[0][1]} {" ".join(packages)}')
    return 1


def require_runtime() -> None:
    missing = missing_dependencies()
    if missing:
        raise SystemExit(
            "缺少 Python 依赖：" + ", ".join(missing) + "\n"
            f'一键安装（自动选国内镜像）： "{sys.executable}" -m pip install '
            f'-i {MIRRORS[0][1]} {" ".join(missing)}\n'
            f'也可以直接运行： "{sys.executable}" "{Path(__file__).resolve()}" doctor --install'
        )
    if not (shutil.which("ssh-keygen") and shutil.which("ssh")):
        raise SystemExit("未找到 OpenSSH 客户端（ssh / ssh-keygen），请先安装并加入 PATH。")


def observe_host_key(host: str, port: int, timeout: float = 15.0) -> tuple:
    """Connect at transport level only and return (algorithm, blob) of the host key.

    Nothing is authenticated and nothing is written; the caller decides whether
    the fingerprint is acceptable before any password leaves the process.
    """
    import paramiko

    transport = paramiko.Transport((host, port))
    try:
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        return key.get_name(), key.get_base64()
    finally:
        with contextlib.suppress(BaseException):
            transport.close()


def probe_connection(host: str, user: str, port: int, password: str,
                     known_hosts: Path) -> dict:
    """Check reachability, host-key trust and password auth without changing anything."""
    import paramiko

    target = core.validate_target(host, user, None, port)
    endpoint = core.format_known_hosts_endpoint(target.host, target.port)
    existing = known_hosts.read_bytes() if known_hosts.exists() else b""
    records = list(core._known_host_records(existing, endpoint))
    if any(marker == "@revoked" for marker, _a, _b in records):
        return {"ok": False, "known": False, "host_key": "",
                "message": "该主机在 known_hosts 中被标记为 @revoked，已停止。"}
    try:
        algorithm, blob = observe_host_key(target.host, target.port)
    except Exception as error:  # noqa: BLE001 - reachability failures are expected here
        return {"ok": False, "known": False, "host_key": "",
                "message": f"连不上 {target.host}:{target.port}（网络、端口或防火墙）：{error}"}
    fingerprint = core.sha256_fingerprint(blob)
    pinned = [(a, b) for marker, a, b in records if marker is None]
    if pinned:
        if any((a, b) == (algorithm, blob) for a, b in pinned):
            known = True
        else:
            return {"ok": False, "known": False, "host_key": fingerprint,
                    "message": f"主机指纹与 known_hosts 记录不一致（服务器返回 {fingerprint}），"
                               "可能是重装或中间人，已停止。"}
    else:
        known = False

    class PinnedPolicy(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, _client, _hostname, key):
            if (key.get_name(), key.get_base64()) != (algorithm, blob):
                raise paramiko.SSHException("host key changed during the probe")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(PinnedPolicy())
    try:
        client.connect(
            hostname=target.host, port=target.port, username=target.user,
            password=password, allow_agent=False, look_for_keys=False,
            timeout=15, banner_timeout=15, auth_timeout=15, channel_timeout=15,
        )
        _stdin, stdout, _stderr = client.exec_command("hostname; id -u", timeout=15)
        stdout.channel.recv_exit_status()
        lines = [line.strip() for line in stdout.read().decode("utf-8", "replace").splitlines()]
    except paramiko.AuthenticationException:
        return {"ok": False, "known": known, "host_key": fingerprint,
                "message": "密码错误，或该账号不允许密码登录（PasswordAuthentication no）。"}
    except Exception as error:  # noqa: BLE001
        return {"ok": False, "known": known, "host_key": fingerprint,
                "message": f"登录失败：{core.redact_sensitive(error, secrets=(password,))}"}
    finally:
        with contextlib.suppress(BaseException):
            client.close()

    hostname = lines[0] if lines else target.host
    uid = lines[1] if len(lines) > 1 else "?"
    return {
        "ok": True,
        "known": known,
        "host_key": fingerprint,
        "message": f"连接正常 · 主机名 {hostname} · uid {uid}"
                   + ("" if known else " · 首次连接，指纹待确认"),
    }


def command_probe(args) -> int:
    """Handle a probe request coming from the connection window (stdin JSON)."""
    if os.environ.get(CHANNEL_ENV) != CHANNEL_VALUE:
        print(json.dumps({"ok": False, "message": "probe requires the owned pipe"}, ensure_ascii=False))
        return 2
    raw = sys.stdin.readline() if sys.stdin else ""
    try:
        payload = json.loads(raw or "{}")
    except json.JSONDecodeError:
        print(json.dumps({"ok": False, "message": "invalid probe payload"}, ensure_ascii=False))
        return 2
    known_hosts = Path.home() / ".ssh" / "known_hosts"
    try:
        result = probe_connection(
            str(payload.get("host", "")), str(payload.get("user", "")),
            int(payload.get("port", 22)), str(payload.get("password", "")), known_hosts,
        )
    except core.BootstrapStageError as error:
        result = {"ok": False, "known": False, "host_key": "", "message": str(error)}
    except (ValueError, TypeError) as error:
        result = {"ok": False, "known": False, "host_key": "", "message": f"连接信息不合法：{error}"}
    print(json.dumps(result, ensure_ascii=False))
    return 0


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def command_setup(args) -> int:
    require_runtime()
    total = 5
    error_hint = ""
    prefill = last_target()
    attempt = 0

    while True:
        attempt += 1
        try:
            target, password, accept_host_key = collect_credentials(
                args, error=error_hint, prefill=prefill)
        except core.BootstrapStageError as error:
            return report_failure(error)

        known_hosts, ssh_config = default_paths(args)
        key_path = key_path_for(target, args.key_path)
        remember_target(target)

        say(f"目标      : {target.user}@{target.host}:{target.port}")
        say(f"别名      : {target.alias}")
        say(f"专用密钥  : {key_path}")
        say(f"known_hosts: {known_hosts}")
        pinned = args.expected_host_key_sha256 or accept_host_key
        if accept_host_key and not args.expected_host_key_sha256:
            say(f"主机指纹  : {accept_host_key}（窗口内已确认）")
        say()

        def read_password() -> str:
            # The window already collected it; this hands the value to the core
            # once and never asks the user to retype anything in the same run.
            return password

        def choose_identity(path, validated):
            step(1, total, "生成 / 复用专用 Ed25519 密钥")
            identity = core.choose_or_create_identity(path, validated)
            say(f"      {'新建' if identity.created else '复用'} {identity.private_path}")
            say(f"      指纹 {identity.fingerprint}")
            return identity

        def connect(validated, secret, known, fingerprint):
            step(2, total, "用密码登录并确认主机指纹")
            return core.connect_with_password(validated, secret, known, fingerprint)

        def install(client, public_key):
            step(3, total, "把公钥写入远端 authorized_keys")
            return core._install_via_client(client, public_key)

        def write_config(config_path, validated, identity_file):
            step(4, total, "写入本地托管 SSH 配置")
            return core.write_target_config(config_path, validated, identity_file)

        def validate_config(config_path, validated, identity_file):
            core.validate_written_config(config_path, validated, identity_file)
            say(f"      已通过 ssh -G 校验：{managed_config_path(Path(config_path), validated)}")

        def verify(validated, private_key, known):
            step(5, total, "复核免密登录（不使用密码）")
            return core.verify_direct_ssh(validated, private_key, known)

        dependencies = {
            "choose_identity": choose_identity,
            "read_password": read_password,
            "connect": connect,
            "install": install,
            "write_config": write_config,
            "validate_config": validate_config,
            "verify": verify,
        }

        try:
            core.bootstrap_target(
                target, key_path, known_hosts, ssh_config,
                pinned, dependencies=dependencies,
            )
            break
        except core.BootstrapStageError as error:
            password = ""
            retryable = (
                error.stage in ("connect", "credential")
                and attempt < 2
                and not args.terminal
                and "cancel" not in str(error).lower()
            )
            if retryable:
                warn(core.redact_sensitive(error))
                error_hint = "上次登录失败（密码错误或该账号不允许密码登录），请核对后重新填写。"
                prefill = {"host": target.host, "user": target.user, "port": target.port}
                say()
                continue
            return report_failure(error)

    say()
    say("完成：这台服务器已经可以免密登录。")
    say(f"  直接连接 : ssh {target.alias}")
    say(f"  复核命令 : python \"{Path(__file__).resolve()}\" verify --host {target.host} "
        f"--user {target.user} --port {target.port} --alias {target.alias}")
    say("  说明     : 密码没有被保存；删除时移除该密钥与托管配置即可。")
    return 0


def report_failure(error: core.BootstrapStageError) -> int:
    stage = getattr(error, "stage", "verify")
    detail = str(error) or "未知错误"
    if stage != "credential":
        warn(detail)
    else:
        say(detail)
    hint = STAGE_HINTS.get(stage)
    if hint:
        say(f"失败阶段: {STAGE_LABELS.get(stage, stage)}（{stage}）")
        say(f"处理建议: {hint}")
    return core._STAGE_EXIT_CODES.get(stage, 1)


def command_verify(args) -> int:
    require_runtime()
    target = core.validate_target(args.host, args.user, args.alias, args.port)
    known_hosts, ssh_config = default_paths(args)
    key_path = key_path_for(target, args.key_path)
    managed = managed_config_path(ssh_config, target)
    ok = True

    if not managed.exists():
        say(f"未找到托管配置：{managed}")
        say("这台目标还没有配置过，先运行 setup。")
        return 2
    if not key_path.exists():
        say(f"未找到专用密钥：{key_path}")
        return 3

    try:
        core.validate_written_config(managed, target, key_path)
        say(f"[1/3] ssh -G 解析正确：{target.alias} → {target.host}:{target.port}")
    except Exception as error:  # noqa: BLE001 - report every failure verbatim
        say(f"[1/3] ssh -G 校验失败：{core.redact_sensitive(error)}")
        ok = False

    if core.verify_direct_ssh(target, key_path, known_hosts):
        say("[2/3] 指定密钥直连成功（已禁用 agent / 密码 / 键盘交互）")
    else:
        say("[2/3] 指定密钥直连失败")
        ok = False

    try:
        result = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
             "-o", "IdentitiesOnly=yes", target.alias, "hostname; whoami; id -u"],
            capture_output=True, text=True, timeout=20, check=False,
        )
        if result.returncode == 0:
            hostname, _, rest = result.stdout.strip().partition("\n")
            say(f"[3/3] 别名登录成功：{hostname} / {rest.replace(chr(10), ' / ')}")
        else:
            say(f"[3/3] 别名登录失败：{result.stderr.strip()}")
            ok = False
    except (OSError, subprocess.SubprocessError) as error:
        say(f"[3/3] 别名登录失败：{error}")
        ok = False

    say()
    say("结论: 免密可用" if ok else "结论: 未通过，请按上面的失败项排查")
    return 0 if ok else 1


def command_list(args) -> int:
    _, ssh_config = default_paths(args)
    ssh_config = ssh_config.expanduser()
    if not ssh_config.exists():
        say(f"{ssh_config} 不存在，还没有配置任何目标。")
        return 0
    pattern = re.compile(rf"^{re.escape(MANAGED_PREFIX)}")
    managed_files = sorted(
        path for path in ssh_config.parent.iterdir()
        if path.is_file() and pattern.match(path.name)
    )
    included = ssh_config.read_text(encoding="utf-8", errors="replace")
    if not managed_files:
        say("没有由本技能托管的目标。")
        return 0
    say(f"托管目标（共 {len(managed_files)} 个）：")
    for path in managed_files:
        entry = parse_managed_entries(path)
        alias = entry.get("alias", "?")
        host = entry.get("host", "?")
        user = entry.get("user", "?")
        port = entry.get("port", "22")
        linked = "已挂载" if path.name in included else "未挂载（config 中缺少 Include）"
        say(f"  - {alias:24s} {user}@{host}:{port}   {linked}")
        say(f"    密钥 {entry.get('identity_file', '?')}")
    return 0


def command_doctor(args) -> int:
    say(f"ssh-passwordless v{SKILL_VERSION}")
    say(f"Python            : {sys.version.split()[0]} ({sys.executable})")
    gui = find_gui_interpreter(args.gui_python)
    say(f"Tk 弹窗解释器     : {gui if gui else '未找到（可安装官方 Python 或加 --terminal）'}")
    say(f"paramiko          : {_module_version('paramiko')}")
    say(f"cryptography      : {_module_version('cryptography')}")
    say(f"ssh               : {_tool_version(['ssh', '-V'])}")
    say(f"ssh-keygen        : {'可用' if shutil.which('ssh-keygen') else '缺失'}")
    home = Path.home() / ".ssh"
    say(f"~/.ssh            : {'存在' if home.exists() else '不存在（首次运行会自动创建）'}")
    say()
    missing = missing_dependencies()
    if missing:
        if getattr(args, "install", False):
            return install_dependencies(missing)
        say("缺少依赖：" + ", ".join(missing) + "（优先用国内镜像安装）")
        say(f'  "{sys.executable}" -m pip install -i {MIRRORS[0][1]} {" ".join(missing)}')
        say("或让脚本自动挑镜像：")
        say(f'  "{sys.executable}" "{Path(__file__).resolve()}" doctor --install')
        return 1
    say("运行时齐备，可以执行 setup。")
    return 0


def _module_version(name: str) -> str:
    if importlib.util.find_spec(name) is None:
        return "缺失"
    try:
        module = importlib.import_module(name)
    except Exception:  # noqa: BLE001
        return "已安装但导入失败"
    return getattr(module, "__version__", "已安装")


def _tool_version(command: list, accept_stderr: bool = False) -> str:
    if not shutil.which(command[0]):
        return "缺失"
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        return "存在但无法执行"
    text = (result.stderr if accept_stderr else result.stdout) or result.stdout or result.stderr
    first = text.strip().splitlines()[0] if text.strip() else "可用"
    return first.strip()


# --------------------------------------------------------------------------- #
# selftest
# --------------------------------------------------------------------------- #
class _FakeAttributes:
    def __init__(self, mode, uid=1001):
        self.st_mode, self.st_uid = mode, uid


class _FakeSftp:
    """Minimal SFTP double used by the selftest (no network, no server)."""

    def __init__(self, existing: bytes = b""):
        import stat

        self.files = {"/home/deploy/.ssh/authorized_keys": existing}
        self.attrs = {
            "/home/deploy": _FakeAttributes(stat.S_IFDIR | 0o755),
            "/home/deploy/.ssh": _FakeAttributes(stat.S_IFDIR | 0o700),
            "/home/deploy/.ssh/authorized_keys": _FakeAttributes(stat.S_IFREG | 0o600),
        }
        self.renames = []
        self.channel = _NullChannel()

    def normalize(self, _path):
        return "/home/deploy"

    def lstat(self, path):
        if path not in self.attrs:
            raise IOError(2, "missing")
        return self.attrs[path]

    def mkdir(self, path, mode=0o777):
        if path in self.attrs:
            raise IOError(17, "exists")
        import stat

        self.attrs[path] = _FakeAttributes(stat.S_IFDIR | mode)

    def rmdir(self, path):
        self.attrs.pop(path, None)

    def chmod(self, path, mode):
        import stat

        self.attrs[path].st_mode = stat.S_IFMT(self.attrs[path].st_mode) | mode

    def read_bytes(self, path):
        return self.files[path]

    def write_exclusive(self, path, data, mode):
        import stat

        if path in self.files:
            raise IOError(17, "exists")
        self.files[path] = data
        self.attrs[path] = _FakeAttributes(stat.S_IFREG | mode)

    def posix_rename(self, source, destination):
        self.renames.append((source, destination))
        self.files[destination] = self.files.pop(source)
        self.attrs[destination] = self.attrs.pop(source)

    def remove(self, path):
        self.files.pop(path, None)
        self.attrs.pop(path, None)

    def get_channel(self):
        return self.channel

    def close(self):
        pass


class _NullChannel:
    def settimeout(self, _value):
        pass


def _ssh_wire_blob(material: bytes) -> str:
    import base64
    import struct

    algorithm = b"ssh-ed25519"
    wire = struct.pack(">I", len(algorithm)) + algorithm + struct.pack(">I", len(material)) + material
    return base64.b64encode(wire).decode("ascii")


def run_selftest() -> int:
    import contextlib
    import io
    import stat

    key_one = _ssh_wire_blob(b"A" * 32)
    key_two = _ssh_wire_blob(b"B" * 32)
    failures = []

    def check(name: str, condition, detail: str = "") -> None:
        if condition:
            say(f"  ✅ {name}")
        else:
            failures.append(name)
            say(f"  ❌ {name} {detail}")

    say("1) 参数校验与目标标识")
    target = core.validate_target("Example.COM", "root", "rakserver", "2222")
    check("主机名归一化", target.host == "example.com")
    check("端口解析", target.port == 2222)
    check("target_id 稳定", target.target_id == core.validate_target("example.com", "root", "rakserver", 2222).target_id)
    check("自动别名带 sshpl 前缀", core.validate_target("example.com", "root", None, 22).alias.startswith("sshpl-"))
    for bad in ("bad host", "*.example.com", "host?"):
        try:
            core.validate_target(bad, "root", "a", 22)
            check(f"拒绝非法主机 {bad!r}", False)
        except ValueError:
            check(f"拒绝非法主机 {bad!r}", True)

    say("2) authorized_keys 合并")
    existing = f'from="10.0.0.0/8" ssh-ed25519 {key_one} keep\n'.encode("utf-8")
    check("同密钥去重且不改动原字节", core.merge_authorized_key(existing, f"ssh-ed25519 {key_one} new") == existing)
    appended = core.merge_authorized_key(b"a-without-newline", f"ssh-ed25519 {key_two} added")
    check("追加时保留原内容并补换行", appended.startswith(b"a-without-newline\n"))
    try:
        core.merge_authorized_key(b"", f"# ssh-ed25519 {key_one} disabled")
        check("拒绝注释形态的候选密钥", False)
    except ValueError:
        check("拒绝注释形态的候选密钥", True)

    say("3) 托管 Include 与别名冲突")
    config_bytes = b"\xef\xbb\xbfHost old\r\n  User keep\r\n"
    updated = core.ensure_managed_include(config_bytes, r"C:\Users\me\.ssh\config.sshpl.demo")
    check("保留 BOM 与原字节", updated.startswith(config_bytes))
    check("写入 Include 并转成 / 分隔", b"Include C:/Users/me/.ssh/config.sshpl.demo" in updated)
    check("重复执行幂等", core.ensure_managed_include(updated, r"C:\Users\me\.ssh\config.sshpl.demo") == updated)
    check("别名冲突大小写不敏感", core.find_alias_conflicts(b"Host PROD-api\n", ["prod-API"]) == {"prod-API"})
    rendered = core.render_managed_config([
        {"alias": "b-host", "host": "h.example", "user": "root", "port": 22, "identity_file": "C:/k/b"},
        {"alias": "a-host", "host": "g.example", "user": "root", "port": 22, "identity_file": "C:/k/a"},
    ])
    check("渲染按别名排序", rendered.index(b"Host a-host") < rendered.index(b"Host b-host"))
    check("渲染禁用 agent 且限定密钥", b"IdentityAgent none" in rendered and b"IdentitiesOnly yes" in rendered)

    say("4) known_hosts 端点与指纹")
    endpoint = core.format_known_hosts_endpoint("Host.Example", 2222)
    check("非 22 端口加方括号", endpoint == "[host.example]:2222")
    check("IPv6 归一化", core.format_known_hosts_endpoint("2001:0db8::1", 22) == "2001:db8::1")
    fingerprint = core.sha256_fingerprint(key_one)
    check("指纹为 SHA256: 前缀", fingerprint.startswith("SHA256:"))
    try:
        core.verify_host_key_fingerprint(key_two, fingerprint)
        check("指纹不一致时拒绝", False)
    except core.HostKeyChangedError:
        check("指纹不一致时拒绝", True)

    say("5) 密码通道与脱敏")
    secret = "SENTINEL_SECRET_VALUE"
    sanitized = core.redact_sensitive(f"token={secret} Authorization: Bearer abc123", secrets=[secret])
    check("脱敏覆盖显式密钥", secret not in sanitized)
    check("脱敏覆盖 Bearer", "abc123" not in sanitized)
    try:
        core.read_password(io.StringIO("must-not-read\n"), {})
        check("管道无授权时拒绝读取密码", False)
    except core.BootstrapStageError:
        check("管道无授权时拒绝读取密码", True)
    check("授权管道可读取", core.read_password(
        io.StringIO("pipe-secret\n"), {CHANNEL_ENV: CHANNEL_VALUE}) == "pipe-secret")

    say("6) 远端安装（模拟 SFTP）")
    sftp = _FakeSftp(b"# keep\n")
    no_lock = contextlib.nullcontext
    install = core.install_authorized_key_sftp
    changed = install(sftp, 1001, f"ssh-ed25519 {key_one}", lock_factory=lambda _d: no_lock())
    check("首次安装写入并原子改名", changed and len(sftp.renames) == 1)
    again = install(sftp, 1001, f"ssh-ed25519 {key_one} changed", lock_factory=lambda _d: no_lock())
    check("重复安装幂等", again is False)
    check("保留原有条目", sftp.files["/home/deploy/.ssh/authorized_keys"].startswith(b"# keep\n"))
    unsafe = _FakeSftp(b"old\n")
    unsafe.attrs["/home/deploy/.ssh/authorized_keys"] = _FakeAttributes(stat.S_IFLNK | 0o777)
    try:
        install(unsafe, 1001, f"ssh-ed25519 {key_one}", lock_factory=lambda _d: no_lock())
        check("拒绝符号链接目标", False)
    except core.BootstrapStageError:
        check("拒绝符号链接目标", True)

    say("7) 配置路径命名")
    fake_target = core.validate_target("example.com", "root", "prod", 22)
    managed = managed_config_path(Path("/home/x/.ssh/config"), fake_target)
    check("托管配置名含 config.sshpl 前缀", managed.name == f"config.sshpl.{fake_target.target_id}")
    check("默认密钥名含 sshpl 前缀", key_path_for(fake_target, None).name == f"sshpl_{fake_target.target_id}")

    say()
    if failures:
        say(f"自检未通过：{len(failures)} 项失败 → {', '.join(failures)}")
        return 1
    say("自检全部通过（不联网、不触碰真实服务器）。")
    return 0


# --------------------------------------------------------------------------- #
# cli
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh_passwordless.py",
        description="用一次密码换长期免密：生成专用密钥、安装公钥、写好 SSH 别名。",
    )
    subparsers = parser.add_subparsers(dest="command")

    def add_shared_options(sub):
        sub.add_argument("--alias", default=None, help="本地 ssh 别名，省略则自动生成")
        sub.add_argument("--key-path", default=None, help="专用私钥路径，省略则 ~/.ssh/sshpl_<target_id>")
        sub.add_argument("--known-hosts", default=None, help="known_hosts 路径，默认 ~/.ssh/known_hosts")
        sub.add_argument("--ssh-config", default=None, help="ssh config 路径，默认 ~/.ssh/config")
        sub.add_argument("--expected-host-key-sha256", default=None,
                         help="未知主机必须先经可信渠道确认的 SHA256: 指纹")

    setup = subparsers.add_parser("setup", help="配置免密登录（连接信息可在弹窗里填）")
    setup.add_argument("--host", default="", help="服务器 IP 或域名（省略则在弹窗里填写）")
    setup.add_argument("--user", default="", help="登录用户名（省略则在弹窗里填写）")
    setup.add_argument("--port", type=int, default=None, help="SSH 端口，默认 22（省略则在弹窗里填）")
    add_shared_options(setup)
    setup.add_argument("--terminal", action="store_true",
                       help="不使用弹窗，改在终端隐藏输入（需同时给出 --host 与 --user）")
    setup.add_argument("--gui-python", default=None, help="指定带 tcl/tk 的 Python 解释器")
    setup.set_defaults(func=command_setup)

    verify = subparsers.add_parser("verify", help="复核免密状态（不需要密码）")
    verify.add_argument("--host", required=True)
    verify.add_argument("--user", required=True)
    verify.add_argument("--port", type=int, default=22)
    add_shared_options(verify)
    verify.set_defaults(func=command_verify)

    listing = subparsers.add_parser("list", help="列出本技能托管的目标")
    listing.add_argument("--ssh-config", default=None)
    listing.set_defaults(func=command_list)

    doctor = subparsers.add_parser("doctor", help="检查本地运行时")
    doctor.add_argument("--gui-python", default=None)
    doctor.add_argument("--install", action="store_true",
                        help="缺少依赖时自动安装（依次尝试清华/阿里云/腾讯云/中科大镜像）")
    doctor.set_defaults(func=command_doctor)

    probe = subparsers.add_parser("probe", help="（内部）测试连接，凭据从标准输入读取")
    probe.set_defaults(func=command_probe)

    selftest = subparsers.add_parser("selftest", help="运行内置自检")
    selftest.set_defaults(func=lambda _args: run_selftest())

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
