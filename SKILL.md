---
name: ssh-passwordless
display_name: SSH 免密登录配置
display_name_en: SSH Passwordless Setup
description: Use when a user wants passwordless SSH to a Linux server, or asks to stop typing the SSH password every time. Generates a dedicated Ed25519 key per host, installs it over SFTP after one masked password prompt, then writes a managed SSH alias so ssh ALIAS works forever. Triggers: SSH 免密, 免密登录, 不用再输密码, passwordless, ssh-keygen, authorized_keys, 配置 SSH 密钥, ssh config 别名.
description_zh: 一次输入密码，之后 ssh 别名直接登录。自动生成每台服务器专用的 Ed25519 密钥、安装公钥并写好 SSH 别名，密码只走本地掩码弹窗，不保存、不进对话。
description_en: Turn one password prompt into permanent key-based SSH. Creates a dedicated Ed25519 key per server, installs the public key, and writes a managed SSH alias; the password only travels through a local masked window and is never stored.
category: development
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
version: 1.0.0
disable-model-invocation: false
user-invocable: true
author: 程迅科技
---

# SSH 免密登录配置

把「每次都要输密码」变成「一次配置、长期免密」。适用于标准 OpenSSH Linux 服务器（初始允许密码登录、支持 SFTP `posix-rename` 扩展）。

**不适用**：跳板机/堡垒机多跳、纯 2FA/MFA 登录、FIPS 受限主机、非标准 `AuthorizedKeysFile` 布局、Windows OpenSSH 服务端。遇到这些情况直接说明不适用，不要硬试。

## 铁律

1. **密码绝不进入对话、命令行参数、环境变量或任何文件。** 只能由用户在我们弹出的掩码窗口里输入；窗口由助手主动打开，**不要把命令丢给用户让他自己敲**。
2. **每台服务器一把专用密钥**，命名为 `~/.ssh/sshpl_<target_id>`；绝不复用或覆盖 `id_rsa`、`id_ed25519` 这类通用身份。
3. **信任锚是 known_hosts**。已有记录直接使用；未知主机必须先让用户通过可信渠道确认 `SHA256:` 指纹，再用 `--expected-host-key-sha256` 传入。指纹变更或 `@revoked` 一律停下，绝不自动覆盖。
4. **只追加、不覆盖远端**：`authorized_keys` 的无关条目必须保留，写入前加远端锁、写临时文件后原子改名，失败即回滚。
5. **不使用** `StrictHostKeyChecking=no`、`sshpass`、`plink -pw`，不关闭主机指纹校验。
6. 已有密钥仍可登录时走短路复用，不要无谓轮换。

## 执行流程

### 1. 先体检，缺依赖就用国内镜像装

```bash
python scripts/ssh_passwordless.py doctor
```

确认 `paramiko`、`cryptography`、`ssh`、`ssh-keygen` 与带 tcl/tk 的解释器都在位。缺依赖时**自动用国内镜像安装**，不要走默认 PyPI：

```bash
python scripts/ssh_passwordless.py doctor --install
```

脚本按「清华 TUNA → 阿里云 → 腾讯云 → 中科大 USTC → 官方 PyPI」顺序重试，任一成功即停。需要手工装时也用镜像：

```bash
"<当前 python>" -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple paramiko cryptography
```

**不要**因为缺依赖就改用密码登录或别的降级方案。

### 2. 收集目标信息

必须拿到：主机（IP 或域名）、用户名。可选：端口（默认 22）、别名（缺省自动生成为 `sshpl-<hash>`）、已有指纹。**缺主机或用户名就问，不要猜。**

### 3. 助手主动开弹窗：填连接信息 → 测试连接 → 开始配置

先说明会发生什么（例如「我给你弹一个窗口，填地址、端口、用户名、密码，点测试连接通过后就开始配置」），再运行：

```bash
python scripts/ssh_passwordless.py setup --alias <alias>
```

窗口里是**四个输入框**：

| 字段 | 说明 |
|---|---|
| 服务器地址 | IP 或域名，不要写 `ssh://` 前缀 |
| 端口 | 默认 22，可改 |
| 用户名 | 如 `root` / `ubuntu` |
| 密码 | 掩码显示，可「粘贴」或点「显示明文」核对；仅本次使用、不保存 |

地址/端口/用户名可以在命令行预填（`--host/--port/--user`），也可以留给用户在窗口里填；**密码永远只能在窗口里输入**。

窗口底部是「测试连接」+「开始配置」+「取消」：

1. 用户填完点 **测试连接**：脚本会做 TCP 探活 → 读主机公钥算 `SHA256:` 指纹 → 用密码认证并执行 `hostname; id -u`。
2. 结果显示 **✅ 连接正常 · 主机名 … · uid …** = 路径通、密码对，配置前提正常。
3. 首次连接的主机会显示指纹并要求勾选「我已通过可信渠道核对」——勾选后该指纹会作为本次安装的固定指纹，安装过程只接受这一个主机密钥。
4. 只有测试通过才能点 **开始配置**，否则会提示先测通；这就是「通了才配」的硬闸门。

要点：

- 弹窗是唯一收集密码的通道，窗口会阻塞到用户点「开始配置」或「取消」。
- 调用可能持续数十秒到数分钟：给足超时（例如 600000 ms），或用后台运行方式，**不要中途杀掉**。
- 用户取消会返回 `credential` 阶段错误；说明「已取消，没有做任何改动」，等他决定是否重试。
- 首次密码错误会自动重开一次窗口并提示原因；再失败就停下报告，不要连续重试。
- 无图形界面时才用 `--terminal`（需同时给 `--host` 与 `--user`），此时只能用终端隐藏输入，没有测试按钮。

脚本内部依次完成：生成或复用专用密钥 → 密码登录并核验主机指纹 → 追加公钥到远端 `authorized_keys` → 写入本地托管配置 `~/.ssh/config.sshpl_*` 并在 `~/.ssh/config` 里挂一段托管 `Include` → 用隔离配置做一次无密码复核。

### 4. 复核并交付

```bash
python scripts/ssh_passwordless.py verify --host <host> --user <user> --port <port> --alias <alias>
python scripts/ssh_passwordless.py list
```

`verify` 必须三项全过才算成功：`ssh -G <alias>` 解析出正确的 HostName/User/Port 且只用该专用密钥、隔离直连（禁用 agent 与密码）成功、`ssh <alias>` 免密登录返回同一台主机。任何一项失败都要如实报告失败，不要含糊成「应该可以了」。

交付时告诉用户：别名、密钥路径、托管配置路径，以及之后直接 `ssh <alias>` 即可。

## 常用参数

| 参数 | 说明 |
|---|---|
| `--host` | 服务器 IP 或域名；省略则在窗口里填 |
| `--user` | 登录用户名；省略则在窗口里填 |
| `--port` | SSH 端口，默认 22；省略则在窗口里填 |
| `--alias` | 本地别名，省略则自动生成 `sshpl-<hash>` |
| `--key-path` | 专用私钥路径，默认 `~/.ssh/sshpl_<target_id>` |
| `--expected-host-key-sha256` | 未知主机必填，用户已核对的 `SHA256:` 指纹 |
| `--known-hosts` / `--ssh-config` | 自定义路径，默认在 `~/.ssh/` |
| `--terminal` | 无图形界面时改在终端隐藏输入 |
| `--gui-python` | 指定带 tcl/tk 的解释器 |
| `doctor --install` | 缺依赖时按国内镜像顺序自动安装 |

## 退出码与排查

| 退出码 | 阶段 | 典型原因与处理 |
|---|---|---|
| 2 | validate | 主机/用户名/端口格式不合法，或缺少未知主机指纹 |
| 3 | keygen | `ssh-keygen` 不可用，或目标密钥已存在但公私钥不配对（人工确认后清理） |
| 4 | connect | 密码错误、账号禁止密码登录、端口或网络不通 |
| 5 | hostkey | 指纹未确认或与 known_hosts 不一致；确认后重试，绝不擅自覆盖记录 |
| 6 | install | 远端 `~/.ssh` 属主/权限异常、磁盘满，或服务端缺 SFTP `posix-rename` |
| 7 | config | 别名已被**非托管** Host 条目占用，或 `~/.ssh/config` 语法有误 |
| 8 | verify | 公钥认证复核失败，看 stderr 明细 |
| 9 | credential | 用户取消，或当前会话无法安全收集密码 |

排查看 @references/troubleshooting.md；机制与安全模型看 @references/how-it-works.md。

## 撤销

删除该目标的专用密钥与托管配置即可，例如 `~/.ssh/sshpl_<target_id>`、`~/.ssh/sshpl_<target_id>.pub`、`~/.ssh/config.sshpl_<target_id>`，并从远端 `authorized_keys` 移除对应那一行。需要时再提示用户：托管 `Include` 段落用于集中挂载，删除后其余目标不受影响。

## 子资源

- @references/how-it-works.md：阶段划分、安全模型、密码生命周期
- @references/troubleshooting.md：各阶段失败的具体命令与判据
- `python scripts/ssh_passwordless.py selftest`：31 项内置契约自检，不联网、不碰真实服务器
