# 排错手册

先跑 `python scripts/ssh_passwordless.py doctor` 看运行时，再按失败阶段对照下表。脚本的失败输出里一定带阶段名，用它定位最快。

## 运行时

| 现象 | 原因 | 处理 |
|---|---|---|
| `缺少 Python 依赖：paramiko` | 当前解释器没装 | `"<当前 python>" -m pip install paramiko cryptography` |
| `Tk 弹窗解释器: 未找到` | 该 Python 没带 tcl/tk | 装官方 Python（含 tcl/tk），或用 `--gui-python` 指定，或加 `--terminal` |
| `未找到 OpenSSH 客户端` | PATH 里没有 ssh / ssh-keygen | Windows 用「添加可选功能 → OpenSSH 客户端」；macOS/Linux 装 openssh-client |

## 测试连接按钮

窗口里的「测试连接」做三件事：TCP 到端口 → 读主机公钥算指纹 → 用密码认证并执行 `hostname; id -u`。三种结果：

- **✅ 连接正常 · 主机名 … · uid …**：说明网络、端口、账号密码全通，可以直接点「开始配置」。
- **✅ 端口与密码都通了，但这是首次连接**：下面会出现指纹与勾选框。先去可信渠道核对 `SHA256:`（云控制台、服务器上 `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`），一致再勾选。
- **❌ 连不上 / 密码错误 / 指纹不一致**：按提示改。指纹不一致是硬红线，不要绕。

## 按阶段

### validate（退出码 2）
主机名不允许空格、`*?[]` 等 Host 通配符；用户名不允许首字符是 `-`、不允许含 `@`；端口必须 1~65535。带 `: ` 的字符串会被判非法——只填地址本身。

### keygen（3）
- `a generic SSH identity cannot be reused or overwritten`：`--key-path` 指到了 `id_rsa` 这类通用密钥，换路径。
- `dedicated key pair is incomplete`：私钥在、公钥丢了（或反之）。确认无用后删掉该对文件再重跑。
- 密钥已存在但不配对：脚本拒绝覆盖，这是保护措施。

### connect（4）
密码错误、账号禁止密码登录（`PasswordAuthentication no`）、端口被防火墙挡、fail2ban 拉黑。先点「测试连接」确认能登录；服务端确实关闭了密码登录时，这条路走不通，改用服务器管理员预置公钥。

### hostkey（5）
- `unknown host requires --expected-host-key-sha256`：命令行模式下首次连接必须显式给指纹；图形界面走「测试连接 + 勾选」。
- `host key changed`：指纹变了。先在服务器上确认主机密钥是否被重装替换，再手工删 `known_hosts` 里的旧行，不要用脚本自动覆盖。
- `@revoked`：该主机被撤销信任，停下来查原因。

### install（6）
- `remote directory has an unexpected owner`：`~/.ssh` 属主不是登录用户（常见于 `sudo` 建目录）。`chown -R user:user ~/.ssh && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys`。
- `OpenSSH/Linux server with the posix-rename SFTP extension is required`：服务端 SFTP 不是 OpenSSH 实现（如某些 NAS / 精简版），本技能不写入；改用管理员预置。
- `remote authorized_keys live lock timed out`：另一个进程正在写，或残留锁目录。确认没有并发任务后，删掉远端 `~/.ssh/.ssh-passwordless.lock`。

### config（7）
- `SSH alias already exists outside the managed entry`：`~/.ssh/config` 里已有同名 `Host`。换个 `--alias`，或先手工清理那一段（脚本不会动非托管内容）。
- `ssh -G` 失败：`~/.ssh/config` 有语法错误。`ssh -G 任意别名` 手工复现，看它报哪一行。

### verify（8）
公钥认证复核失败。按顺序查：远端 `authorized_keys` 是否真有 `ssh-passwordless:<target_id>` 那一行、`~/.ssh` 权限、服务端是否限制 `AllowUsers` / `PubkeyAuthentication no`。用 `ssh -vvv -i <密钥> -o IdentitiesOnly=yes -p <端口> <用户>@<主机>` 看协商过程。

### credential（9）
窗口被关掉，或当前会话既无图形界面也无交互终端。装带 tcl/tk 的 Python，或在本地终端加 `--terminal` 运行。

## 配置之后仍然要密码？

1. `ssh -G <别名>` 是否解析出了正确的 `hostname / user / port / identityfile`？
2. 文件权限：私钥 600、`~/.ssh` 700；Windows 上私钥 ACL 应只含当前用户与 SYSTEM。
3. 是不是被 `~/.ssh/config` 里更靠前的 `Host *` 段覆盖了（`IdentityAgent`、`IdentitiesOnly`）？
4. `ssh -v <别名>` 看实际尝试了哪些身份文件——如果出现了别的密钥，说明 `IdentitiesOnly` 没生效。

## 自检

```bash
python scripts/ssh_passwordless.py selftest
```

31 项契约检查，覆盖参数校验、`authorized_keys` 合并去重、托管 `Include` 幂等、别名冲突、指纹计算、密码通道授权、SFTP 原子安装与符号链接拒绝、路径命名。全绿说明本地逻辑没坏，问题在环境或服务端。
