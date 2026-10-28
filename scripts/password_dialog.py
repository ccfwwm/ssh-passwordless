#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Connection window for the ssh-passwordless skill.

The window collects the whole target once: 服务器地址 / 端口 / 用户名 / 密码.
It is the only accepted way to collect the password, and it is a separate
program on purpose — the worker process can pick a Python build that ships
tcl/tk, while the secret only travels over a pipe the parent process owns.

Standalone usage (the parent sets SSH_PASSWORDLESS_CHANNEL=gui-pipe-v1):

    python scripts/password_dialog.py --host 203.0.113.10 --user root --port 2222

stdout carries exactly one JSON line:
    {"host": "...", "port": 2222, "user": "...", "password": "..."}
All progress/errors go to stderr, so a caller can pipe stdout straight into
its own credential reader.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading

CHANNEL_ENV = "SSH_PASSWORDLESS_CHANNEL"
CHANNEL_VALUE = "gui-pipe-v1"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SSH passwordless connection window")
    parser.add_argument("--host", default="")
    parser.add_argument("--user", default="")
    parser.add_argument("--port", default="22")
    parser.add_argument("--alias", default="")
    parser.add_argument("--error", default="", help="message shown under the form (e.g. a previous failure)")
    parser.add_argument("--title", default="配置 SSH 免密登录")
    parser.add_argument("--probe-python", default=None,
                        help="interpreter able to run the probe (needs paramiko)")
    parser.add_argument("--probe-script", default=None,
                        help="ssh_passwordless.py path used for the connection test")
    return parser


def run_dialog(host: str = "", user: str = "", port=22, alias: str = "",
               error: str = "", title: str = "配置 SSH 免密登录",
               probe_python: str = None, probe_script: str = None):
    """Show the window and return a dict, or None when the user cancels."""
    import tkinter as tk
    from tkinter import font as tkfont

    ui = {
        "bg": "#F5F5F7",
        "header_from": "#FFFFFF",
        "header_to": "#EFF6FF",
        "surface": "#FFFFFF",
        "field": "#FFFFFF",
        "text": "#111114",
        "muted": "#3C3C43",
        "faint": "#6E6E73",
        "accent": "#0071E3",
        "primary": "#0071E3",
        "primary_hover": "#0A84FF",
        "ghost": "#FFFFFF",
        "ghost_hover": "#F0F5FF",
        "danger": "#D70015",
        "success": "#0F8A45",
        "hairline": "#E1E1E6",
        "border": "#D8D8DE",
        "badge": "#0071E3",
        "focus": "#A9CDFF",
    }

    root = tk.Tk()
    available = set(tkfont.families(root))
    family = next(
        (name for name in ("Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC",
                           "Noto Sans CJK SC", "Segoe UI", "Helvetica")
         if name in available),
        "TkDefaultFont",
    )

    def F(size: int, weight: str = "normal") -> tuple:
        return (family, size, weight)

    def hex_to_rgb(value: str) -> tuple:
        return tuple(int(value[i:i + 2], 16) for i in (1, 3, 5))

    def rgb_to_hex(rgb) -> str:
        return "#%02x%02x%02x" % tuple(max(0, min(255, int(v))) for v in rgb)

    def draw_h_gradient(canvas, width: int, height: int, start: str, end: str) -> None:
        left, right = hex_to_rgb(start), hex_to_rgb(end)
        for x in range(width):
            t = x / max(1, width - 1)
            canvas.create_line(
                x, 0, x, height,
                fill=rgb_to_hex([left[i] + (right[i] - left[i]) * t for i in range(3)]),
            )

    def round_rect(canvas, x1: float, y1: float, x2: float, y2: float, r: float, **kwargs):
        r = max(2.0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
        points = [
            x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
            x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
        ]
        return canvas.create_polygon(points, smooth=True, **kwargs)

    class RoundButton(tk.Canvas):
        """Flat rounded button that still feels like a button on every Tk build."""

        def __init__(self, master, text, command, *, width, height, fill, hover, fg, font,
                     border=None, border_hover=None, radius=None, bg=None):
            super().__init__(master, width=width, height=height, bg=bg or ui["bg"],
                             highlightthickness=0, bd=0, takefocus=1, cursor="hand2")
            self._command = command
            self._fill, self._hover = fill, hover
            self._border = border or fill
            self._border_hover = border_hover or self._border
            radius = radius if radius is not None else height // 2
            self._shape = round_rect(self, 1, 1, width - 1, height - 1, radius,
                                     fill=fill, outline=self._border, width=1)
            self.create_text(width // 2, height // 2, text=text, fill=fg, font=font)
            self.bind("<Enter>", lambda _e: self._paint(self._hover, self._border_hover))
            self.bind("<Leave>", lambda _e: self._paint(self._fill, self._border))
            self.bind("<Button-1>", lambda _e: self._command())
            self.bind("<Return>", lambda _e: self._command())
            self.bind("<space>", lambda _e: self._command())

        def _paint(self, fill: str, border: str) -> None:
            self.itemconfigure(self._shape, fill=fill, outline=border)

    class Field:
        """Rounded input with an optional right-hand action chip."""

        def __init__(self, master, *, label, value="", width, masked=False,
                     chip=None, chip_command=None, hint="", label_action=None):
            self.masked = masked
            self.showing = not masked
            block = tk.Frame(master, bg=ui["bg"])
            block.pack(side="left")
            self.block = block
            label_row = tk.Frame(block, bg=ui["bg"])
            label_row.pack(fill="x")
            tk.Label(label_row, text=label, bg=ui["bg"], fg=ui["muted"], font=F(10),
                     anchor="w").pack(side="left")
            if label_action:
                action_text, action_command = label_action
                action = tk.Label(label_row, text=action_text, bg=ui["bg"], fg=ui["accent"],
                                  font=F(9), cursor="hand2")
                action.pack(side="right")
                action.bind("<Button-1>", lambda _e: action_command(self))
                self.action_label = action
            else:
                self.action_label = None
            canvas = tk.Canvas(block, width=width, height=48, bg=ui["bg"],
                               highlightthickness=0, bd=0)
            canvas.pack(fill="x", pady=(6, 0))
            self.canvas = canvas
            self.width = width
            self.shape = round_rect(canvas, 0, 0, width, 48, 11, fill=ui["field"],
                                    outline=ui["border"], width=1)
            entry = tk.Entry(canvas, bd=0, bg=ui["field"], fg=ui["text"],
                             insertbackground=ui["accent"],
                             show="●" if masked else "", font=F(12),
                             highlightthickness=0, relief="flat",
                             disabledbackground=ui["field"], disabledforeground=ui["faint"])
            self.entry = entry
            reserved = 84 if chip else 20
            canvas.create_window(16, 24, window=entry, anchor="w",
                                 width=width - reserved - 16, height=28)
            if value:
                entry.insert(0, str(value))
            if chip:
                self.chip_shape = round_rect(canvas, width - 76, 9, width - 10, 39, 15,
                                             fill="#F5F5F7", outline="#D8D8DE", width=1)
                self.chip_text = canvas.create_text(width - 43, 24, text=chip,
                                                    fill=ui["accent"], font=F(10))
                for item in (self.chip_shape, self.chip_text):
                    canvas.tag_bind(item, "<Button-1>", lambda _e: chip_command(self))
                    canvas.tag_bind(item, "<Enter>", lambda _e: canvas.configure(cursor="hand2"))
                    canvas.tag_bind(item, "<Leave>", lambda _e: canvas.configure(cursor=""))
            entry.bind("<FocusIn>", lambda _e: canvas.itemconfigure(self.shape, outline=ui["focus"]))
            entry.bind("<FocusOut>", lambda _e: canvas.itemconfigure(self.shape, outline=ui["border"]))
            if hint:
                tk.Label(block, text=hint, bg=ui["bg"], fg=ui["faint"], font=F(9),
                         anchor="w").pack(fill="x", pady=(4, 0))

        def get(self) -> str:
            return self.entry.get().strip()

        def focus(self) -> None:
            self.entry.focus_set()

        def toggle_mask(self) -> None:
            showing = self.entry.cget("show") == ""
            self.entry.configure(show="" if showing else "●")
            if self.action_label is not None:
                self.action_label.configure(text="隐藏明文" if showing else "显示明文")

    state = {"value": None}

    def on_close() -> None:
        root.destroy()

    def apply_windows_chrome() -> None:
        """Rounded corners on Windows 11 so the frame reads like a mac panel."""
        if os.name != "nt":
            return
        try:
            import ctypes

            hwnd = ctypes.windll.user32.GetParent(root.winfo_id()) or root.winfo_id()
            corner = ctypes.c_int(2)  # DWMWCP_ROUND
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 33, ctypes.byref(corner), ctypes.sizeof(corner)
            )
        except Exception:
            pass

    width_total = 700
    pad = 30

    root.configure(bg=ui["bg"])
    root.title(f"{title} · SSH Passwordless")
    root.attributes("-topmost", True)
    root.withdraw()  # avoid a default-size flash before the content-sized geometry lands

    header = tk.Canvas(root, width=width_total, height=110, bg=ui["header_from"],
                       highlightthickness=0, bd=0)
    header.pack(fill="x")
    draw_h_gradient(header, width_total, 110, ui["header_from"], ui["header_to"])
    round_rect(header, width_total - 232, 18, width_total - pad, 92, 14,
               fill="#F4F9FF", outline="#C7DEFF", width=1)
    header.create_text(width_total - 131, 42, text="一次配置 · 长期免密", fill=ui["accent"], font=F(15, "bold"))
    header.create_text(width_total - 131, 70, text="专用密钥留在本机，登录不再问密码", fill="#1D4E89", font=F(9))
    header.create_text(pad, 42, text="配置 SSH 免密登录", anchor="w", fill=ui["text"], font=F(17, "bold"))
    header.create_text(pad, 74, text="填好下面四项，密码只用于本次登录并安装公钥",
                       anchor="w", fill=ui["muted"], font=F(10))
    header.create_line(0, 109, width_total, 109, fill=ui["hairline"], width=1)

    body = tk.Frame(root, bg=ui["bg"])
    body.pack(fill="both", expand=True)
    tk.Frame(body, bg=ui["bg"], height=14).pack()

    tk.Label(body, text="连接信息 · 地址与用户名可在此直接修改", bg=ui["bg"], fg=ui["muted"],
             font=F(10), anchor="w").pack(fill="x", padx=pad, pady=(0, 9))

    form = tk.Frame(body, bg=ui["bg"])
    form.pack(fill="x", padx=pad)

    def paste_from_clipboard(field: Field) -> None:
        try:
            text = root.clipboard_get()
        except tk.TclError:
            set_status("剪贴板里没有文本。", ui["danger"])
            return
        field.entry.delete(0, tk.END)
        field.entry.insert(0, text.strip())
        field.focus()
        set_status("")

    row_one = tk.Frame(form, bg=ui["bg"])
    row_one.pack(fill="x")
    host_field = Field(row_one, label="服务器地址（IP 或域名）", value=host, width=420,
                       hint="不用写 ssh:// 前缀")
    host_field.block.pack(side="left")
    port_field = Field(row_one, label="端口", value=str(port), width=190, hint="默认 22")
    port_field.block.pack(side="left", padx=(18, 0))

    tk.Frame(form, bg=ui["bg"], height=14).pack()

    row_two = tk.Frame(form, bg=ui["bg"])
    row_two.pack(fill="x")
    user_field = Field(row_two, label="用户名", value=user, width=290, hint="如 root / ubuntu")
    user_field.block.pack(side="left")
    password_field = Field(row_two, label="密码", value="", width=320, masked=True,
                          chip="粘贴", chip_command=lambda field: paste_from_clipboard(field),
                          label_action=("显示明文", lambda field: field.toggle_mask()),
                          hint="仅本次使用，不保存")
    password_field.block.pack(side="left", padx=(18, 0))

    tk.Frame(body, bg=ui["bg"], height=16).pack()

    card = tk.Frame(body, bg=ui["surface"], highlightbackground=ui["hairline"], highlightthickness=1)
    card.pack(fill="x", padx=pad, pady=(0, 4))
    inner = tk.Frame(card, bg=ui["surface"])
    inner.pack(fill="x", padx=18, pady=12)

    def add_step(index: int, title_text: str, detail: str, last: bool = False) -> None:
        row = tk.Frame(inner, bg=ui["surface"])
        row.pack(fill="x")
        badge = tk.Canvas(row, width=26, height=26, bg=ui["surface"], highlightthickness=0, bd=0)
        badge.pack(side="left", anchor="n")
        badge.create_oval(0, 0, 26, 26, fill=ui["badge"], outline=ui["badge"])
        badge.create_text(13, 13, text=str(index), fill="#FFFFFF", font=F(10, "bold"))
        box = tk.Frame(row, bg=ui["surface"])
        box.pack(side="left", fill="x", expand=True, padx=(12, 0))
        tk.Label(box, text=title_text, bg=ui["surface"], fg=ui["text"], font=F(10, "bold"),
                 anchor="w").pack(fill="x")
        tk.Label(box, text=detail, bg=ui["surface"], fg=ui["muted"], font=F(9), anchor="w",
                 justify="left", wraplength=540).pack(fill="x", pady=(2, 0))
        if not last:
            tk.Frame(inner, bg=ui["hairline"], height=1).pack(fill="x", pady=(9, 9))

    add_step(1, "生成专用密钥", "只为这台服务器生成一把 Ed25519 密钥，复用时直接跳过")
    add_step(2, "登录并写入公钥", "追加到远端 authorized_keys，保留原有条目，原子替换")
    add_step(3, "写好本地别名", "写入托管 Include 配置，之后 ssh 别名 直接登录", last=True)

    trust_row = tk.Frame(body, bg=ui["bg"])
    trust_var = tk.BooleanVar(value=False)
    trust_label = tk.Label(trust_row, text="", bg=ui["bg"], fg=ui["muted"], font=F(9),
                           anchor="w", justify="left", wraplength=520)
    trust_check = tk.Checkbutton(
        trust_row, text="我已通过可信渠道核对，允许记录该指纹", variable=trust_var,
        bg=ui["bg"], fg=ui["text"], font=F(9), activebackground=ui["bg"],
        selectcolor=ui["surface"], bd=0, highlightthickness=0, anchor="w",
    )

    footer = tk.Frame(body, bg=ui["bg"])
    footer.pack(fill="x", padx=pad, pady=(10, 16))
    status_label = tk.Label(footer, text=error, bg=ui["bg"],
                            fg=ui["danger"] if error else ui["muted"], font=F(10),
                            anchor="w", justify="left", wraplength=width_total - 2 * pad)
    status_label.pack(fill="x", pady=(0, 10))
    button_row = tk.Frame(footer, bg=ui["bg"])
    button_row.pack(fill="x")
    root.protocol("WM_DELETE_WINDOW", on_close)

    def resize_to_fit() -> None:
        root.update_idletasks()
        width = max(width_total, root.winfo_reqwidth())
        height = max(root.winfo_reqheight(), root.winfo_height())
        x = root.winfo_x()
        y = root.winfo_y()
        root.geometry(f"{width}x{height}+{x}+{y}")

    def set_status(text: str, color=None) -> None:
        status_label.configure(text=text, fg=color or ui["muted"])
        resize_to_fit()

    state["probing"] = False
    state["probe_ok"] = False
    state["pending_fingerprint"] = ""

    def show_trust_row(fingerprint: str) -> None:
        trust_label.configure(text=f"首次连接该主机 · 指纹 {fingerprint}")
        trust_row.pack(fill="x", padx=pad, pady=(0, 8))
        trust_label.pack(fill="x")
        trust_check.pack(fill="x", pady=(2, 0))
        trust_var.set(False)
        root.update_idletasks()

    def hide_trust_row() -> None:
        trust_check.pack_forget()
        trust_label.pack_forget()
        trust_row.pack_forget()
        root.update_idletasks()

    def reset_probe(_event=None) -> None:
        if state["probing"]:
            return
        state["probe_ok"] = False
        state["pending_fingerprint"] = ""
        hide_trust_row()
        if status_label.cget("fg") == ui["success"]:
            set_status("", ui["muted"])

    for widget in (host_field.entry, port_field.entry, user_field.entry, password_field.entry):
        widget.bind("<KeyRelease>", reset_probe, add="+")

    def run_probe() -> None:
        if state["probing"] or probe_python is None or probe_script is None:
            return
        host_value = host_field.get()
        port_value = port_field.get()
        user_value = user_field.get()
        password_value = password_field.entry.get()
        if not host_value or not user_value or not password_value:
            set_status("先把地址、用户名、密码填全再测试。", ui["danger"])
            return
        if not port_value.isdigit() or not 1 <= int(port_value) <= 65535:
            set_status("端口必须是 1~65535 的整数。", ui["danger"])
            return
        state["probing"] = True
        state["probe_ok"] = False
        state["pending_fingerprint"] = ""
        hide_trust_row()
        set_status("正在测试连接…", ui["accent"])
        test_button.configure(cursor="watch")
        payload = json.dumps({
            "host": host_value, "port": int(port_value),
            "user": user_value, "password": password_value,
        })

        def worker() -> None:
            environment = os.environ.copy()
            environment[CHANNEL_ENV] = CHANNEL_VALUE
            environment["PYTHONIOENCODING"] = "utf-8"
            try:
                result = subprocess.run(
                    [probe_python, probe_script, "probe"],
                    input=payload + "\n", capture_output=True, text=True,
                    encoding="utf-8", env=environment, timeout=90, check=False,
                )
                lines = [line for line in (result.stdout or "").splitlines() if line.strip()]
                data = json.loads(lines[-1]) if lines else {"ok": False, "message": "测试没有返回结果"}
            except Exception as failure:  # noqa: BLE001 - surfaced in the window
                data = {"ok": False, "message": f"测试执行失败：{failure}"}
            root.after(0, lambda: finish_probe(data))

        threading.Thread(target=worker, daemon=True).start()

    def finish_probe(data: dict) -> None:
        state["probing"] = False
        test_button.configure(cursor="hand2")
        if not isinstance(data, dict):
            data = {"ok": False, "message": "测试返回格式异常"}
        if data.get("ok"):
            state["probe_ok"] = True
            if data.get("known"):
                set_status(f"✅ {data.get('message', '连接正常')}", ui["success"])
            else:
                fingerprint = str(data.get("host_key") or "")
                state["pending_fingerprint"] = fingerprint
                set_status("✅ 端口与密码都通了，但这是首次连接，需确认指纹。", ui["success"])
                show_trust_row(fingerprint)
        else:
            set_status(f"❌ {data.get('message', '连接失败')}", ui["danger"])
            hide_trust_row()

    def submit() -> None:
        host_value = host_field.get()
        port_value = port_field.get()
        user_value = user_field.get()
        password_value = password_field.entry.get()
        if not host_value:
            set_status("请填写服务器地址。", ui["danger"])
            host_field.focus()
            return
        if not port_value.isdigit() or not 1 <= int(port_value) <= 65535:
            set_status("端口必须是 1~65535 的整数。", ui["danger"])
            port_field.focus()
            return
        if not user_value:
            set_status("请填写用户名。", ui["danger"])
            user_field.focus()
            return
        if not password_value:
            set_status("请填写密码，或点「取消」退出。", ui["danger"])
            password_field.focus()
            return
        if probe_python is not None and probe_script is not None:
            if not state["probe_ok"]:
                set_status("请先点「测试连接」，通了再开始配置。", ui["danger"])
                return
            if state["pending_fingerprint"] and not trust_var.get():
                set_status("请先勾选确认该主机指纹。", ui["danger"])
                return
        state["value"] = {
            "host": host_value,
            "port": int(port_value),
            "user": user_value,
            "password": password_value,
        }
        if state["pending_fingerprint"] and trust_var.get():
            state["value"]["accept_host_key"] = state["pending_fingerprint"]
        password_field.entry.delete(0, tk.END)
        password_field.entry.configure(state="disabled")
        set_status("已收到连接信息，正在配置…", ui["success"])
        root.after(280, root.destroy)

    cancel_button = RoundButton(button_row, "取消", on_close, width=98, height=44,
                                fill=ui["ghost"], hover=ui["ghost_hover"], fg=ui["text"],
                                font=F(11), border=ui["border"], border_hover="#C4C4CB",
                                radius=10)
    cancel_button.pack(side="right")
    submit_button = RoundButton(button_row, "开始配置", submit, width=132, height=44,
                                fill=ui["primary"], hover=ui["primary_hover"], fg="#FFFFFF",
                                font=F(11, "bold"), radius=10)
    submit_button.pack(side="right", padx=(0, 10))
    test_button = RoundButton(button_row, "测试连接", run_probe, width=118, height=44,
                              fill="#EAF3FF", hover="#D8E9FF", fg="#0062CC",
                              font=F(11, "bold"), border="#A9CDFF", border_hover=ui["accent"],
                              radius=10)
    if probe_python is not None and probe_script is not None:
        test_button.pack(side="left")
    tk.Label(button_row, text="" if probe_python else "未启用连接测试", bg=ui["bg"],
             fg=ui["faint"], font=F(9)).pack(side="left", padx=(12, 0))

    def bring_to_front() -> None:
        try:
            root.deiconify()
            root.lift()
            root.attributes("-topmost", True)
            root.focus_force()
            root.grab_set()
        except tk.TclError:
            pass

    def finalize_layout() -> None:
        root.update_idletasks()
        width = max(width_total, root.winfo_reqwidth())
        height = root.winfo_reqheight()
        x = max(0, (root.winfo_screenwidth() - width) // 2)
        y = max(0, (root.winfo_screenheight() - height) // 3)
        root.geometry(f"{width}x{height}+{x}+{y}")
        root.resizable(False, False)
        root.minsize(width, height)
        root.deiconify()
        apply_windows_chrome()

    root.bind("<Return>", lambda _event: submit())
    root.bind("<Escape>", lambda _event: on_close())
    finalize_layout()
    root.after(150, bring_to_front)
    root.after(320, (host_field if not host else (port_field if not user else password_field)).focus)
    root.mainloop()
    return state["value"]


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    if os.environ.get(CHANNEL_ENV) != CHANNEL_VALUE:
        print(
            f"refusing to print credentials outside the owned pipe; set {CHANNEL_ENV}={CHANNEL_VALUE}",
            file=sys.stderr,
        )
        return 2
    try:
        value = run_dialog(args.host, args.user, args.port, args.alias, args.error,
                           args.title, args.probe_python, args.probe_script)
    except Exception as error:  # noqa: BLE001 - the parent turns this into a readable stage error
        print(f"dialog_error: {error}", file=sys.stderr)
        return 1
    if value is None:
        print("dialog_result: cancelled", file=sys.stderr)
        return 3
    print("dialog_result: submitted", file=sys.stderr)
    sys.stdout.write(json.dumps(value, ensure_ascii=False) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
