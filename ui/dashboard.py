# -*- coding: utf-8 -*-
"""仪表盘：防护状态 + 统计卡片 + 模块概览 + 最近事件。"""
import customtkinter as ctk

from core import __version__ as CORE_VER
from core.config import config
from core.monitor import monitor
from core.quarantine import quarantine
from core.trust import trust
from core.lockdown import lockdown
from core.snapshot import snapshot
from core.scanner import engine as scan_engine, fixed_drives, removable_drives

from .ctk_base import BRAND, DANGER, CORNER, BasePage, Card, tok

MODULE_LABELS = {
    "file_av": "文件反病毒",
    "network": "反网络攻击",
    "system_watcher": "System Watcher",
    "protected": "受控文件夹",
    "ransomware": "勒索防护",
    "advanced_clear": "高级清除",
}


class DashboardPage(BasePage):
    title = "仪表盘"
    subtitle = "防护状态总览"

    def build(self):
        root = self.content
        root.grid_columnconfigure((0, 1), weight=1, uniform="col")
        root.grid_rowconfigure(2, weight=1)

        # ---- 状态卡 ----
        self.hero = Card(root, height=150)
        self.hero.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        self.hero.grid_columnconfigure(0, weight=1)

        head = ctk.CTkFrame(self.hero, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=18, pady=(16, 4))
        head.grid_columnconfigure(0, weight=1)
        self.lbl_state = ctk.CTkLabel(head, text="● 实时防护启动中",
                                      font=ctk.CTkFont(size=22, weight="bold"),
                                      text_color=BRAND, anchor="w")
        self.lbl_state.grid(row=0, column=0, sticky="w")
        self.lbl_scope = ctk.CTkLabel(head, text="", anchor="w",
                                      font=ctk.CTkFont(size=11), text_color=tok("dim"))
        self.lbl_scope.grid(row=1, column=0, sticky="w", pady=(2, 0))

        btns = ctk.CTkFrame(self.hero, fg_color="transparent")
        btns.grid(row=1, column=0, sticky="ew", padx=18, pady=(4, 14))
        ctk.CTkButton(btns, text="快速扫描", width=110, height=34, corner_radius=8,
                      fg_color=BRAND, hover_color="#0b8760",
                      command=lambda: self._scan("quick")).grid(row=0, column=0, padx=(0, 8))
        ctk.CTkButton(btns, text="全盘扫描", width=110, height=34, corner_radius=8,
                      fg_color=tok("card2"), command=lambda: self._scan("full")).grid(
            row=0, column=1, padx=8)
        ctk.CTkButton(btns, text="可移动驱动器", width=120, height=34, corner_radius=8,
                      fg_color=tok("card2"), command=lambda: self._scan("removable")).grid(
            row=0, column=2, padx=8)
        ctk.CTkButton(btns, text="后台低优先级扫描", width=140, height=34, corner_radius=8,
                      fg_color=tok("card2"), command=lambda: self._scan("background")).grid(
            row=0, column=3, padx=8)
        ctk.CTkButton(btns, text="创建快照", width=100, height=34, corner_radius=8,
                      fg_color=tok("card2"), command=self._snapshot).grid(
            row=0, column=4, padx=8)

        # ---- 统计卡 ----
        stats = ctk.CTkFrame(root, fg_color="transparent")
        stats.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        for i in range(5):
            stats.grid_columnconfigure(i, weight=1, uniform="st")
        self.stat_labels = {}
        for i, (key, label) in enumerate([
                ("sig", "病毒特征库"), ("trust", "信任项"),
                ("quar", "隔离区"), ("lock", "原地锁定"),
                ("snap", "防勒索快照")]):
            card = ctk.CTkFrame(stats, corner_radius=CORNER, fg_color=tok("card"),
                                height=84)
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 8, 0))
            card.grid_propagate(False)
            ctk.CTkLabel(card, text=label, font=ctk.CTkFont(size=10),
                         text_color=tok("dim")).pack(anchor="w", padx=14, pady=(12, 0))
            v = ctk.CTkLabel(card, text="0", font=ctk.CTkFont(size=20, weight="bold"))
            v.pack(anchor="w", padx=14)
            self.stat_labels[key] = v

        # ---- 模块状态 ----
        self.mod_card = Card(root, title="防护模块状态",
                             subtitle="对标卡巴斯基模块分组")
        self.mod_card.grid(row=2, column=0, sticky="nsew", padx=(0, 5))
        self.mod_body = ctk.CTkFrame(self.mod_card.body, fg_color="transparent")
        self.mod_body.pack(fill="both", expand=True, padx=4, pady=4)
        self.mod_rows = {}
        for i, (key, label) in enumerate(MODULE_LABELS.items()):
            rowf = ctk.CTkFrame(self.mod_body, fg_color="transparent")
            rowf.pack(fill="x", pady=3)
            dot = ctk.CTkLabel(rowf, text="●", width=18,
                               font=ctk.CTkFont(size=12), text_color=BRAND)
            dot.pack(side="left")
            ctk.CTkLabel(rowf, text=label, anchor="w",
                         font=ctk.CTkFont(size=12)).pack(side="left", padx=(2, 0))
            state = ctk.CTkLabel(rowf, text="", anchor="e",
                                 font=ctk.CTkFont(size=11), text_color=tok("dim"))
            state.pack(side="right")
            self.mod_rows[key] = (dot, state)

        # ---- 最近事件 ----
        self.ev_card = Card(root, title="最近防护事件", subtitle="实时防护 / System Watcher")
        self.ev_card.grid(row=2, column=1, sticky="nsew", padx=(5, 0))
        self.ev_box = ctk.CTkTextbox(self.ev_card.body, corner_radius=8,
                                     font=ctk.CTkFont(size=11), wrap="word",
                                     fg_color=tok("card2"), height=240)
        self.ev_box.pack(fill="both", expand=True, padx=2, pady=2)
        self.ev_box.configure(state="disabled")

        self.refresh()

    # ---------- 动作 ----------
    def _scan(self, mode):
        pages = getattr(self.app, "_pages", {})
        scan_page = pages.get("scan")
        if scan_page:
            self.app.show_page("scan")
            scan_page.start_mode(mode)
        else:
            from tkinter import messagebox
            messagebox.showinfo("提示", "扫描页尚未初始化")

    def _snapshot(self):
        res = snapshot.create(label="仪表盘手动快照",
                             max_file_mb=config.get_int("snapshot_max_file_mb", 20),
                             max_total_mb=config.get_int("snapshot_max_total_mb", 500))
        from tkinter import messagebox
        if res.get("ok"):
            messagebox.showinfo("快照完成", res.get("msg", "已完成"))
        else:
            messagebox.showerror("快照失败", res.get("msg", "失败"))

    def on_show(self):
        self.refresh()

    def refresh(self):
        try:
            st = monitor.status
            if st.get("paused"):
                self.lbl_state.configure(text="● 实时防护 已暂停", text_color="#e0a955")
            elif st.get("running"):
                self.lbl_state.configure(text="● 实时防护 运行中", text_color=BRAND)
            else:
                self.lbl_state.configure(text="● 实时防护 已停止", text_color=DANGER)
            scope = "全盘" if st.get("scope") == "full" else "自定义目录"
            self.lbl_scope.configure(
                text=f"{scope} · 监控 {len(st.get('dirs') or [])} 个位置 · "
                     f"引擎 {st.get('engine')} · 固定盘 {len(fixed_drives())} "
                     f"/ 可移动 {len(removable_drives())}")

            from core.signature import signature_db
            self.stat_labels["sig"].configure(text=str(len(getattr(signature_db, "entries", []) or [])))
            self.stat_labels["trust"].configure(text=str(trust.count))
            self.stat_labels["quar"].configure(text=str(quarantine.count))
            self.stat_labels["lock"].configure(text=str(lockdown.count))
            self.stat_labels["snap"].configure(text=str(len(snapshot.list_snapshots())))

            mods = config.get("modules_enabled") or {}
            for key, (dot, state) in self.mod_rows.items():
                on = bool(mods.get(key, False))
                if key == "advanced_clear":
                    on = on and config.get_bool("advanced_clear_ack", False)
                dot.configure(text_color=BRAND if on else tok("dim"))
                state.configure(text="已启用" if on else "未启用")

            lines = []
            for ev in monitor.recent(10):
                lines.append(f"[{ev.time}] {ev.title} — {ev.detail}")
            for a in monitor_status_alerts():
                lines.append(a)
            self.ev_box.configure(state="normal")
            self.ev_box.delete("1.0", "end")
            self.ev_box.insert("1.0", "\n".join(lines) if lines else "暂无事件")
            self.ev_box.configure(state="disabled")
        except Exception:
            pass


def monitor_status_alerts():
    """System Watcher 高危告警（列表文本）。"""
    try:
        from core.systemwatcher import watcher
        out = []
        for a in watcher.recent_alerts(5):
            out.append(f"[{a['time']}] ⚠ System Watcher 评分 {a['score']} — {a['msg']}")
        return out
    except Exception:
        return []
