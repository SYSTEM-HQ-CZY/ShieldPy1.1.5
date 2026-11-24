# -*- coding: utf-8 -*-
"""勒索防护页（v1.1.0）：System Watcher 行为评分 + 快照备份 + 一键回滚。"""
from tkinter import filedialog, messagebox

import customtkinter as ctk

from core.config import config
from core.protected import protected
from core.snapshot import snapshot
from core.systemwatcher import watcher

from .ctk_base import BRAND, DANGER, BasePage, Card, make_tree, tok


class RansomwarePage(BasePage):
    title = "勒索防护"
    subtitle = "System Watcher 加权评分 · 防勒索快照 · 手动回滚"

    def build(self):
        root = self.content
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(1, weight=1)

        # ---- 顶部：评分状态 + 快照操作 ----
        top = Card(root, height=132)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        top.grid_columnconfigure(0, weight=1)

        self.lbl_score = ctk.CTkLabel(
            top, text="System Watcher 评分：0", anchor="w",
            font=ctk.CTkFont(size=15, weight="bold"), text_color=BRAND)
        self.lbl_score.grid(row=0, column=0, sticky="w", padx=16, pady=(14, 2))
        self.lbl_detail = ctk.CTkLabel(top, text="", anchor="w",
                                       font=ctk.CTkFont(size=11),
                                       text_color=tok("dim"))
        self.lbl_detail.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 8))

        row = ctk.CTkFrame(top, fg_color="transparent")
        row.grid(row=2, column=0, sticky="ew", padx=16, pady=(2, 14))
        ctk.CTkButton(row, text="立即创建快照", width=130, height=32,
                      corner_radius=8, fg_color=BRAND,
                      command=self._snapshot).grid(row=0, column=0, padx=(0, 8))
        ctk.CTkButton(row, text="回滚选中快照", width=130, height=32,
                      corner_radius=8, fg_color=tok("card2"),
                      command=self._rollback).grid(row=0, column=1, padx=8)
        ctk.CTkButton(row, text="删除选中快照", width=130, height=32,
                      corner_radius=8, fg_color=tok("card2"),
                      command=self._delete_snap).grid(row=0, column=2, padx=8)
        ctk.CTkButton(row, text="受保护文件夹…", width=140, height=32,
                      corner_radius=8, fg_color=tok("card2"),
                      command=self._manage_folders).grid(row=0, column=3, padx=8)
        self.lbl_folder = ctk.CTkLabel(row, text="", anchor="e",
                                       font=ctk.CTkFont(size=11),
                                       text_color=tok("dim"))
        self.lbl_folder.grid(row=0, column=4, sticky="e", padx=(12, 0))
        row.grid_columnconfigure(4, weight=1)

        # ---- 快照列表 ----
        tree = make_tree(root, ["创建时间", "标签", "文件数", "体积", "目录"],
                         widths=[150, 220, 80, 100, 520], height=10)
        tree._frame.grid(row=1, column=0, sticky="nsew")
        self.tree = tree._frame
        self.tree.grid_propagate(False)
        self.tt = tree
        self._snaps = {}

        self.refresh()

    # ---------- 动作 ----------
    def _snapshot(self):
        res = snapshot.create(
            label="手动快照",
            max_file_mb=config.get_int("snapshot_max_file_mb", 20),
            max_total_mb=config.get_int("snapshot_max_total_mb", 500))
        if res.get("ok"):
            messagebox.showinfo("快照完成", f"{res.get('msg')}\n"
                                           f"大小 {res.get('bytes', 0) / 1024 / 1024:.1f} MB")
        else:
            messagebox.showerror("快照失败", res.get("msg", ""))
        self.refresh()

    def _rollback(self):
        sel = self.tt.selection()
        if not sel:
            messagebox.showinfo("提示", "请选择要回滚的快照")
            return
        sid = self._snaps.get(sel[0])
        if not sid:
            return
        if not messagebox.askyesno(
                "确认回滚",
                "回滚会用快照内容覆盖当前被篡改/加密的文件。\n"
                "被覆盖前的内容会另存为 rollback_backup 以便取证。\n\n继续？"):
            return
        res = snapshot.rollback(sid, keep_bad=True)
        messagebox.showinfo("回滚完成", res.get("msg", ""))
        self.refresh()

    def _delete_snap(self):
        sel = self.tt.selection()
        if not sel:
            messagebox.showinfo("提示", "请选择要删除的快照")
            return
        sid = self._snaps.get(sel[0])
        if not sid or not messagebox.askyesno("确认", f"删除快照 {sid}？"):
            return
        ok, msg = snapshot.delete_snapshot(sid)
        if not ok:
            messagebox.showerror("失败", msg)
        self.refresh()

    def _manage_folders(self):
        win = ctk.CTkToplevel(self)
        win.title("受保护文件夹")
        win.geometry("640x460")
        win.configure(fg_color=tok("bg"))
        win.transient(self.winfo_toplevel())

        ctk.CTkLabel(win, text="受保护文件夹（受控文件夹访问）",
                     font=ctk.CTkFont(size=15, weight="bold")).pack(
            anchor="w", padx=16, pady=(14, 4))
        ctk.CTkLabel(
            win, text=f"判定规则：{protected.window_sec} 秒内同一目录发生 "
                      f"{protected.threshold} 次以上文件操作 → 判定批量篡改，弹窗告警。\n"
                      f"只拦截文件操作并告警，不结束进程、不隔离程序。",
            font=ctk.CTkFont(size=11), text_color=tok("dim"),
            justify="left", wraplength=580).pack(anchor="w", padx=16, pady=(0, 8))

        box = ctk.CTkScrollableFrame(win, fg_color=tok("card"), corner_radius=10)
        box.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        def render():
            for w in box.winfo_children():
                w.destroy()
            if not protected.folders:
                ctk.CTkLabel(box, text="（暂无受保护文件夹）",
                             text_color=tok("dim")).pack(anchor="w", padx=10, pady=10)
            for f in protected.folders:
                r = ctk.CTkFrame(box, fg_color="transparent")
                r.pack(fill="x", pady=2)
                ctk.CTkLabel(r, text=f, anchor="w", font=ctk.CTkFont(size=11)).pack(
                    side="left", padx=8)
                ctk.CTkButton(r, text="移除", width=60, height=24, corner_radius=6,
                              fg_color=tok("card2"),
                              command=lambda p=f: (protected.remove_folder(p), render())).pack(
                    side="right", padx=6)

        def add():
            d = filedialog.askdirectory(title="选择要保护的文件夹")
            if d:
                protected.add_folder(d)
                render()

        btns = ctk.CTkFrame(win, fg_color="transparent")
        btns.pack(fill="x", padx=16, pady=(0, 14))
        ctk.CTkButton(btns, text="添加文件夹", width=110, height=30, corner_radius=8,
                      fg_color=BRAND, command=add).pack(side="left")
        ctk.CTkButton(btns, text="关闭", width=80, height=30, corner_radius=8,
                      fg_color=tok("card2"), command=win.destroy).pack(side="right")
        render()

    # ---------- 刷新 ----------
    def refresh(self):
        try:
            top_score = 0
            for a in watcher.recent_alerts(1):
                top_score = a.get("score", 0)
            self.lbl_score.configure(
                text=f"System Watcher 评分：{top_score} / 阈值 {watcher.threshold}",
                text_color=DANGER if top_score >= watcher.threshold else BRAND)
            self.lbl_detail.configure(
                text=f"采样事件 {len(watcher.events)} · 高危告警 {len(watcher.alerts)} · "
                     f"受保护文件夹 {len(protected.folders)} 个 · "
                     f"批量告警 {len(protected.alerts)} 次 · "
                     f"自动快照 {'开' if config.get('snapshot_enabled', True) else '关'}")
            self.lbl_folder.configure(text=f"快照目录 {snapshot.stats().get('dir')}")

            for i in self.tt.get_children():
                self.tt.delete(i)
            self._snaps = {}
            for s in snapshot.list_snapshots():
                iid = self.tt.insert("", "end", values=(
                    s.get("created"), s.get("label"),
                    s.get("count"), f"{s.get('bytes', 0) / 1024 / 1024:.1f} MB",
                    "; ".join(s.get("folders", [])[:2])))
                self._snaps[iid] = s.get("id")
        except Exception:
            pass

    def on_show(self):
        self.refresh()
