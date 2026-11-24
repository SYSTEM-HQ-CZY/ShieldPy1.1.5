# -*- coding: utf-8 -*-
"""扫描面板（v1.1.5）：结果列表 + 复选框批量处置 + 卡巴式处置提示。

需求落点：
    · 需求 5：结果列表每条前置复选框；表头【全选/取消全选】支持三态
      （☐ 未选 / ◑ 半选 / ☑ 全选）；支持批量隔离、删除、加入信任、原地锁定；
      复选框与选中行高亮适配深/浅色主题。
    · 需求 3：处置顺序固定"先杀进程 → 再隔离"；杀进程后明确提示"进程已终止"；
      隔离/删除/高级清除的确认弹窗与结果弹窗都显示文件**完整路径**。

布局要点（继承 v1.0.55 修复）：
    * 整页 grid：表格占 row1（weight=1），处置栏固定 row2 —— 底部按钮永不被挤压
    * 进度条单调保护（_last_pct），不再回跳
"""
import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

from core import logger
from core.config import config
from core.dispose import dispose_file, LEVEL_LABELS
from core.scanner import (engine as scan_engine, SCAN_MODES, fixed_drives,
                          removable_drives)

from .ctk_base import BRAND, DANGER, BasePage, Card, make_tree, tok

SEV_LABEL = {"high": "高危", "medium": "中危", "low": "提示"}
SEV_COLOR = {"high": DANGER, "medium": "#e0a955", "low": "#8a8a8a"}

CHECK_ON = "☑"
CHECK_OFF = "☐"
CHECK_HALF = "◑"

COLUMNS = ["✓", "严重度", "评分", "检测引擎", "威胁名称", "文件路径"]
WIDTHS = [40, 66, 56, 118, 300, 460]


class ScanPanelPage(BasePage):
    title = "病毒扫描"
    subtitle = "快速 / 全盘 / 可移动驱动器 / 后台低优先级 · 支持勾选批量处置"

    # ---------------- 构建界面 ----------------
    def build(self):
        root = self.content
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(1, weight=1)

        # ---------- 模式栏 ----------
        top = Card(root, height=112)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        top.grid_columnconfigure(0, weight=1)

        modes = ctk.CTkFrame(top, fg_color="transparent")
        modes.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 4))
        self.btn_quick = ctk.CTkButton(modes, text="快速扫描", width=104, height=34,
                                      corner_radius=8, fg_color=BRAND,
                                      hover_color="#0b8760",
                                      command=lambda: self.start_mode("quick"))
        self.btn_quick.grid(row=0, column=0, padx=(0, 8))
        self.btn_full = ctk.CTkButton(modes, text="全盘扫描", width=104, height=34,
                                      corner_radius=8, fg_color=tok("card2"),
                                      command=lambda: self.start_mode("full"))
        self.btn_full.grid(row=0, column=1, padx=8)
        self.btn_removable = ctk.CTkButton(modes, text="可移动驱动器", width=120,
                                           height=34, corner_radius=8,
                                           fg_color=tok("card2"),
                                           command=lambda: self.start_mode("removable"))
        self.btn_removable.grid(row=0, column=2, padx=8)
        self.btn_bg = ctk.CTkButton(modes, text="后台低优先级", width=118, height=34,
                                    corner_radius=8, fg_color=tok("card2"),
                                    command=lambda: self.start_mode("background"))
        self.btn_bg.grid(row=0, column=3, padx=8)
        self.btn_custom = ctk.CTkButton(modes, text="自定义扫描", width=110, height=34,
                                        corner_radius=8, fg_color=tok("card2"),
                                        command=self._choose_dir)
        self.btn_custom.grid(row=0, column=4, padx=8)
        self.btn_stop = ctk.CTkButton(modes, text="停止", width=70, height=34,
                                      corner_radius=8, fg_color=DANGER,
                                      hover_color="#b84343", command=self._stop,
                                      state="disabled")
        self.btn_stop.grid(row=0, column=5, padx=(8, 0))

        self.lbl_path = ctk.CTkLabel(top, text="未选择路径 · 快速扫描将检查常用目录",
                                     anchor="w", font=ctk.CTkFont(size=11),
                                     text_color=tok("dim"))
        self.lbl_path.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 2))

        prow = ctk.CTkFrame(top, fg_color="transparent")
        prow.grid(row=2, column=0, sticky="ew", padx=16, pady=(2, 12))
        prow.grid_columnconfigure(0, weight=1)
        self.progress = ctk.CTkProgressBar(prow, height=10, corner_radius=5,
                                           progress_color=BRAND)
        self.progress.grid(row=0, column=0, sticky="ew")
        self.progress.set(0)
        self.lbl_prog = ctk.CTkLabel(prow, text="0%", width=64,
                                     font=ctk.CTkFont(size=11))
        self.lbl_prog.grid(row=0, column=1, padx=(10, 0))

        # ---------- 结果表 ----------
        tree = make_tree(root, COLUMNS, widths=WIDTHS, height=12)
        tree._frame.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        self.tree = tree._frame
        self.tree.grid_propagate(False)
        self.tt = tree

        # ---------- 底部处置栏（固定，永不被挤压）----------
        bottom = Card(root, height=104)
        bottom.grid(row=2, column=0, sticky="ew")
        bottom.grid_columnconfigure(0, weight=1)

        # 第一行：全选复选框 + 已选统计 + 处置档位
        drow = ctk.CTkFrame(bottom, fg_color="transparent")
        drow.grid(row=0, column=0, sticky="ew", padx=16, pady=(10, 2))

        self.btn_all = ctk.CTkButton(
            drow, text=f"{CHECK_OFF} 全选", width=132, height=28, corner_radius=8,
            fg_color=tok("card2"), hover_color=tok("card2"),
            font=ctk.CTkFont(size=12), command=self._toggle_all)
        self.btn_all.grid(row=0, column=0, padx=(0, 10))
        self.lbl_checked = ctk.CTkLabel(drow, text="已选 0 项",
                                        font=ctk.CTkFont(size=11),
                                        text_color=tok("dim"), width=90, anchor="w")
        self.lbl_checked.grid(row=0, column=1, padx=(0, 16))

        ctk.CTkLabel(drow, text="处置档位：", font=ctk.CTkFont(size=12)).grid(
            row=0, column=2, padx=(0, 6))
        self.level_menu = ctk.CTkOptionMenu(
            drow, values=["隔离（可恢复）", "删除", "高级清除（NSudo 提权）"],
            width=200, height=28, corner_radius=8, fg_color=tok("card2"),
            button_color=tok("card2"), command=self._on_level)
        self.level_menu.grid(row=0, column=3, padx=(0, 12))
        self.lbl_tip = ctk.CTkLabel(drow, text="", font=ctk.CTkFont(size=11),
                                    text_color=DANGER, anchor="w")
        self.lbl_tip.grid(row=0, column=4, sticky="w")
        drow.grid_columnconfigure(4, weight=1)

        # 第二行：批量操作按钮
        brow = ctk.CTkFrame(bottom, fg_color="transparent")
        brow.grid(row=1, column=0, sticky="ew", padx=16, pady=(6, 10))
        self.btn_quar = ctk.CTkButton(brow, text="批量隔离", width=104, height=32,
                                      corner_radius=8, fg_color=BRAND,
                                      command=lambda: self._dispose_selected("quarantine"))
        self.btn_quar.grid(row=0, column=0, padx=(0, 8))
        self.btn_del = ctk.CTkButton(brow, text="批量删除", width=104, height=32,
                                     corner_radius=8, fg_color=tok("card2"),
                                     command=lambda: self._dispose_selected("delete"))
        self.btn_del.grid(row=0, column=1, padx=8)
        self.btn_trust = ctk.CTkButton(brow, text="批量信任", width=104, height=32,
                                       corner_radius=8, fg_color=tok("card2"),
                                       command=self._trust_selected)
        self.btn_trust.grid(row=0, column=2, padx=8)
        self.btn_lock = ctk.CTkButton(brow, text="批量原地锁定", width=118, height=32,
                                      corner_radius=8, fg_color=tok("card2"),
                                      command=self._lock_selected)
        self.btn_lock.grid(row=0, column=3, padx=8)
        self.btn_report = ctk.CTkButton(brow, text="导出报告", width=96, height=32,
                                        corner_radius=8, fg_color=tok("card2"),
                                        command=self._export)
        self.btn_report.grid(row=0, column=4, padx=8)
        self.lbl_summary = ctk.CTkLabel(brow, text="未扫描", anchor="e",
                                        font=ctk.CTkFont(size=11),
                                        text_color=tok("dim"))
        self.lbl_summary.grid(row=0, column=5, sticky="e")
        brow.grid_columnconfigure(5, weight=1)

        # ---------- 状态 ----------
        self._q = queue.Queue()
        self._last_pct = 0.0
        self._custom_dirs = []
        self._scan_items = {}
        self._checked = set()
        self._running = False
        self._busy = False

        scan_engine.on_progress = self._cb_progress
        scan_engine.on_threat = self._cb_threat
        scan_engine.on_done = self._cb_done
        self.tt.bind("<Double-1>", self._open_location)
        self.tt.bind("<Button-1>", self._on_click)
        self.tt.bind("<space>", self._on_space)
        self._apply_check_style()
        self._sync_level_menu()
        self.after(120, self._drain)

    # ---------------- 深浅色适配 ----------------
    def _apply_check_style(self):
        """复选框列与"已勾选行"配色：深色主题用深绿，浅色主题用淡绿。"""
        try:
            light = ctk.get_appearance_mode() == "Light"
        except Exception:
            light = False
        if light:
            self._sel_bg, self._sel_fg = "#d3f0e4", "#075e42"
            self._chk_fg = "#0a7a59"
        else:
            self._sel_bg, self._sel_fg = "#123a2e", "#7fe0bb"
            self._chk_fg = "#38d39b"
        try:
            self.tt.tag_configure("checked", background=self._sel_bg,
                                  foreground=self._sel_fg)
            self.tt.tag_configure("high", foreground=DANGER)
            self.tt.tag_configure("medium", foreground="#e0a955")
            self.tt.tag_configure("low", foreground=tok("dim"))
        except Exception:
            pass

    def on_theme_changed(self):
        self._apply_check_style()
        self._refresh_check_state()

    # ---------------- 复选框逻辑 ----------------
    def _on_click(self, event):
        """点击第 1 列（✓）切换该行勾选；点击其他列交给 Treeview 默认选择。"""
        try:
            region = self.tt.identify("region", event.x, event.y)
            col = self.tt.identify_column(event.x)
            row = self.tt.identify_row(event.y)
        except Exception:
            return None
        if region == "cell" and col == "#1" and row:
            self._toggle_row(row)
            return "break"
        return None

    def _on_space(self, event):
        sel = self.tt.focus()
        if sel:
            self._toggle_row(sel)
        return "break"

    def _toggle_row(self, iid):
        if iid not in self._scan_items:
            return
        if iid in self._checked:
            self._checked.discard(iid)
        else:
            self._checked.add(iid)
        self._refresh_row_check(iid)
        self._refresh_check_state()

    def _toggle_all(self):
        ids = [i for i in self.tt.get_children() if i in self._scan_items]
        if not ids:
            return
        if len(self._checked) >= len(ids):
            self._checked.clear()
        else:
            self._checked = set(ids)
        for i in ids:
            self._refresh_row_check(i)
        self._refresh_check_state()

    def _refresh_row_check(self, iid):
        try:
            vals = list(self.tt.item(iid, "values"))
            if not vals:
                return
            vals[0] = CHECK_ON if iid in self._checked else CHECK_OFF
            tags = ("checked",) if iid in self._checked else ()
            sev = getattr(self._scan_items.get(iid), "severity", "")
            self.tt.item(iid, values=vals, tags=tags + ((sev,) if sev else ()))
        except Exception:
            pass

    def _refresh_check_state(self):
        total = len([i for i in self.tt.get_children() if i in self._scan_items])
        n = len(self._checked)
        if n == 0 or total == 0:
            label, state = "全选", CHECK_OFF
        elif n >= total:
            label, state = "取消全选", CHECK_ON
        else:
            label, state = "全选", CHECK_HALF
        try:
            self.btn_all.configure(text=f"{state} {label}")
            self.lbl_checked.configure(text=f"已选 {n} / {total} 项",
                                       text_color=tok("text") if n else tok("dim"))
        except Exception:
            pass

    def _checked_items(self):
        return [self._scan_items[i] for i in self.tt.get_children()
                if i in self._checked and i in self._scan_items]

    # ---------------- 扫描控制 ----------------
    def _sync_level_menu(self):
        level = str(config.get("dispose_level", "quarantine"))
        idx = {"quarantine": 0, "delete": 1, "advanced": 2}.get(level, 0)
        try:
            self.level_menu.set(["隔离（可恢复）", "删除",
                                 "高级清除（NSudo 提权）"][idx])
        except Exception:
            pass
        self._on_level(self.level_menu.get(), apply=False)

    def _on_level(self, value, apply=True):
        if value.startswith("高级"):
            if apply:
                config.set("dispose_level", "advanced")
            self.lbl_tip.configure(
                text="⚠ 高级清除会借 NSudo 获取 TrustedInstaller 权限，"
                     "可能被其他安全软件标记为风险工具，全程记录日志")
            try:
                self.level_menu.configure(text_color=DANGER)
            except Exception:
                pass
        elif value.startswith("删除"):
            if apply:
                config.set("dispose_level", "delete")
            self.lbl_tip.configure(text="删除：抹除源文件并清理启动项/服务残留")
            try:
                self.level_menu.configure(text_color=tok("text"))
            except Exception:
                pass
        else:
            if apply:
                config.set("dispose_level", "quarantine")
            self.lbl_tip.configure(text="隔离：文件移入隔离区，可随时恢复")
            try:
                self.level_menu.configure(text_color=tok("text"))
            except Exception:
                pass

    def start_mode(self, mode):
        if scan_engine.running:
            messagebox.showwarning("提示", "已有扫描正在进行，请先停止")
            return
        if mode == "quick":
            roots = config.get("quick_dirs", []) or []
            if not roots:
                messagebox.showwarning("提示", "快速扫描目录为空，请在设置中配置")
                return
        elif mode == "full":
            roots = fixed_drives()
        elif mode == "removable":
            roots = removable_drives()
            if not roots:
                messagebox.showinfo("提示", "当前没有可移动驱动器（U 盘/移动硬盘）")
                return
        elif mode == "background":
            roots = fixed_drives()
        elif mode == "custom":
            roots = self._custom_dirs
            if not roots:
                messagebox.showinfo("提示", "请先选择要扫描的目录")
                return
        else:
            roots = fixed_drives()

        if mode == "background":
            scan_engine.start_background_scan(roots)
        else:
            scan_engine.start_scan(roots, mode=mode)

        self._clear_results()
        self._last_pct = 0.0
        self.progress.set(0)
        self.lbl_prog.configure(text="0%")
        self._running = True
        self.btn_stop.configure(state="normal")
        self.lbl_path.configure(
            text=f"{SCAN_MODES.get(mode, mode)} · {len(roots)} 个位置："
                 f"{', '.join(roots[:3])}{' ...' if len(roots) > 3 else ''}")
        self.lbl_summary.configure(text="扫描进行中…")
        logger.info(f"开始{SCAN_MODES.get(mode, mode)}：{roots[:5]}")

    def _choose_dir(self):
        d = filedialog.askdirectory(title="选择要扫描的目录")
        if d:
            self._custom_dirs = [os.path.abspath(d)]
            self.lbl_path.configure(text=f"自定义扫描：{d}")
            self.start_mode("custom")

    def _stop(self):
        scan_engine.stop()
        self.lbl_summary.configure(text="正在停止…")

    # ---------------- 回调（工作线程 → 队列） ----------------
    def _cb_progress(self, done, total, path):
        self._q.put(("progress", done, total, path))

    def _cb_threat(self, item):
        self._q.put(("threat", item))

    def _cb_done(self, stats):
        self._q.put(("done", stats))

    def _drain(self):
        try:
            while True:
                msg = self._q.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    _, done, total, path = msg
                    pct = (done / total) if total else 0
                    if pct < self._last_pct:
                        pct = self._last_pct
                    self._last_pct = pct
                    self.progress.set(pct)
                    self.lbl_prog.configure(text=f"{int(pct * 100)}%")
                    self.lbl_summary.configure(
                        text=f"{done}/{total} 文件 · {os.path.basename(path or '')[:40]}")
                elif kind == "threat":
                    self._add_row(msg[1])
                elif kind == "done":
                    st = msg[1]
                    self._running = False
                    self.btn_stop.configure(state="disabled")
                    self.progress.set(1.0)
                    self.lbl_prog.configure(text="100%")
                    self.lbl_summary.configure(
                        text=f"完成：{st.get('scanned')} 文件，"
                             f"威胁 {st.get('threats')}，提示 {st.get('hints')}，"
                             f"耗时 {st.get('elapsed')}s")
                    if st.get("threats", 0):
                        messagebox.showwarning(
                            "扫描完成",
                            f"发现 {st.get('threats')} 个威胁、{st.get('hints')} 个提示。\n"
                            f"勾选复选框后可批量处置。")
        except queue.Empty:
            pass
        self.after(120, self._drain)

    # ---------------- 结果表 ----------------
    def _clear_results(self):
        for i in self.tt.get_children():
            self.tt.delete(i)
        self._scan_items = {}
        self._checked = set()
        self._refresh_check_state()

    def _add_row(self, item):
        sev = getattr(item, "severity", "medium")
        score = getattr(item, "score", 0)
        iid = self.tt.insert("", "end", values=(
            CHECK_OFF, SEV_LABEL.get(sev, sev), str(score) if score else "-",
            item.detection, item.threat, item.path))
        self._scan_items[iid] = item
        self._refresh_row_check(iid)
        self._refresh_check_state()

    def _selected_items(self):
        return [self._scan_items[i] for i in self.tt.selection()
                if i in self._scan_items]

    def _open_location(self, event):
        # 双击第 1 列交给勾选，其余列打开文件位置
        try:
            if self.tt.identify_column(event.x) == "#1":
                return
        except Exception:
            pass
        sel = self.tt.selection()
        if not sel:
            return
        it = self._scan_items.get(sel[0])
        if not it:
            return
        try:
            import subprocess
            subprocess.Popen(["explorer", "/select,", os.path.normpath(it.path)])
        except Exception:
            pass

    # ---------------- 外观辅助 ----------------
    def _path_block(self, items, limit=10):
        """确认弹窗用：逐条完整路径。"""
        lines = [f"· {getattr(it, 'path', it)}"
                 + (f"\n    {getattr(it, 'threat', '')[:90]}" if getattr(it, "threat", "") else "")
                 for it in items[:limit]]
        if len(items) > limit:
            lines.append(f"… 另有 {len(items) - limit} 个文件")
        return "\n".join(lines)

    def _notice_block(self, results):
        """结果弹窗用：逐条完整路径 + 处置结果，杀进程单独提示。"""
        total_killed = sum(getattr(r, "killed", 0) for r in results)
        lines = []
        if total_killed:
            lines.append(f"✔ 进程已终止：共 {total_killed} 个")
            for r in results:
                if getattr(r, "killed", 0):
                    names = "；".join(str(m) for m in (r.killed_msgs or [])[:3])
                    lines.append(f"    {r.path}")
                    if names:
                        lines.append(f"    └ {names}")
        else:
            lines.append("· 未发现占用进程，直接处置")
        lines.append("")
        for r in results[:10]:
            lines.append(f"{'✔' if getattr(r, 'ok', False) else '✘'} {r.path}")
            lines.append(f"    {r.msg}")
        if len(results) > 10:
            lines.append(f"… 另有 {len(results) - 10} 个文件")
        return "\n".join(lines)

    # ---------------- 处置（卡巴式：先杀进程再处置） ----------------
    def _dispose_selected(self, level):
        if self._busy:
            return
        items = self._checked_items()
        if not items:
            messagebox.showinfo("提示",
                                "请先勾选要处置的条目（点击每行最左侧的复选框，"
                                "或用底部【全选】）")
            return
        if level == "advanced" and not self._confirm_advanced(items):
            return
        if level == "delete":
            if not messagebox.askyesno(
                    "确认删除（不可恢复）",
                    f"将删除以下 {len(items)} 个文件的完整路径：\n\n"
                    f"{self._path_block(items)}\n\n"
                    "处理顺序：先终止占用进程 → 再删除源文件 → 清理启动项/服务残留。\n"
                    "删除后无法通过隔离区恢复，是否继续？"):
                return
        elif level == "quarantine":
            if not messagebox.askyesno(
                    "确认隔离",
                    f"将隔离以下 {len(items)} 个文件的完整路径：\n\n"
                    f"{self._path_block(items)}\n\n"
                    "处理顺序：先终止占用进程 → 再移入隔离区（可随时恢复）。\n"
                    "是否继续？"):
                return

        self._busy = True
        self.lbl_summary.configure(text=f"正在处置 {len(items)} 项…")

        def work():
            results = []
            for it in items:
                try:
                    res = dispose_file(it.path, level=level, threat=it.threat,
                                       detection=it.detection, md5=it.md5,
                                       sha256=it.sha256, size=it.size)
                    it.action = LEVEL_LABELS.get(level, level)
                    results.append(res)
                except Exception as e:
                    logger.error(f"处置失败 {it.path}: {e}")
            self.after(0, lambda: self._after_dispose(results, level))

        threading.Thread(target=work, daemon=True).start()

    def _confirm_advanced(self, items):
        if not config.get_bool("advanced_clear_ack", False):
            ok = messagebox.askyesno(
                "⚠ 高风险操作确认",
                "高级清除将借助 NSudo 获取 TrustedInstaller 权限强制删除文件。\n\n"
                "风险提示：\n"
                "  1. 需要管理员权限，且 NSudo 可能被其他安全软件标记为风险工具；\n"
                "  2. 提权删除无法回滚，删除前请确认文件确为威胁；\n"
                "  3. 全程操作会写入 data/advanced_clear.log 以便事后核对。\n\n"
                "是否继续执行高级清除？")
            if not ok:
                return False
            config.set("advanced_clear_ack", True)
        return messagebox.askyesno(
            "确认高级清除",
            f"将对以下 {len(items)} 个文件的完整路径执行高级清除：\n\n"
            f"{self._path_block(items)}\n\n"
            "顺序：先终止占用进程 → NSudo 提权删除 → 残留深度扫描。是否继续？")

    def _after_dispose(self, results, level):
        self._busy = False
        ok_n = sum(1 for r in results
                   if getattr(r, "ok", False) or getattr(r, "msg", "").startswith("已")
                   or getattr(r, "need_reboot", False))
        reboot = [r for r in results if getattr(r, "need_reboot", False)]
        body = self._notice_block(results)
        msg = f"处置完成：成功/已登记 {ok_n} / {len(results)}\n\n{body}"
        if reboot:
            msg += f"\n\n有 {len(reboot)} 个文件被占用，已登记重启后删除。"
        messagebox.showinfo(f"处置结果（{LEVEL_LABELS.get(level, level)}）", msg)

        disposed = [r.path for r in results]
        self._clear_results()
        for item in list(scan_engine.results):
            if item.path not in disposed:
                self._add_row(item)
        self.lbl_summary.configure(text=f"已处置 {len(results)} 项")

    def _trust_selected(self):
        items = self._checked_items()
        if not items:
            messagebox.showinfo("提示", "请先勾选要加入信任的条目")
            return
        if not messagebox.askyesno(
                "确认信任",
                f"将把以下 {len(items)} 个文件的路径 + SHA256 加入信任列表：\n\n"
                f"{self._path_block(items)}\n\n"
                "文件内容一旦被篡改，信任会自动失效。是否继续？"):
            return
        n = 0
        for it in items:
            ok, _ = trust.add(it.path, reason="扫描页手动信任")
            if ok:
                n += 1
        messagebox.showinfo("信任", f"已信任 {n} 个文件（路径+SHA256 双哈希）")
        for iid in list(self._checked):
            if iid in self._scan_items:
                self.tt.delete(iid)
                self._scan_items.pop(iid, None)
        self._checked.clear()
        self._refresh_check_state()

    def _lock_selected(self):
        items = self._checked_items()
        if not items:
            messagebox.showinfo("提示", "请先勾选要抽地锁定的条目")
            return
        from core.lockdown import lockdown
        n, fails = 0, []
        for it in items:
            ok, res = lockdown.lock(it.path)
            if ok:
                n += 1
            else:
                fails.append(f"{it.path}: {res}")
        msg = f"已原地锁定 {n} 个文件（所有者→System，ACL 拒绝普通用户执行）"
        if fails:
            msg += "\n\n未成功：\n" + "\n".join(fails[:5])
        messagebox.showinfo("原地锁定", msg)

    def _export(self):
        try:
            from core.report import export_report
            path = export_report(scan_engine.results, scan_engine.stats)
            messagebox.showinfo("报告", f"已导出：{path}")
        except Exception as e:
            messagebox.showerror("导出失败", str(e))

    def on_show(self):
        self._apply_check_style()

    def refresh(self):
        if not self._running and scan_engine.running:
            self._running = True
            self.btn_stop.configure(state="normal")


# 兼容别名（旧引用 ScanPage）
ScanPage = ScanPanelPage
