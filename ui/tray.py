# -*- coding: utf-8 -*-
"""系统托盘（后台常驻）。

菜单：显示主界面 / 暂停·恢复实时防护 / 创建快照 / 退出。
图标优先使用打包内嵌的 installer/shield_icon.ico。
"""
import os
import threading

try:
    import pystray
    from PIL import Image
    HAS_TRAY = True
except Exception:
    pystray = None
    Image = None
    HAS_TRAY = False

from core import logger
from core.config import BASE_DIR

ICON_CANDIDATES = [
    os.path.join(str(BASE_DIR), "icon", "shield_icon.ico"),
    os.path.join(str(BASE_DIR), "installer", "shield_icon.ico"),
    os.path.join(str(BASE_DIR), "shield_icon.ico"),
    os.path.join(str(BASE_DIR), "data", "shield_icon.ico"),
]


def _load_icon():
    if not HAS_TRAY:
        return None
    for p in ICON_CANDIDATES:
        try:
            if os.path.isfile(p):
                return Image.open(p)
        except Exception:
            continue
    # 兜底：画一个纯色方块
    try:
        return Image.new("RGB", (64, 64), (13, 158, 110))
    except Exception:
        return None


class TrayIcon:
    def __init__(self, app):
        self.app = app
        self.icon = None
        self._image = None

    def _protection_label(self):
        try:
            from core.monitor import monitor
            return "恢复实时防护" if monitor.paused else "暂停实时防护"
        except Exception:
            return "暂停实时防护"

    def _build_menu(self):
        return pystray.Menu(
            pystray.MenuItem("显示主界面", self._on_show, default=True),
            pystray.MenuItem(lambda item: self._protection_label(),
                             self._on_toggle),
            pystray.MenuItem("创建防勒索快照", self._on_snapshot),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("退出玄盾卫士", self._on_quit),
        )

    def start(self):
        if not HAS_TRAY:
            return False
        self._image = _load_icon()
        try:
            self.icon = pystray.Icon("ShieldPy", self._image,
                                     f"玄盾卫士 v{self.app.version}",
                                     self._build_menu())
            threading.Thread(target=self.icon.run, daemon=True).start()
            return True
        except Exception as e:
            logger.warn(f"托盘图标创建失败: {e}")
            self.icon = None
            return False

    def stop(self):
        try:
            if self.icon:
                self.icon.stop()
        except Exception:
            pass
        self.icon = None

    # -------- 菜单动作（均需转回 Tk 主线程） --------
    def _ui(self, fn):
        try:
            self.app.after(0, fn)
        except Exception:
            pass

    def _on_show(self, icon=None, item=None):
        self._ui(self.app.show_from_tray)

    def _on_toggle(self, icon=None, item=None):
        self._ui(self.app.tray_toggle_protection)

    def _on_snapshot(self, icon=None, item=None):
        def do():
            try:
                from core.snapshot import snapshot
                snapshot.create(label="托盘手动快照")
                self.app._notify("已创建防勒索快照")
            except Exception as e:
                logger.warn(f"托盘快照失败: {e}")
        threading.Thread(target=do, daemon=True).start()

    def _on_quit(self, icon=None, item=None):
        self._ui(self.app.real_quit)
