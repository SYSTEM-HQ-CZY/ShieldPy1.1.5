# -*- coding: utf-8 -*-
"""玄盾卫士图形界面包（CustomTkinter 版）。"""
from .app import ShieldApp, run  # noqa: F401


def register_all(app):
    """创建全部页面并注册到主窗口（v1.1.5：扫描页为 scan_panel）。"""
    from .dashboard import DashboardPage
    from .scan_panel import ScanPanelPage
    from .quarantine_page import QuarantinePage
    from .lock_page import LockPage
    from .modules_page import ModulesPage
    from .defense_page import DefensePage
    from .ransomware_page import RansomwarePage
    from .process_page import ProcessPage
    from .log_page import LogPage
    from .settings_page import SettingsPage

    pages = {
        "dashboard": DashboardPage(app.body, app),
        "scan": ScanPanelPage(app.body, app),
        "quarantine": QuarantinePage(app.body, app),
        "lock": LockPage(app.body, app),
        "modules": ModulesPage(app.body, app),
        "defense": DefensePage(app.body, app),
        "ransomware": RansomwarePage(app.body, app),
        "process": ProcessPage(app.body, app),
        "log": LogPage(app.body, app),
        "settings": SettingsPage(app.body, app),
    }
    app.register_pages(pages)
    return pages
