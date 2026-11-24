# -*- coding: utf-8 -*-
"""兼容层（v1.1.5）。

按项目文件拆分要求，扫描页面已正式落在 **ui/scan_panel.py**
（ScanPanelPage：结果列表 + 复选框批量处置 + 卡巴式处置提示）。

本文件只保留旧类名别名，避免历史引用断裂；新代码请直接：

    from ui.scan_panel import ScanPanelPage
"""
from .scan_panel import ScanPage, ScanPanelPage  # noqa: F401
