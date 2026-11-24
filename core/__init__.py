# -*- coding: utf-8 -*-
"""
ShieldPy 玄盾卫士 核心引擎包 · v1.1.5
对标卡巴斯基流程的用户态安全方案（无内核驱动，日常普通权限，高危操作按需 NSudo 提权）

模块索引：
  config        配置、白名单、路径（含 data 目录可写回退）
  engine        引擎层门面（扫描引擎 + 风险打分 + 处置逻辑统一入口）
  risk          风险加权打分（数字签名校验、日志基线白名单、阈值判定）
  logger        日志
  signature     特征库
  heuristics    启发式检测
  scanner       扫描引擎（快速/全盘/可移动/后台低优先级）
  trust         信任项（路径 + SHA256 双哈希，篡改失效）
  terminator    进程终止（含子进程树）
  pendmoves     占用文件重启删除（PendingFileRenameOperations）
  residue       启动项/服务/注册表残留清理
  nsudo         NSudo 提权（TrustedInstaller，仅在高级清除时调用）
  dispose       威胁处置链路（先杀进程 → 隔离/删除/高级清除）
  quarantine    隔离区
  lockdown      原地锁定（所有者+ACL，权限快照）
  protected     受保护文件夹（受控文件夹访问）
  systemwatcher System Watcher 行为采集中枢（加权风险打分）
  yara_engine   YARA 规则引擎
  olevba_engine Office 宏分析（olevba）
  snapshot      防勒索快照备份与回滚
  monitor       实时防护中枢
  process       进程体检
  report        扫描报告
"""
__version__ = "1.1.5"
__app_name__ = "玄盾卫士"
__app_name_en__ = "ShieldPy"
