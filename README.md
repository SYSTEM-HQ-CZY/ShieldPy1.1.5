# 玄盾卫士 ShieldPy v1.1.5

纯 Python 实现的用户态杀毒软件（无内核驱动），对标卡巴斯基的查杀与处置流程。
v1.1.0 的全部功能保留；v1.1.5 修 5 个问题：**向导卡死、误报、处置顺序与提示、权限过重、结果面板无法批量勾选**。

---

## v1.1.5 更新要点（5 项修复 + 文件拆分）

### 需求 1 · 修复向导"点下一步黑屏卡死 / 按钮无响应 / 无法关闭"

**真实根因**（本轮实测定位，不是猜的）：向导里的 `CTkCheckBox` / `CTkRadioButton` 传了
`progress_color` 参数，而 customtkinter 6.0.0 的这两个控件**不支持该参数**，
构造时直接抛 `ValueError: ['progress_color'] are not supported arguments`。
于是每点一次"下一步"，`_render()` 在创建控件时崩溃 → 页面 body 已清空但新控件没建出来
→ 表现为**黑屏**，且导航按钮没恢复 → 表现为**无响应 / 关不掉**。

修复组合拳：
| 措施 | 说明 |
|---|---|
| 修参数 | 5 处控件改用 `fg_color` / `hover_color` / `checkmark_color`（正确参数） |
| 异步渲染 | 切步先画"⏳ 正在准备下一步…"占位，`after(50)` 再渲染，主循环不再被长任务堵死 |
| 超时兜底 | 同时挂 `after(700)` 强制渲染，即便前一个 `after` 被拖住也一定会出界面 |
| 异常兜底 | 渲染整体 try/except，出错显示"渲染出错页"（含错误详情 + 重试 + 关闭），不再是黑屏 |
| 防重入 | 切换期间禁用上一步/下一步，连点不会重复建控件 |
| 可关闭 | 标题栏 ✕、Esc、底部「关闭」三处出口；关闭即按当前/默认配置完成向导 |
| 不 transient | 向导不再做 `transient(主窗口)`——主窗口是 `overrideredirect` 无边框窗口，其 transient 子窗口部分系统上不绘制 |
| 耗时逻辑后台 | 「开始使用」时的防勒索快照创建放到 worker 线程，期间显示"正在创建快照…"，不卡界面 |

### 需求 2 · 修复误报（签名校验 + 日志基线 + 风险加权打分）

新增 `core/risk.py`（评分层），扫描引擎从**"命中即判定"**改为**"特征收集 → 加权打分 → 过阈值才判威胁"**。

特征权重（`WEIGHTS`）：

| 特征 | 分值 | 特征 | 分值 |
|---|---|---|---|
| 特征库哈希命中 | 100（强特征，直接判） | YARA 高/中/低 | 78 / 46 / 18 |
| 宏 高/中危 | 62 / 34 | 脚本启发式 高/中/低 | 55 / 28 / 12 |
| 加壳 高/中/低 | 42 / 20 / 8 | 高危扩展名 | 5 |
| 压缩包内容 | 6 | | |

减免项（`MITIGATIONS`）：有效数字签名 **-52**、已知厂商 -10、已知厂商版本信息 -10、
日志基线白名单 **-42**、小体积文本 -8、系统目录 -6。阈值 **60**（`>=85` 判高危）。

- **单特征不判恶意**：`risk_ext` 5 分、`heur_medium` 28 分单独出现只记"提示（low）"，不再弹病毒；
  仅"高危扩展名/压缩包内容"这类弱特征**永远只提示**。
- **签名校验**：`WinVerifyTrust` 校验内嵌 Authenticode 签名（结果按 `(路径,大小,mtime)` 缓存）；
  有效签名 → 正常程序模块不再被误杀。系统文件多为 catalog 签名（Win32 会报"无签名"，属正常），
  这类再退一步读 `VS_VERSION_INFO` 的 CompanyName 做弱减免。
- **日志类基线白名单**：`.log/.txt/.ini/.json/.xml/.csv/.md` 等文本类 + 路径含 `\logs\`、
  且内容确为文本时减免 -42。**安全边界**：脚本/可执行/宏文档扩展名（`.exe/.vbs/.ps1/.hta/.docm…`）
  **一律不套基线**，防止"恶意脚本丢 Temp 或 logs 目录就被洗白"（本轮实测发现并修掉了这个后门）。
- 评分明细写日志（`[评分豁免] … 评分= 减免=…`），可开关 `risk_log`。

### 需求 3 · 处置流程卡巴化（先杀进程 → 再隔离，且提示"进程已终止"）

链路顺序本来就是"先杀后处置"，v1.1.5 补齐了**呈现层**：

- `DisposeResult` 新增 `notification` / `killed_msgs` 字段，杀进程后固定产出
  `进程已终止（N 个）：evil.exe (1234)` 这样的通知；无占用进程时明确写"未发现占用进程，直接处置"。
- 处置结果弹窗首行醒目显示 **✔ 进程已终止：共 N 个**，并列出被杀进程名与 PID。
- 隔离 / 删除 / 高级清除的**确认弹窗与结果弹窗都显示文件完整路径**（不再只显示数量或文件名），
  超过 10 条自动折叠为"另有 N 个文件"。

### 需求 4 · 权限调整（主程序普通权限，按需提权）

| 项 | v1.1.0 | v1.1.5 |
|---|---|---|
| 打包参数 | `--uac-admin`（exe 清单要求管理员） | **已去掉** → 快捷方式无"管理员蓝盾"角标 |
| 主程序运行权限 | 始终管理员 | **普通用户权限**（`run_as_user=True`） |
| 提权时机 | 启动即提权 | **只在高级清除/原地锁定等点击时**调 `NSudoLC.exe`（`elevate_on_advanced=True`） |
| 数据目录 | 固定 `{app}\data` | 不可写时自动回退 `%LOCALAPPDATA%\ShieldPy\data`（`DATA_DIR_FALLBACK`） |
| 安装脚本 | 无 ACL 处理 | 安装末尾用 `icacls` 给 `data`、`reports`、`{app}` 授予 Users 写权限（SID 形式，兼容中文系统） |

安装程序本身仍需管理员（要写 Program Files 与 HKLM 右键菜单），这不影响快捷方式角标。

### 需求 5 · 扫描结果面板复选框 + 批量操作

`ui/scan_panel.py`（原 `scan_page.py` 正式迁移至此）：

- 表格列变为 `✓ | 严重度 | 评分 | 检测引擎 | 威胁名称 | 文件路径`，每条前面有复选框
  （`☐` 未选 / `☑` 选中），点击第 1 列或按空格切换。
- 表头位置是**三态全选按钮**：`☐ 全选` → `◑ 全选`（半选）→ `☑ 取消全选`，
  旁边实时显示"已选 N / M 项"。
- 批量操作：**批量隔离 / 批量删除 / 批量信任 / 批量原地锁定**，全部作用于勾选集合。
- 深浅色适配：勾选行背景深色主题 `#123a2e` 字 `#7fe0bb`，浅色主题 `#d3f0e4` 字 `#075e42`；
  威胁严重度仍用红/橙/灰着色。

### 项目文件拆分

按要求把"用户关心的 5 个文件"作为功能落点（内部仍保留 v1.1.0 的 `core/` 22 模块 + `ui/` 十页模块化，
避免把已验证的代码揉成巨型文件）：

| 要求的文件 | 实际位置 | 职责 |
|---|---|---|
| `wizard.py` | `ui/wizard.py` | 初次启动向导界面（异步渲染 / 占位 / 兜底 / 可关闭） |
| `scan_panel.py` | `ui/scan_panel.py` | 扫描页面、结果列表、复选框批量处置（`scan_page.py` 已降为兼容别名） |
| `engine.py` | `core/engine.py` | 扫描引擎 + 风险打分 + 处置逻辑**统一门面**（`scan_file / dispose / scan_and_dispose / engine_info`） |
| `main.py` | `main.py`（根目录） | 程序入口 + 主窗口装配 + 权限模型（`is_admin` / `create_main_window` / `run_app`） |
| `config.py` | `core/config.py` | 配置、白名单、日志基线扩展名、路径（含 data 目录可写回退） |

---

### 自动化验证结果（本机实测，打包前）

| 套件 | 结果 | 覆盖内容 |
|---|---|---|
| 核心逻辑测试 | **14 / 14 通过** | 风险评分（干净/提示/威胁三档、哈希强特征直判、日志基线减免、基线不给脚本开后门、数字签名校验+减免、厂商信息减免）、引擎门面（日志不误杀 / 恶意脚本仍判 171 分）、处置顺序与"进程已终止"通知、无进程分支、data 目录可写与回退、普通权限默认、面板列结构与向导异步方法 |
| 界面冒烟测试 | **9 / 9 通过** | 十页真实渲染、单行复选框、全选三态（全选/半选/取消）、批量勾选集合、完整路径弹窗文本、"进程已终止"结果弹窗、向导四步推进（含异步渲染与兜底）、向导三处出口可关闭、深浅色复选框配色 |
| 打包产物 | 通过 | `dist\ShieldPy.exe` 清单为 **asInvoker**（无 requireAdministrator → 快捷方式无蓝盾）；双击后 10 秒进程存活、无 `startup_error.txt` |
| 安装脚本 | 通过 | Inno Setup 7.1.1 编译成功；`icacls "*S-1-5-32-545:(OI)(CI)M"` 语法在本机实测生效（`BUILTIN\Users:(OI)(CI)(M)`） |

> 打包与安装包均需用 `D:\python\python.exe`（本机唯一带完整 Tcl/Tk 的解释器）；
> 界面测试必须后台运行并在脚本内 append+flush 写报告文件，前台跑超过 15 秒会被移入后台并丢失 stdout。

---

## v1.1.0 基线功能（11 大项，v1.1.5 全部保留）


### 1. 扫描四模式
| 模式 | 说明 |
|---|---|
| 快速扫描 | 常用目录（Windows、System32、Temp、启动目录等） |
| 全盘扫描 | 所有固定磁盘（`GetDriveTypeW == DRIVE_FIXED`） |
| 可移动驱动器扫描 | 仅 U 盘/移动硬盘（`DRIVE_REMOVABLE`） |
| 后台低优先级扫描 | 进程优先级降到 IDLE，前台不卡 |

进度条做了**单调保护**（`_last_pct`），不会出现 5%↔70% 来回跳的历史 bug。

### 2. 威胁处置链路 + 三档处置
链路顺序：**终止进程树 → 删除源文件（被占用则登记 PendMoves 重启删除）→ 清理启动项/服务/注册表残留**。

| 档位 | 实现 |
|---|---|
| 隔离（默认） | 移入 `data/quarantine/`，可随时恢复；失败退化 PendMoves |
| 删除 | 直接抹除 + 清理启动项/服务；失败退化 PendMoves |
| 高级清除 | **NSudo 提权到 TrustedInstaller**：`NSudoLC.exe -U:T -P:E -M:S -ShowWindowMode:Hide -Wait`；`attrib -r -s -h & del /f /q`，失败再"改名后删除"；全程写 `data/advanced_clear.log`；**首次使用弹红字风险确认框** |

新增模块：`core/terminator.py`、`core/pendmoves.py`、`core/residue.py`、`core/nsudo.py`、`core/dispose.py`。

### 3. 信任项（路径 + SHA256 双哈希）
`core/trust.py`：同一文件必须**路径与 SHA256 都匹配**才放行；文件被改动后该项自动标记失效（`✕ 失效`），扫描立即恢复检出。
旧版 `whitelist.json` 会自动迁移并补算 SHA256。

### 4. 原地锁定
`core/lockdown.py`：可疑文件"只许存在、不许运行"。
① `icacls /save` 保存原始 DACL 快照 → ② 所有者改为 `NT AUTHORITY\SYSTEM`（失败退化 `takeown`）→ ③ `icacls /deny "*S-1-1-0:(X)"` 拒绝执行。
放行时先 grant 管理员 F，再从快照 `icacls /restore` 并恢复原所有者。**仅用户目录可用，系统目录直接拒绝**。

### 5. 受保护文件夹（受控文件夹访问）
`core/protected.py`：滑动窗口统计同一目录的文件操作，默认 `10 秒内 20 次` → 判定批量篡改并弹窗告警。
按设计**只拦截文件操作 + 告警，不杀进程、不隔离程序**。

### 6. 勒索防护
- `core/systemwatcher.py`：System Watcher 行为采集中枢，采集文件/进程/命令行/注册表/VSS 删除，**加权打分**（22 条命令行特征 + 勒索扩展名 +70、勒索信关键词 +55、同目录 10 秒内 ≥25 次操作 +40、VSS 删除 +75…），60 秒滚动窗口累计达阈值（默认 60）触发告警。
- `core/yara_engine.py`：YARA 引擎，内置 7 条规则（EICAR、PowerShell 编码、卷影删除、勒索信关键词、脚本下载执行、凭据窃取、防御规避），规则文件 `data/yara/shieldpy_base.yar`，可按 mtime 热加载外部规则。
- `core/olevba_engine.py`：Office 宏分析（13 组关键词加权，≥50 高危 / ≥25 中危）。
- `core/snapshot.py`：防勒索快照备份（约 50 种数据类扩展名，按 SHA256 去重存储）+ **手动回滚**，被覆盖前的坏版本另存 `rollback_backup/` 便于取证。

### 7. 初次启动向导
`ui/wizard.py`：4 步 —— 欢迎 → 防护模块勾选（含高级清除高风险确认）→ 默认处置策略 → 性能档位 + 性能日志 + 首份快照。

### 8. 防护模块卡巴斯基化分组
`ui/modules_page.py`：文件反病毒 / 反网络攻击（只告警不断网）/ System Watcher / 受控文件夹 / 勒索防护 / 高级清除，卡片式开关，每项标注能力与限制。

### 9. UI 全面 CustomTkinter 化
`ui/ctk_base.py`：移除原生标题栏，自制顶部栏（♜ 图标 + —/▢/✕）、拖动窗口、双击最大化、`SetWindowRgn` 圆角（最大化自动取消）、`SetProcessDpiAwareness(2)` 高 DPI。
侧边栏四组十页：仪表盘 / 病毒扫描 / 隔离区 / 原地锁定 / 防护模块 / 防御中心 / 勒索防护 / 进程体检 / 日志 / 设置。
托盘常驻（`ui/tray.py`）：显示主界面 / 暂停·恢复实时防护 / 创建快照 / 退出。

### 10. 实时防护（默认全盘）
`core/monitor.py`：默认 `realtime_scope = "full"`（固定盘 + 可移动盘），watchdog 事件驱动，失败降级轮询；
辅助线程每 8 秒检查自启动项、hosts、新进程、VSS 卷影副本数量；命中威胁按 `realtime_auto_action` 自动处置（隔离/删除/仅告警）。

### 11. 配置与兼容
`core/config.py` 新增键：`dispose_level`、`advanced_clear_ack`、`nsudo_path`、`modules_enabled`、`protected_*`、`ransomware_*`、`snapshot_*`、`yara_enabled`、`olevba_enabled`、`ui_borderless`、`wizard_done`、`perf_log`。
旧 v1.0.x 配置自动迁移（缺 `realtime_scope` 强制全盘防护）。

---

## 运行环境

- Python **3.12.x**（构建机已装 `D:\python\python.exe`，含完整 Tcl/Tk 8.6）
- 依赖：`customtkinter 6.0.0`、`darkdetect`、`watchdog`、`pystray`、`Pillow`、`yara-python 4.5.4`、`oletools 0.60.2`、`psutil`、`pywin32`、`pefile`
- 打包：`PyInstaller 6.22.3`、`Inno Setup 7`（`C:\Program\ISCC.exe`）

## 快速开始

```bat
cd ShieldPy
D:\python\python.exe main.py
```

托盘不可用时可用 `set SHIELDPY_NO_TRAY=1` 后启动。

## 打包

```bat
D:\python\python.exe -m PyInstaller --noconfirm --clean --onefile --windowed ^
  --name ShieldPy --icon "installer\shield_icon.ico" ^
  --add-data "data\signatures.json;data" ^
  --add-data "installer\shield_icon.ico;icon" ^
  --add-data "tools\nsudo;tools\nsudo" ^
  --collect-all customtkinter --collect-submodules oletools ^
  --hidden-import pystray._win32 --hidden-import yara --hidden-import pyexpat main.py

"C:\Program\ISCC.exe" installer\shieldpy_setup.iss
```

> v1.1.5 已**移除 `--uac-admin`**：主程序默认普通权限，快捷方式无管理员盾牌；
> 只有高级清除 / 原地锁定等操作在点击时才由 NSudo 单独提权。

## 目录结构

```
ShieldPy/
├─ main.py                 入口 + 主窗口装配 + 权限模型（--scan 支持右键菜单查杀）
├─ core/                   24 个核心模块
│   ├─ config.py           配置、白名单、日志基线扩展名、data 可写回退
│   ├─ engine.py           ★ v1.1.5 引擎层门面（扫描 + 打分 + 处置统一入口）
│   ├─ risk.py             ★ v1.1.5 风险加权打分（签名校验 / 日志基线 / 阈值）
│   ├─ scanner.py          四模式扫描引擎（特征/YARA/olevba/启发式/加壳 → 打分）
│   ├─ monitor.py          实时防护（watchdog + 辅助线程）
│   ├─ trust.py            信任项双哈希
│   ├─ quarantine.py       隔离区
│   ├─ terminator.py       进程树终止
│   ├─ pendmoves.py        重启删除登记
│   ├─ residue.py          启动项/服务/注册表残留
│   ├─ nsudo.py            NSudo 提权封装（仅高危操作调用）
│   ├─ dispose.py          三档处置链路（先杀进程 → 处置 → 清残留）
│   ├─ lockdown.py         原地锁定（ACL + 权限快照）
│   ├─ protected.py        受保护文件夹
│   ├─ systemwatcher.py    System Watcher 加权打分
│   ├─ yara_engine.py      YARA 引擎
│   ├─ olevba_engine.py    Office 宏分析
│   ├─ snapshot.py         快照/回滚
│   └─ … signature / heuristics / process / report / logger / whitelist
├─ ui/                     CustomTkinter 界面（10 页 + 向导 + 托盘）
│   ├─ scan_panel.py       ★ v1.1.5 扫描页（复选框 + 三态全选 + 批量处置）
│   ├─ scan_page.py        兼容别名（指向 scan_panel）
│   ├─ wizard.py           ★ v1.1.5 修复版向导（异步渲染 / 占位 / 兜底 / 可关闭）
│   └─ … app / ctk_base / tray / dashboard 等九页
├─ installer/              安装脚本、图标、中文语言、测试指南
├─ tools/nsudo/            随包的 NSudo 组件（高级清除用）
└─ data/                   配置、隔离区、日志、YARA 规则、快照、锁定快照
```

## 限制说明（务必知悉）

| 限制 | 说明 |
|---|---|
| 用户态监控延迟 | 无内核驱动，拦截存在毫秒~秒级延迟 |
| 驱动级 Rootkit | 无法处理，需转 PE 环境清理 |
| 高级清除依赖 NSudo | 会被其他安全软件标记为风险工具，且删除不可回滚 |
| 反网络攻击只告警 | 用户态不接管防火墙，不主动断网 |
| 原地锁定仅用户目录 | 系统目录禁用，防止锁死系统文件 |
| 受控文件夹只告警 | 不杀进程/不隔离，避免误伤批量正常操作 |
| 未签名 exe | 智能应用控制(SAC)等环境会拦截，需手动放行 |

---

v1.1.5：修向导黑屏卡死（真实根因：CTkCheckBox/CTkRadioButton 不支持 progress_color）、
        误报治理（风险加权打分 + 数字签名校验 + 日志基线白名单）、
        处置卡巴化（先杀进程并提示"进程已终止"，弹窗显示完整路径）、
        权限降级（去掉 --uac-admin，按需 NSudo 提权，data 目录可写回退）、
        结果面板复选框（三态全选 + 批量隔离/删除/信任/锁定）。
v1.1.0：新增四种扫描模式、三档处置、双哈希信任、原地锁定、受控文件夹、System Watcher、
        YARA/olevba、快照回滚、卡巴式模块分组、无边框 UI + 托盘、初次向导。
v1.0.55：修复三按钮不显示、实时防护默认全盘、进度条回跳、主题切换卡死、托盘常驻。
v1.0.2：降低误报、降低全盘扫描 CPU 占用。
