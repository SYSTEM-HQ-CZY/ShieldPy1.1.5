; 玄盾卫士 ShieldPy 安装脚本 v1.1.5
; 编译: ISCC.exe shieldpy_setup.iss
; 生成: Output\ShieldPy_Setup.exe
;
; v1.1.5 权限模型变更：
;   * 主程序 ShieldPy.exe 不再带 requireAdministrator 清单（打包已去掉 --uac-admin），
;     因此桌面/开始菜单快捷方式不再有"管理员蓝盾"角标，默认以普通用户权限运行；
;   * 仅"高级清除 / 原地锁定"等高危操作在点击时才调用 NSudo 单独提权；
;   * 安装程序本身仍需管理员（要写入 Program Files 与 HKLM 右键菜单），
;     并在安装末尾给 data / reports 目录授予 Users 写权限，
;     保证普通权限运行时配置、隔离区、日志、快照都可写。

#define MyAppName "玄盾卫士"
#define MyAppNameEN "ShieldPy"
#define MyAppVersion "1.1.5"
#define MyAppPublisher "ShieldPy"
#define MyAppExeName "ShieldPy.exe"
#define MyAppURL ""

[Setup]
; 保持与 1.0.x 相同的 AppId，升级安装可原地覆盖
AppId={{5A2B9C4D-1E3F-4A5B-8C6D-2E7F8A9B0C1D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\ShieldPy
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; 安装程序需要管理员权限（写 Program Files 与 HKLM 菜单）；
; 主程序本身是普通权限，快捷方式无 UAC 盾牌
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
SetupIconFile=shield_icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
OutputDir=Output
OutputBaseFilename=ShieldPy_Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
WizardImageAlphaFormat=premultiplied
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
MinVersion=10.0
AllowNoIcons=yes

[Languages]
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务:"; Flags: unchecked
Name: "autostart"; Description: "开机自动启动（后台常驻防护）"; GroupDescription: "附加任务:"; Flags: checkedonce

[Files]
Source: "..\dist\ShieldPy.exe"; DestDir: "{app}"; Flags: ignoreversion
; NSudo 提权组件（高级清除用，随包附带便于虚拟机测试）
Source: "..\tools\nsudo\NSudoLC.exe"; DestDir: "{app}\tools\nsudo"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\tools\nsudo\NSudoLG.exe"; DestDir: "{app}\tools\nsudo"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\tools\nsudo\NSudo.json"; DestDir: "{app}\tools\nsudo"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\tools\nsudo\NSudo_License.txt"; DestDir: "{app}\tools\nsudo"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\installer\shield_icon.ico"; DestDir: "{app}\icon"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\installer\shieldpy_readme.txt"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist overwritereadonly
Source: "..\installer\虚拟机测试指南.md"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

; 注意：data 目录（配置文件、隔离区、日志、快照、信任项）由程序首次运行时创建，
; 卸载时默认保留，避免误删用户的隔离样本与快照。

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{group}\卸载 {#MyAppName}"; Filename: "{uninstallexe}"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

; ---------- 开机自启（用户级） ----------
[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "ShieldPy"; ValueData: """{app}\{#MyAppExeName}"""; Flags: uninsdeletevalue; Tasks: autostart

; ---------- 右键菜单：自定义查杀（HKLM，卸载自动清理） ----------
; 1) 文件夹右键
Root: HKLM; Subkey: "Software\Classes\Directory\shell\ShieldPyScan"; ValueType: string; ValueName: ""; ValueData: "用玄盾卫士查杀"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Directory\shell\ShieldPyScan"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#MyAppExeName},0"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Directory\shell\ShieldPyScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan ""%1"""; Flags: uninsdeletekey

; 2) 文件夹空白处右键
Root: HKLM; Subkey: "Software\Classes\Directory\Background\shell\ShieldPyScan"; ValueType: string; ValueName: ""; ValueData: "用玄盾卫士查杀"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Directory\Background\shell\ShieldPyScan"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#MyAppExeName},0"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Directory\Background\shell\ShieldPyScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan ""%V"""; Flags: uninsdeletekey

; 3) 任意文件右键
Root: HKLM; Subkey: "Software\Classes\*\shell\ShieldPyScan"; ValueType: string; ValueName: ""; ValueData: "用玄盾卫士查杀"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\*\shell\ShieldPyScan"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#MyAppExeName},0"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\*\shell\ShieldPyScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan ""%1"""; Flags: uninsdeletekey

; 4) 磁盘驱动器右键
Root: HKLM; Subkey: "Software\Classes\Drive\shell\ShieldPyScan"; ValueType: string; ValueName: ""; ValueData: "用玄盾卫士查杀"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Drive\shell\ShieldPyScan"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#MyAppExeName},0"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Drive\shell\ShieldPyScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan ""%1"""; Flags: uninsdeletekey

[Run]
; runasoriginaluser：安装程序是管理员权限，若不指定该标志，安装结束时启动的
; 主程序会继承管理员令牌（就等于又变回"管理员运行"）。加上它，首次启动仍是普通权限，
; 与 v1.1.5 的权限模型一致（快捷方式无蓝盾，只有高级清除才提权）。
Filename: "{app}\{#MyAppExeName}"; Description: "启动 {#MyAppName}（首次运行会弹出配置向导）"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallDelete]
; 只清理程序自身产生的临时目录，保留 data（隔离样本/快照/日志）
Type: filesandordirs; Name: "{app}\icon"
Type: filesandordirs; Name: "{app}\tools"

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
end;

{ v1.1.5：给数据目录授予 Users 写权限（SID，避免中文系统名称差异） }
procedure GrantDirWrite(Dir: String);
var
  ResultCode: Integer;
begin
  if not DirExists(Dir) then
    ForceDirectories(Dir);
  Exec(ExpandConstant('{sys}\icacls.exe'),
       '"' + Dir + '" /grant *S-1-5-32-545:(OI)(CI)M /Q',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // 预建数据目录，避免首次运行权限不足
    ForceDirectories(ExpandConstant('{app}\data'));
    ForceDirectories(ExpandConstant('{app}\data\quarantine'));
    ForceDirectories(ExpandConstant('{app}\data\logs'));
    ForceDirectories(ExpandConstant('{app}\data\yara'));
    ForceDirectories(ExpandConstant('{app}\data\snapshots'));
    ForceDirectories(ExpandConstant('{app}\data\locks'));
    ForceDirectories(ExpandConstant('{app}\reports'));

    // 主程序以普通权限运行 → 这两个目录必须对 Users 可写
    GrantDirWrite(ExpandConstant('{app}\data'));
    GrantDirWrite(ExpandConstant('{app}\data\quarantine'));
    GrantDirWrite(ExpandConstant('{app}\data\logs'));
    GrantDirWrite(ExpandConstant('{app}\data\snapshots'));
    GrantDirWrite(ExpandConstant('{app}\reports'));
    GrantDirWrite(ExpandConstant('{app}'));
  end;
end;
