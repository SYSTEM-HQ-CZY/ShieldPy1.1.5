# -*- coding: utf-8 -*-
"""生成简体中文语言文件（带 UTF-8 BOM，Inno Setup 6 使用）。
覆盖 Languages\ChineseSimplified.isl。
"""
from pathlib import Path

CONTENT = """; *** ShieldPy 简体中文本地化 (基于 Inno Setup 6 官方结构)

[LangOptions]
LanguageName=简体中文
LanguageID=$0804
LanguageCodePage=0

[Messages]

; *** Application titles
SetupAppTitle=安装
SetupWindowTitle=安装 - %1
UninstallAppTitle=卸载
UninstallAppFullTitle=卸载 %1

; *** Misc. common
InformationTitle=信息
ConfirmTitle=确认
ErrorTitle=错误

; *** SetupLdr messages
SetupLdrStartupMessage=将要安装 %1。是否继续？

; *** Setup common messages
ExitSetupTitle=退出安装
ExitSetupMessage=安装尚未完成。如果现在退出，程序将不会被安装。%n%n以后可以再次运行安装程序以完成安装。%n%n退出安装吗？
AboutSetupMenuItem=关于安装(&A)...
AboutSetupTitle=关于安装
AboutSetupNote=

; *** Buttons
ButtonBack=< 上一步(&B)
ButtonNext=下一步(&N) >
ButtonInstall=安装(&I)
ButtonCancel=取消
ButtonFinish=完成(&F)
ButtonBrowse=浏览(&R)...
ButtonWizardBrowse=浏览(&R)...
ButtonNewFolder=新建文件夹(&M)
ButtonYes=是(&Y)
ButtonNo=否(&N)
ButtonOK=确定
ButtonClose=关闭(&C)
ButtonAbort=中止(&A)
ButtonRetry=重试(&R)
ButtonIgnore=忽略(&I)
ButtonDownload=下载(&D)
ButtonDontDownload=不下载(&D)
ButtonExit=退出(&E)
ButtonRestart=重启(&R)
ButtonLater=稍后(&L)
ButtonDelete=删除(&D)
ButtonWillRestart=现在重启(&W)

; *** Common messages
ClickNext=单击“下一步”继续。
ClickInstall=单击“安装”开始安装。
ClickFinish=单击“完成”退出安装程序。
BeveledLabel=

; *** Welcome page
WelcomeLabel1=欢迎使用 %1 安装向导
WelcomeLabel2=此向导将引导您完成 %1 的安装。%n%n建议您在继续之前关闭所有其他应用程序。%n%n单击“下一步”继续。
WelcomeLabel3=
WelcomePageDescription=安装 %1 到您的计算机。
WelcomeLabelNoIcons=

; *** Select directory page
SelectDirTitle=选择安装位置
SelectDirLabel1=安装程序将安装 %1 到下列文件夹中。
SelectDirLabel2=单击“下一步”继续。如果您想选择其他文件夹，请单击“浏览”。
SelectDirBrowseLabel=要选择其他文件夹，请单击“浏览”。
SelectDirPageDescription=选择 %1 的安装文件夹。
SelectDirBrowseHelp=
SelectDirBrowseHelp2=
SelectDirBrowseNewFolderHelp=
DiskSpaceMBLabel=您的计算机上至少需要有 [mb] MB 的可用磁盘空间。
DiskSpaceGBLabel=您的计算机上至少需要有 [gb] GB 的可用磁盘空间。
SpaceOnProgramFiles=Program Files 目录中可用空间:
SpaceOnData=数据目录中可用空间:
DirNameTooLong=文件夹名或路径太长。
InvalidPath=输入的路径无效。请检查后再试。
CannotSelectFolder=无法选择该文件夹。请选择其他文件夹。
CannotSelectFolderNotEmpty=无法选择该文件夹，因为它是空的且无法创建。请选择其他文件夹。

; *** Select components page
SelectComponentsTitle=选择组件
SelectComponentsLabel1=选择要安装的组件。取消选中不需要的组件。
SelectComponentsLabel2=
SelectComponentsPageDescription=选择要安装的组件。
SelectComponentsDescLabel=

; *** Select program group page
SelectProgramGroupTitle=选择“开始菜单”文件夹
SelectProgramGroupLabel1=请选择“开始菜单”文件夹，以创建程序的快捷方式。
SelectProgramGroupLabel2=
SelectProgramGroupPageDescription=选择“开始菜单”文件夹。

; *** Select tasks page
SelectTasksTitle=选择附加任务
SelectTasksLabel1=选择安装时要执行的其他任务。
SelectTasksLabel2=单击“下一步”继续。
SelectTasksPageDescription=选择要执行的其他任务。
SelectTasksDescLabel=附加任务:

; *** Ready to install page
ReadyToInstallTitle=准备安装
ReadyToInstallLabel1=安装程序已准备好安装 %1 到您的计算机。
ReadyToInstallLabel2=单击“安装”开始安装。如果要复查或更改任何安装设置，请单击“上一步”。
ReadyToInstallLabel3=您可以在卸载后随时重新安装该程序，方法是运行它的卸载程序或再次运行该安装程序。
ReadyToInstallLabel4=该程序将与以下项目一同安装。
ReadyToInstallLabel5=按“下一步”继续安装。
ReadyToInstallLabel6=按“安装”开始安装。
ReadyToInstallLabel7=准备安装 %1。
ReadyToInstallPageDescription=准备安装 %1。
ReadyMemoStart=该程序将被安装为:
ReadyMemoDone=“完成”。

; *** Installing page
InstallingLabel=正在安装 %1，请稍候...
InstallingLabel2=请稍候，安装程序正在将 %1 安装到您的计算机上。
InstallingLabel3=正在创建卸载信息...
InstallingPageDescription=正在安装 %1。
InstallingLabelProgress=正在安装 %1。正在复制文件...

; *** Finished page
FinishedHeadingLabel=正在完成 %1 安装向导
FinishedLabel=%1 已安装到您的计算机上。%n%n单击“完成”退出安装向导。
FinishedLabelNoIcons=单击“完成”退出安装向导。
FinishedRestartLabel=必须重新启动计算机才能完成 %1 的安装。是否立即重新启动？
FinishedRestartMessage=必须重新启动计算机才能完成 %1 的安装。%n%n是否立即重新启动？
FinishedButtonLabel=完成(&F)
FinishedPageDescription=正在完成 %1 安装向导。
FinishedLabelTasks=所选附加任务已执行。
ClickFinish=

; *** Uninstall messages
UninstallStatusLabel=正在卸载 %1，请稍候...
UninstallStatusLabel2=请稍候，正在从您的计算机中删除 %1。
UninstallStatusLabelProgress=正在卸载 %1。正在删除文件...
UninstallWelcomeLabel1=维护 %1
UninstallWelcomeLabel2=该程序将要从您的计算机中卸载。%n%n单击“卸载”继续。
UninstallWelcomeLabel3=
UninstallWelcomePageDescription=卸载 %1。
UninstallProgressLabel=请稍候，正在从您的计算机中删除 %1。
UninstallProgressLabel2=正在卸载 %1，请稍候...
UninstallProgressLabel3=正在创建卸载记录...
UninstallProgressLabelProgress=正在卸载 %1。正在删除文件...
UninstallFinishedLabel=%1 已从您的计算机中卸载。
UninstallFinishedLabelNoIcons=单击“完成”退出卸载程序。
UninstallNotSupported=卸载程序不支持该功能。
UninstallAppRunningError=卸载程序检测到 %1 正在运行。%n%n请先关闭它的所有实例，然后点击“确定”继续，或点击“取消”退出。
UninstallModeLabel=该程序将从您的计算机中卸载。
UninstallModeLabel2=卸载 %1 吗？
UninstallModeLabel3=
UninstallAppTitle=卸载
UninstallAppFullTitle=卸载 %1
UninstallPageDescription=卸载 %1。

; *** Setup common messages
ClickInstall2=单击“安装”开始安装程序。
ReadyToInstallLabel7=准备安装 %1。
TaskDescLabel=
TasksListLabel=
ComponentsDiskSpaceLabel=磁盘空间要求:
ComponentsDiskSpaceGBLabel=
DiskSpaceGBLabel=您的计算机上至少需要有 [gb] GB 的可用磁盘空间。
OnlyOnTheseArchitectures=此程序只能安装在适用于以下处理器架构的 Windows 版本上:%n%n%1
AdminPrivilegesRequired=安装此程序时，您必须以管理员身份登录。
PowerUserPrivilegesRequired=安装此程序时，您必须以管理员或超级用户组成员身份登录。
SetupAppRunningError=安装程序检测到 %1 正在运行。%n%n请先关闭它的所有实例，然后点击“确定”继续，或点击“取消”退出。
WindowsVersionNotSupported=您的计算机所运行的 Windows 版本不受此程序支持。
WinVersionTooLowError=此程序需要 %1 版本 %2 或更高版本。
ErrorCreatingDir=安装程序无法创建目录“%1”。
SetupFileMissing=安装目录中缺少文件 %1。请解决问题或获取程序的新副本。
SetupFileCorrupt=安装文件已损坏。请获取程序的新副本。
ExitSetupMessage=安装尚未完成。如果现在退出，程序将不会被安装。%n%n以后可以再次运行安装程序以完成安装。%n%n退出安装吗？
"""


def main():
    target = Path(r"C:\Users\admin\AppData\Local\Programs\Inno Setup 6\Languages\ChineseSimplified.isl")
    target.write_text(CONTENT, encoding="utf-8-sig")  # 带 BOM，Inno 识别为 UTF-8
    print(f"[OK] 中文语言文件已写入: {target} ({target.stat().st_size} 字节)")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
