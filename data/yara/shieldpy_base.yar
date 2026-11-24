/*
  ShieldPy 基础 YARA 规则集（v1.1.0）
  可自由追加/替换为 Loki、Neo23x0 signature-base 等开源规则。
*/
rule EICAR_Test_File
{
    meta:
        description = "EICAR 反病毒测试文件"
        severity = "high"
    strings:
        $e1 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        $e2 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}"
    condition:
        any of them
}

rule Suspicious_PowerShell_Encoded
{
    meta:
        description = "PowerShell 编码命令（隐藏执行）"
        severity = "high"
    strings:
        $p1 = "powershell" nocase ascii
        $p2 = "-enc" ascii nocase
        $p3 = "-nop" ascii nocase
        $p4 = "-w hidden" ascii nocase
    condition:
        2 of them
}

rule Suspicious_ShadowCopy_Deletion
{
    meta:
        description = "卷影副本删除/备份破坏"
        severity = "high"
    strings:
        $s1 = "vssadmin" ascii nocase
        $s2 = "delete shadows" ascii nocase
        $s3 = "wmic shadowcopy delete" ascii nocase
        $s4 = "wbadmin delete catalog" ascii nocase
        $s5 = "bcdedit" ascii nocase
        $s6 = "recoveryenabled" ascii nocase
    condition:
        ($s1 and $s2) or $s3 or $s4 or ($s5 and $s6)
}

rule Ransomware_Note_Keyword
{
    meta:
        description = "勒索说明文件特征文案"
        severity = "high"
    strings:
        $r1 = "your files have been encrypted" ascii nocase
        $r2 = "all your files" ascii nocase
        $r3 = "to decrypt" ascii nocase
        $r4 = "bitcoin" ascii nocase
        $r5 = "BTC address" ascii nocase
        $r6 = "recover your files" ascii nocase
    condition:
        2 of them
}

rule Script_Download_And_Execute
{
    meta:
        description = "脚本下载并执行载荷"
        severity = "medium"
    strings:
        $d1 = "DownloadFile" ascii nocase
        $d2 = "Invoke-WebRequest" ascii nocase
        $d3 = "XMLHTTP" ascii nocase
        $d4 = "ADODB.Stream" ascii nocase
        $d5 = "ShellExecute" ascii nocase
        $d6 = "WScript.Shell" ascii nocase
        $d7 = "http://" ascii
        $d8 = "https://" ascii
    condition:
        ($d7 or $d8) and any of ($d1,$d2,$d3,$d4,$d5,$d6)
}

rule Credential_Dumping_Tool
{
    meta:
        description = "凭据窃取工具特征"
        severity = "high"
    strings:
        $c1 = "mimikatz" ascii nocase
        $c2 = "sekurlsa" ascii nocase
        $c3 = "lsadump" ascii nocase
        $c4 = "wdigest" ascii nocase
        $c5 = "kerberos::golden" ascii nocase
    condition:
        any of them
}

rule Defense_Evasion_Commands
{
    meta:
        description = "关闭防御/记录清理"
        severity = "medium"
    strings:
        $e1 = "wevtutil cl" ascii nocase
        $e2 = "Set-MpPreference" ascii nocase
        $e3 = "DisableRealtimeMonitoring" ascii nocase
        $e4 = "netsh advfirewall firewall" ascii nocase
        $e5 = "sc stop" ascii nocase
    condition:
        any of them
}
