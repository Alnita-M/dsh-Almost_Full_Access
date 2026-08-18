/**
 * dsh-Almost Full Access — 确定性命令分析（零依赖纯模块，可独立测试）
 * ============================================================
 * 只做文本分析，不接触任何服务/IO。被 lib/index.js（Host 插件）引用，
 * 也被 scripts/test.mjs 直接测试。
 *
 * 安全审查版本（v1.0.2）：
 * - A1：写动词表补齐 PowerShell 别名（ri/rm/ni/cp/cpi/mv/mi/rni/sp/si/sc/ac……），
 *       .NET 静态调用 / 调用运算符拼接 / 字符串拼接 / 反引号 / $(…) 一律判 ambiguous 交 LLM；
 * - A2：带写意图时扫描 ..\ 相对路径穿越；可选的 workdir 参与相对路径归一后做包含判断。
 */

const TOKEN_SRC = "(?:[A-Za-z]:[\\\\/][^\\s|&<>;()]*|%(?:TEMP|TMP|WINDIR|SYSTEMROOT|USERPROFILE|APPDATA|LOCALAPPDATA|ProgramFiles|ProgramFiles\\(x86\\)|ProgramData|PUBLIC|SystemDrive|HOMEDRIVE|SystemRoot|windir|temp|tmp)%[\\\\/][^\\s|&<>;()]*|\\$env:[A-Za-z_][A-Za-z0-9_]*[\\\\/][^\\s|&<>;()]*|\\\\\\\\[^\\\\\\s|&<>;()]+\\\\[^\\s|&<>;()]*)"
// v1.0.4：POSIX 绝对路径（类 Unix/bash/WSL）——前导 / 且至少两级，避免误伤 /r /t 等单段参数
const POSIX_TOKEN_SRC = "/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+"
const REG_TOKEN_SRC = "(?:HKLM|HKCU|HKCR|HKU|HKCC):\\\\[^\\s|&<>;()]*"
// A1：全称 cmdlet + cmd 内置 + PowerShell 常用别名（ri/rm=Remove-Item, ni=New-Item,
// cp/cpi=Copy-Item, mv/mi=Move-Item, rni=Rename-Item, sp=Set-ItemProperty,
// si=Set-Item, sc=Set-Content, ac=Add-Content, clc=Clear-Content, cli=Clear-Item）
// v1.0.4：追加解压/打包写入工具（Expand-Archive/tar/unzip/7z/rar），解压到系统路径同样算写操作
const WRITE_VERB_SRC = "\\b(?:Set-Content|Add-Content|Out-File|New-Item|Remove-Item|Copy-Item|Move-Item|Rename-Item|Set-Item|Clear-Content|Clear-Item|Remove-ChildItem|Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|mkdir|rmdir|md|rd|del|erase|ren|move|copy|xcopy|robocopy|ri|rm|ni|cp|cpi|mv|mi|rni|sp|si|sc|ac|clc|cli|Expand-Archive|tar|unzip|7z|7za|rar|unrar)\\b[\\s\\S]{0,160}"
// A1：.NET 静态写方法（[IO.File]::WriteAllText / [System.IO.Directory]::Delete …），
// 排除 [Console]::WriteLine/WriteHost 等只写控制台的成员
const NET_WRITE_RE = /\]::(?!Write(?:Line|Host|Error|Warning|Verbose|Debug|Information)\s*\()(?:Write|Append|Delete|Copy|Move|Create|Set|Add|Remove|Clear|Download)\w*\s*\(/i
const REDIRECT_SRC = ">>?\\s*([^\\s|&;\"'<>]+)"
// A2：相对路径穿越片段（..\ 或 ../ 开头的路径段）
const TRAV_SRC = "\\.\\.[\\\\/](?:[^\\\\/\\s|&<>;()\"']+[\\\\/])*[^\\\\/\\s|&<>;()\"']*"

export const BOOT_RULES = [
  { id: 'boot:bcdedit', re: /\bbcdedit\b/i, text: '修改引导配置（BCD）' },
  { id: 'boot:bootrec', re: /\b(bootrec|bcdboot)\b/i, text: '修复/重建引导记录（bootrec/bcdboot）' },
  { id: 'boot:diskpart', re: /\bdiskpart\b/i, text: '磁盘分区操作（diskpart）' },
  { id: 'boot:format', re: /(^|[\s|;&])format(?!-)(\s|$)/i, text: '磁盘格式化（format）' },
  { id: 'boot:shutdown', re: /\b(shutdown|Restart-Computer|Stop-Computer)\b/i, text: '关机或重启操作' },
  { id: 'boot:hibernate', re: /powercfg\s+\/hibernate\s+off/i, text: '禁用休眠（powercfg /hibernate off）' }
]
export const SYSTEM_RULES = [
  { id: 'sys:service', re: /\b(Stop-Service|Start-Service|Restart-Service|Set-Service|New-Service|Remove-Service)\b/i, text: '系统服务停止/启动/配置' },
  { id: 'sys:sc', re: /\bsc\s+(config|stop|start|delete|create|sdset)\b|\bnet\s+(stop|start)\s+\S+/i, text: '系统服务操作（sc/net，含 sdset 安全描述符）' },
  { id: 'sys:pnputil', re: /\bpnputil\b/i, text: '驱动安装/卸载/更新（pnputil）' },
  { id: 'sys:acl', re: /\b(takeown|icacls)\b/i, text: '系统文件权限修改（takeown/icacls）' },
  { id: 'sys:sfc', re: /\bsfc\s+\/scannow/i, text: '系统文件完整性修复（sfc /scannow）' },
  { id: 'sys:dism', re: /\bdism\b/i, text: '系统映像/组件操作（DISM）' },
  { id: 'sys:hklm', re: /\breg\s+(add|delete|copy|save|restore)\s+HKLM\b/i, text: 'HKLM 系统注册表修改' },
  { id: 'sys:import', re: /\breg\s+import\b/i, text: '注册表导入（reg import，可整体覆盖 HKLM）' },
  { id: 'sys:env', re: /\bSet-Item\s+env:|\[Environment\]::SetEnvironmentVariable|\bsetx\b/i, text: '环境变量持久化修改（setx 含 /M 系统级）' },
  { id: 'sys:firewall', re: /\b(netsh\s+advfirewall|Set-NetFirewall|New-NetFirewall|Remove-NetFirewall|Set-MpPreference|Add-MpPreference|Remove-MpPreference)\b/i, text: '防火墙/安全软件配置修改' },
  { id: 'sys:features', re: /\b(Enable|Disable)-WindowsOptionalFeature\b/i, text: 'Windows 功能启用/禁用' },
  { id: 'sys:software', re: /\bmsiexec\s+\/\w\b|\bwinget\s+(install|upgrade|uninstall)\b|\bchoco\s+(install|upgrade|uninstall)\b|\bscoop\s+(install|update|uninstall)\b/i, text: '安装/卸载/升级软件（系统级变更）' },
  { id: 'sys:schedule', re: /\b(schtasks\s+\/create|Register-ScheduledTask|New-ScheduledTask)\b/i, text: '创建计划任务' },
  { id: 'sys:gpo', re: /\b(gpupdate\s+\/force|Set-GP|Import-GPO)\b/i, text: '组策略修改/强制刷新' },
  { id: 'sys:execpolicy', re: /\bSet-ExecutionPolicy\b/i, text: 'PowerShell 执行策略修改' },
  { id: 'sys:packages', re: /\b(pip|pip3|pipx)\s+(install|uninstall|upgrade)\b|\bconda\s+(install|update|remove)\b|\bgem\s+(install|uninstall|update)\b/i, text: '修改工作区以外的 Python/Ruby 包环境' },
  { id: 'sys:accounts', re: /\b(net\s+(user|localgroup|group)|Add-LocalGroupMember|Remove-LocalGroupMember|Add-LocalUser|Set-LocalUser|Remove-LocalUser|New-LocalUser)\b/i, text: '用户账户/组成员修改（含提权风险）' },
  { id: 'sys:fltmc', re: /\bfltmc\b/i, text: '过滤器驱动加载/卸载/配置（fltmc）' },
  { id: 'sys:vssadmin', re: /\bvssadmin\s+delete\b/i, text: '删除卷影副本/系统还原点（vssadmin delete）' },
  { id: 'sys:bash', re: /\b(apt(-get)?|aptitude|dnf|yum|pacman|zypper|systemctl|ufw|iptables|nft|mkfs|fdisk|parted|useradd|usermod|passwd|crontab|chown)\b|\bdd\s+if=/i, text: '类 Unix 系统级/包管理/引导命令（bash/WSL）' }
]
export const AMBIGUOUS_RULES = [
  /\b(Invoke-Expression|iex)\b/i,
  /-EncodedCommand\b/i,
  /\b(Invoke-WebRequest|Invoke-RestMethod|curl|wget|Start-BitsTransfer)\b|\b(DownloadString|DownloadFile)\b/i,
  /\bStart-Process\b/i,
  /\b(Invoke-Command|Enter-PSSession|New-PSSession)\b|\bssh\b/i,
  /\b(Start-Job|Start-ThreadJob)\b/i,
  /[|;&]\s*(?:&|\.\\)?\s*['"]?[^ \t|;&"']+\.(ps1|bat|cmd|vbs|js|py|exe|msi)['"]?/i,
  /&\s*['"]?[A-Za-z]:\\[^'"]+\.(exe|msi|ps1|bat|cmd)['"]?/i,
  /\b(?:pwsh|powershell)\s+(-Command|-File|-EncodedCommand)/i,
  // A1：.NET 静态成员调用（[IO.File]::…、[Math]::…）
  /\[[A-Za-z_][\w.]*\]::/i,
  // A1：调用运算符 & （括号表达式 / 引号字符串 / 变量 / 裸词）——不用 \b（行首 & 无词界）
  /&\s*\(/i,
  /&\s*['"]/i,
  /&\s*[\w$]/i,
  // A1：字符串拼接构造命令（'Remove'+'-Item' / "a"+"b"）
  /(?:'[^']*'|"[^"]*")\s*\+\s*(?:'[^']*'|"[^"]*")/i,
  // A1：反引号（PowerShell 转义 / bash 命令替换）
  /\x60/,
  // A1：$(…) 子表达式 / bash 命令替换
  /\$\(/,
  // v1.0.4：LOLBin / 脚本宿主 / 下载执行 / 系统工具（多用于绕过检测、远程加载、落地执行）
  /\b(certutil|bitsadmin|regsvr32|rundll32|mshta|cscript|wscript|wmic|installutil|msbuild|regasm|regsvcs|cmstp|pubprn)\b/i,
  // v1.0.4：提权/代权执行（sudo / runas）
  /\bsudo\b/i,
  /\brunas\b/i,
  // v1.0.4：cmd 包装执行（内部是否动态无法从文本保证）
  /\bcmd(\s*\.exe)?\s+\/[ck]\b/i,
  // v1.0.4：常见攻击/凭据采集工具（出现即需确认用途）
  /\b(mimikatz|procdump|wce|pwdump|secretsdump|mimilib)\b/i
]

/** 极简路径归并（仅字符串运算，无 IO）：把相对路径 rel 基于 base 归一为绝对路径。 */
export function resolveRelative(base, rel) {
  if (!base) return rel
  const parts = String(base + '\\' + rel).split(/[\\/]+/)
  const out = []
  for (const p of parts) {
    if (p === '' || p === '.') continue
    if (p === '..') { if (out.length > 1) out.pop(); continue }
    out.push(p)
  }
  return out.join('\\')
}

export function isOutsidePath(t, workspace) {
  if (!t) return false
  if (/^%/.test(t) || /^\$env:/i.test(t)) return true
  if (/^\\\\/.test(t)) return true
  // v1.0.4：POSIX 绝对路径（/etc/...、/usr/...、/tmp/...）——Windows 工作区通常不在其内，判外部
  if (/^\/[^/ ]+\//.test(t)) {
    if (workspace && /^\//.test(workspace) && (t === workspace || t.startsWith(String(workspace).replace(/\/+$/, '') + '/'))) return false
    return true
  }
  if (/^[A-Za-z]:/.test(t)) {
    if (!workspace) return true
    const a = t.toLowerCase()
    const b = String(workspace).toLowerCase()
    if (a === b) return false
    if (a.startsWith(b + '\\') || a.startsWith(b + '/')) return false
    return true
  }
  return false
}

export function analyzeCommand(command, workspace, workdir) {
  const impacts = []
  const ruleIds = []
  const targets = []      // 工作区外的绝对目标（含注册表）
  const traversals = []   // ..\ 相对路径穿越
  const pushTarget = (raw) => {
    let t = raw
    if (!t) return
    t = String(t).replace(/^['"]+|['"]+$/g, '')
    if (!t) return
    const low = t.toLowerCase()
    if (low.startsWith('hklm') || low.startsWith('hkcu') || low.startsWith('hkcr') || low.startsWith('hku') || low.startsWith('hkcc')) {
      if (targets.indexOf('reg:' + t) < 0) targets.push('reg:' + t)
      return
    }
    if (isOutsidePath(t, workspace) && targets.indexOf(t) < 0) targets.push(t)
  }
  // A2：相对路径（含 ..\ 上跳 / 带分隔符的普通相对路径）写入目标判定。
  // workdir 参与归一：能解析到工作区内则不判；无法解析（未提供 workdir）时 ..\ 一律可疑。
  const pushRelative = (t) => {
    if (!t) return
    if (/^\.\.[\\/]/.test(t)) {
      if (workdir) {
        const resolved = resolveRelative(workdir, t)
        if (isOutsidePath(resolved, workspace) && traversals.indexOf(t + ' ⇒ ' + resolved) < 0) {
          traversals.push(t + ' ⇒ ' + resolved)
        }
      } else if (traversals.indexOf(t) < 0) {
        traversals.push(t)
      }
      return
    }
    if (!workdir) return
    const resolved = resolveRelative(workdir, t)
    if (isOutsidePath(resolved, workspace) && targets.indexOf(resolved) < 0) targets.push(resolved)
  }
  // 1) 引号包裹的路径（可能含空格，如 'C:\Users\X\My Folder\a.txt'）——仅当命令存在
  //    写意图（写动词/写别名/.NET 写方法/重定向）时才视为写目标；只读命令（Get-Content 等）不判。
  //    命中后整体提取并占位，避免无引号 token 扫描把它在空格处截断成假路径。
  let scrubbed = command
  const hasWriteIntent = new RegExp(WRITE_VERB_SRC, 'i').test(command) || NET_WRITE_RE.test(command) || />\s*\S/.test(command)
  if (hasWriteIntent) {
    const quotedRe = new RegExp("['\"]([A-Za-z]:[\\\\/][^'\"]+|%(?:TEMP|TMP|WINDIR|SYSTEMROOT|USERPROFILE|APPDATA|LOCALAPPDATA|ProgramFiles|ProgramFiles\\(x86\\)|ProgramData|PUBLIC|SystemDrive|HOMEDRIVE|SystemRoot|windir|temp|tmp)%[\\\\/][^'\"]+|\\$env:[A-Za-z_][A-Za-z0-9_]*[\\\\/][^'\"]+|(?:HKLM|HKCU|HKCR|HKU|HKCC):\\\\[^'\"]+)['\"]", 'gi')
    let qm
    while ((qm = quotedRe.exec(scrubbed)) !== null) {
      pushTarget(qm[1])
      scrubbed = scrubbed.slice(0, qm.index) + ' '.repeat(qm[0].length) + scrubbed.slice(qm.index + qm[0].length)
    }
    // v1.0.4：引号包裹的 POSIX 绝对路径（'/etc/passwd'、'/usr/local/x' 等）
    const quotedPosixRe = /(['"])(\/[^'"]+)\1/gi
    let qp
    while ((qp = quotedPosixRe.exec(scrubbed)) !== null) {
      pushTarget(qp[2])
      scrubbed = scrubbed.slice(0, qp.index) + ' '.repeat(qp[0].length) + scrubbed.slice(qp.index + qp[0].length)
    }
    // A2：引号包裹的相对路径（'.\x.txt'、'..\..\Windows\a.txt'、'sub dir\f.txt'）——绝对路径已被占位
    const quotedRelRe = /(['"])([^'"]*[\\/][^'"]*)\1/gi
    let qr
    while ((qr = quotedRelRe.exec(scrubbed)) !== null) {
      pushRelative(qr[2].replace(/^['"]+|['"]+$/g, ''))
      scrubbed = scrubbed.slice(0, qr.index) + ' '.repeat(qr[0].length) + scrubbed.slice(qr.index + qr[0].length)
    }
    // A2：..\ 相对路径穿越（未引号形式，全命令扫描）
    const travRe = new RegExp(TRAV_SRC, 'gi')
    let tm
    while ((tm = travRe.exec(scrubbed)) !== null) pushRelative(tm[0])
  }
  // 2) 无引号路径 token 与重定向目标（无空格规则）
  let m
  const redirRe = new RegExp(REDIRECT_SRC, 'g')
  while ((m = redirRe.exec(scrubbed)) !== null) pushTarget(m[1])
  const verbRe = new RegExp(WRITE_VERB_SRC, 'gi')
  while ((m = verbRe.exec(scrubbed)) !== null) {
    const win = m[0]
    const tokenRe = new RegExp(TOKEN_SRC, 'gi')
    let t
    while ((t = tokenRe.exec(win)) !== null) pushTarget(t[0])
    const regRe = new RegExp(REG_TOKEN_SRC, 'gi')
    while ((t = regRe.exec(win)) !== null) pushTarget(t[0])
    // v1.0.4：写动词窗口内的 POSIX 绝对路径（跳过 // 协议头 与 C:/ 盘符前缀）
    const posixRe = new RegExp(POSIX_TOKEN_SRC, 'gi')
    while ((t = posixRe.exec(win)) !== null) {
      const prev = win[t.index - 1]
      if (prev === '/' || prev === ':') continue
      pushTarget(t[0])
    }
    // A2：workdir 在工作区外时，写动词窗口内的裸文件名/相对路径也归一再判定
    if (workdir && isOutsidePath(resolveRelative(workdir, '.'), workspace)) {
      const bare = win.split(/[\s|;&<>()]+/)
      for (const tok of bare) {
        if (!tok) continue
        if (tok.charAt(0) === '-' || tok.charAt(0) === '/') continue
        if (/['"$%&|<>;()=\[\]*?]/.test(tok)) continue
        if (new RegExp(WRITE_VERB_SRC, 'i').test(tok)) continue
        if (new RegExp(TOKEN_SRC, 'i').test(tok) || /^[A-Za-z]:/.test(tok) || tok.indexOf('\\\\') === 0) continue
        const resolved = resolveRelative(workdir, tok)
        if (isOutsidePath(resolved, workspace) && targets.indexOf(resolved) < 0) targets.push(resolved)
      }
    }
  }
  let hasWrite = false
  for (const t of traversals) {
    hasWrite = true
    impacts.push('写操作可能穿越工作区目录（相对路径上跳）: ' + t)
  }
  for (const t of targets) {
    hasWrite = true
    impacts.push(t.indexOf('reg:') === 0 ? '修改注册表（工作区以外）: ' + t.slice(4) : '写操作涉及工作区以外的路径: ' + t)
  }
  if (hasWrite) ruleIds.push('write-outside')
  for (const rule of BOOT_RULES) if (rule.re.test(command)) { impacts.push(rule.text); ruleIds.push(rule.id) }
  for (const rule of SYSTEM_RULES) if (rule.re.test(command)) { impacts.push(rule.text); ruleIds.push(rule.id) }
  const ambiguous = AMBIGUOUS_RULES.some((re) => re.test(command))
  return { impacts, ambiguous, ruleIds }
}

export function hashCommand(cmd) {
  let h = 5381
  for (let i = 0; i < cmd.length; i++) h = ((h << 5) + h + cmd.charCodeAt(i)) | 0
  return 'h' + (h >>> 0).toString(16)
}