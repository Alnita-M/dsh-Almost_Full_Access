/**
 * dsh-Almost Full Access — 确定性命令分析（零依赖纯模块，可独立测试）
 * ============================================================
 * 只做文本分析，不接触任何服务/IO。被 lib/index.js（Host 插件）引用，
 * 也被 scripts/test.mjs 直接测试。
 */

const TOKEN_SRC = "(?:[A-Za-z]:[\\\\/][^\\s|&<>;()]*|%(?:TEMP|TMP|WINDIR|SYSTEMROOT|USERPROFILE|APPDATA|LOCALAPPDATA|ProgramFiles|ProgramFiles\\(x86\\)|ProgramData|PUBLIC|SystemDrive|HOMEDRIVE|SystemRoot|windir|temp|tmp)%[\\\\/][^\\s|&<>;()]*|\\$env:[A-Za-z_][A-Za-z0-9_]*[\\\\/][^\\s|&<>;()]*|\\\\\\\\[^\\\\\\s|&<>;()]+\\\\[^\\s|&<>;()]*)"
const REG_TOKEN_SRC = "(?:HKLM|HKCU|HKCR|HKU|HKCC):\\\\[^\\s|&<>;()]*"
const WRITE_VERB_SRC = "\\b(?:Set-Content|Add-Content|Out-File|New-Item|Remove-Item|Copy-Item|Move-Item|Rename-Item|Set-Item|Clear-Content|Clear-Item|Remove-ChildItem|Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|mkdir|rmdir|md|rd|del|erase|ren|move|copy|xcopy|robocopy)\\b[\\s\\S]{0,160}"
const REDIRECT_SRC = ">>?\\s*([^\\s|&;\"'<>]+)"

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
  { id: 'sys:sc', re: /\bsc\s+(config|stop|start|delete|create)\b|\bnet\s+(stop|start)\s+\S+/i, text: '系统服务操作（sc/net）' },
  { id: 'sys:pnputil', re: /\bpnputil\b/i, text: '驱动安装/卸载/更新（pnputil）' },
  { id: 'sys:acl', re: /\b(takeown|icacls)\b/i, text: '系统文件权限修改（takeown/icacls）' },
  { id: 'sys:sfc', re: /\bsfc\s+\/scannow/i, text: '系统文件完整性修复（sfc /scannow）' },
  { id: 'sys:dism', re: /\bdism\b/i, text: '系统映像/组件操作（DISM）' },
  { id: 'sys:hklm', re: /\breg\s+(add|delete|copy|save|restore)\s+HKLM\b/i, text: 'HKLM 系统注册表修改' },
  { id: 'sys:env', re: /\bSet-Item\s+env:|\[Environment\]::SetEnvironmentVariable/i, text: '系统环境变量持久化修改' },
  { id: 'sys:firewall', re: /\b(netsh\s+advfirewall|Set-NetFirewall|New-NetFirewall|Remove-NetFirewall|Set-MpPreference|Add-MpPreference|Remove-MpPreference)\b/i, text: '防火墙/安全软件配置修改' },
  { id: 'sys:features', re: /\b(Enable|Disable)-WindowsOptionalFeature\b/i, text: 'Windows 功能启用/禁用' },
  { id: 'sys:software', re: /\bmsiexec\s+\/i\b|\bwinget\s+(install|upgrade|uninstall)\b|\bchoco\s+(install|upgrade|uninstall)\b|\bscoop\s+(install|update|uninstall)\b/i, text: '安装/卸载/升级软件（系统级变更）' },
  { id: 'sys:schedule', re: /\b(schtasks\s+\/create|Register-ScheduledTask|New-ScheduledTask)\b/i, text: '创建计划任务' },
  { id: 'sys:gpo', re: /\b(gpupdate\s+\/force|Set-GP|Import-GPO)\b/i, text: '组策略修改/强制刷新' },
  { id: 'sys:execpolicy', re: /\bSet-ExecutionPolicy\b/i, text: 'PowerShell 执行策略修改' },
  { id: 'sys:packages', re: /\b(pip|pip3|pipx)\s+(install|uninstall|upgrade)\b|\bconda\s+(install|update|remove)\b|\bgem\s+(install|uninstall|update)\b/i, text: '修改工作区以外的 Python/Ruby 包环境' }
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
  /\b(?:pwsh|powershell)\s+(-Command|-File|-EncodedCommand)/i
]

export function isOutsidePath(t, workspace) {
  if (!t) return false
  if (/^%/.test(t) || /^\$env:/i.test(t)) return true
  if (/^\\\\/.test(t)) return true
  if (/^[A-Za-z]:/.test(t)) {
    if (!workspace) return true
    const a = t.toLowerCase()
    const b = workspace.toLowerCase()
    if (a === b) return false
    if (a.startsWith(b + '\\') || a.startsWith(b + '/')) return false
    return true
  }
  return false
}

export function analyzeCommand(command, workspace) {
  const impacts = []
  const ruleIds = []
  const targets = []
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
  // 1) 引号包裹的路径（可能含空格，如 'C:\Users\X\My Folder\a.txt'）——仅当命令存在
  //    写意图（写动词或重定向）时才视为写目标；只读命令（Get-Content 等）不判。
  //    命中后整体提取并占位，避免无引号 token 扫描把它在空格处截断成假路径。
  let scrubbed = command
  const hasWriteIntent = new RegExp(WRITE_VERB_SRC, 'i').test(command) || />\s*\S/.test(command)
  if (hasWriteIntent) {
    const quotedRe = new RegExp("['\"]([A-Za-z]:[\\\\/][^'\"]+|%(?:TEMP|TMP|WINDIR|SYSTEMROOT|USERPROFILE|APPDATA|LOCALAPPDATA|ProgramFiles|ProgramFiles\\(x86\\)|ProgramData|PUBLIC|SystemDrive|HOMEDRIVE|SystemRoot|windir|temp|tmp)%[\\\\/][^'\"]+|\\$env:[A-Za-z_][A-Za-z0-9_]*[\\\\/][^'\"]+|(?:HKLM|HKCU|HKCR|HKU|HKCC):\\\\[^'\"]+)['\"]", 'gi')
    let qm
    while ((qm = quotedRe.exec(scrubbed)) !== null) {
      pushTarget(qm[1])
      scrubbed = scrubbed.slice(0, qm.index) + ' '.repeat(qm[0].length) + scrubbed.slice(qm.index + qm[0].length)
    }
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
  }
  let hasWrite = false
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
