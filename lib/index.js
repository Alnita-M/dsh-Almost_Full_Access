/**
 * dsh-Almost Full Access — 静态 Host 插件（v1.0.0）
 * ============================================================
 * 介于 workspace-write 与 Full access 之间的权限模式：
 *   1. 在 permissionPresets 预设表中注册 🛡️ almost-full-access 模式
 *      （由 cordis.patch.yml 的 permission 覆盖块提供）
 *   2. 仅在该模式下，对每条 pwsh/bash 命令执行
 *      确定性规则（危险动词表 + 工作区外写路径包含判断）→ LLM 子代理兜底
 *   3. 命中风险 → 审批队列 + HTTP 端点（GET /api/afaccess/queue、
 *      POST /api/afaccess/decide）供浏览器审批面板轮询与决策
 *   4. 会话记忆（记住本次会话的此类操作）+ 超时自动拒绝 + 审计日志
 *
 * 与动态版（afacc）的区别：无 node:vm 沙箱，直接使用 Node 全局
 * （setTimeout / fs）、import 宿主包（defineTool）；RPC 由 webServer
 * HTTP 端点承担（动态版的 harness.handle 仅动态 Client 可用）。
 */
import { defineTool } from '@deepseek-ai/dsh-tools'
import { appendFileSync } from 'node:fs'
import { join } from 'node:path'

export const name = 'dsh-almost-full-access'

export const inject = ['tools', 'subagents', 'userQuestions', 'permissionPresets', 'sandboxPolicy', 'webServer']

// ============ 确定性快路径规则表 ============
const TOKEN_SRC = "(?:[A-Za-z]:[\\\\/][^\\s|&<>;()]*|%(?:TEMP|TMP|WINDIR|SYSTEMROOT|USERPROFILE|APPDATA|LOCALAPPDATA|ProgramFiles|ProgramFiles\\(x86\\)|ProgramData|PUBLIC|SystemDrive|HOMEDRIVE|SystemRoot|windir|temp|tmp)%[\\\\/][^\\s|&<>;()]*|\\$env:[A-Za-z_][A-Za-z0-9_]*[\\\\/][^\\s|&<>;()]*|\\\\\\\\[^\\\\\\s|&<>;()]+\\\\[^\\s|&<>;()]*)"
const REG_TOKEN_SRC = "(?:HKLM|HKCU|HKCR|HKU|HKCC):\\\\[^\\s|&<>;()]*"
const WRITE_VERB_SRC = "\\b(?:Set-Content|Add-Content|Out-File|New-Item|Remove-Item|Copy-Item|Move-Item|Rename-Item|Set-Item|Clear-Content|Clear-Item|Remove-ChildItem|Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|mkdir|rmdir|md|rd|del|erase|ren|move|copy|xcopy|robocopy)\\b[\\s\\S]{0,160}"
const REDIRECT_SRC = ">>?\\s*([^\\s|&;\"'<>]+)"

const BOOT_RULES = [
  { id: 'boot:bcdedit', re: /\bbcdedit\b/i, text: '修改引导配置（BCD）' },
  { id: 'boot:bootrec', re: /\b(bootrec|bcdboot)\b/i, text: '修复/重建引导记录（bootrec/bcdboot）' },
  { id: 'boot:diskpart', re: /\bdiskpart\b/i, text: '磁盘分区操作（diskpart）' },
  { id: 'boot:format', re: /(^|[\s|;&])format(?!-)(\s|$)/i, text: '磁盘格式化（format）' },
  { id: 'boot:shutdown', re: /\b(shutdown|Restart-Computer|Stop-Computer)\b/i, text: '关机或重启操作' },
  { id: 'boot:hibernate', re: /powercfg\s+\/hibernate\s+off/i, text: '禁用休眠（powercfg /hibernate off）' }
]
const SYSTEM_RULES = [
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
const AMBIGUOUS_RULES = [
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

function isOutsidePath(t, workspace) {
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

function analyzeCommand(command, workspace) {
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
  let m
  const redirRe = new RegExp(REDIRECT_SRC, 'g')
  while ((m = redirRe.exec(command)) !== null) pushTarget(m[1])
  const verbRe = new RegExp(WRITE_VERB_SRC, 'gi')
  while ((m = verbRe.exec(command)) !== null) {
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

function hashCommand(cmd) {
  let h = 5381
  for (let i = 0; i < cmd.length; i++) h = ((h << 5) + h + cmd.charCodeAt(i)) | 0
  return 'h' + (h >>> 0).toString(16)
}

function json(res, status, data) {
  const body = JSON.stringify(data)
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(body)
}

function readBody(req) {
  return new Promise((resolve) => {
    let chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      try {
        const text = Buffer.concat(chunks).toString('utf8')
        resolve(text === '' ? {} : JSON.parse(text))
      } catch (err) {
        resolve({})
      }
    })
    req.on('error', () => resolve({}))
  })
}

const REVIEW_PROMPT = [
  '你是「Almost Full Access」插件的命令安全审查员，负责审查一条即将在这台 Windows 电脑上执行的命令。',
  '重要：你只审查命令文本本身，绝不执行任何命令、绝不调用任何工具（你也没有工具可用），直接给出判断。',
  '',
  '严格按以下三类风险逐一判断（只读/查询类操作一律不算风险）：',
  '1. 影响工作区以外的文件：凡是命令会对工作区目录之外的任何路径产生 修改/删除/创建/移动 效果（即使只是临时目录、%TEMP%、C:\\Windows\\Temp、日志文件、缓存、配置文件），一律算此风险。仅读取或查询（如 Get-Process、Get-Service、读取系统信息、查询注册表、Get-Content 读取文件）不算。',
  '2. 影响电脑正常开机：修改引导配置（bcdedit/BCD、EFI、引导加载器、MBR、启动项）、磁盘分区操作（diskpart、分区表、格式化）、关机或重启（如 shutdown /r）、禁用休眠等。',
  '3. 影响操作系统与驱动的正常运作：停止/禁用系统服务（Stop-Service、Set-Service、sc config、net stop）、安装/卸载/更新驱动（pnputil）、替换或删除系统文件（takeown、icacls、sfc、Remove-Item 系统路径）、修改组策略、写入 HKLM 注册表（reg add HKLM、Set-ItemProperty HKLM）、关闭防火墙/杀毒、执行系统更新（DISM、Windows Update）等。仅查询不算。',
  '',
  '注意：不要因为「影响很小」「只是临时文件」「很容易恢复」就把 risky 放行——只要命中上述任何一类，就必须判 risky 并列出具体影响。',
  '',
  '工作区目录（仅在该目录内的普通文件操作视为安全）：{workspace}',
  ''
].join('\n')

const REVIEW_SCHEMA = {
  type: 'object',
  properties: {
    verdict: { type: 'string', enum: ['safe', 'risky'] },
    impacts: { type: 'array', items: { type: 'string' } }
  },
  required: ['verdict', 'impacts'],
  additionalProperties: false
}

function apply(ctx) {
  const subagents = ctx.get('subagents')
  const userQuestions = ctx.get('userQuestions')
  const permissionPresets = ctx.get('permissionPresets')
  const sandboxPolicy = ctx.get('sandboxPolicy')
  const webServer = ctx.get('webServer')
  if (subagents === undefined || userQuestions === undefined || webServer === undefined) {
    ctx.logger.warn('afaccess: inactive — required services unavailable')
    return
  }

  const GATED_TOOLS = new Set(['pwsh', 'bash'])
  const pending = new Map()
  const decidedCache = new Map()
  const remembered = new Map()
  const reviewChildren = new Set()
  let queueSeq = 0
  let lastPollAt = 0
  let auditDir = ''
  const HIGH_RULE_PREFIXES = ['boot:']
  const state = {
    workspace: sandboxPolicy !== undefined ? sandboxPolicy.workspaceRoot : '',
    presetAvailable: false,
    lastPreset: '',
    counters: { detSafe: 0, detRisky: 0, llmReviewed: 0, approved: 0, denied: 0, autoDecided: 0, pending: 0 },
    queue: () => Array.from(pending.values()).map((r) => r.approvalId + ' ' + r.source + '/' + r.severity + ' ' + r.command.slice(0, 60)),
    rememberedKeys: () => Array.from(remembered.keys())
  }
  if (permissionPresets !== undefined) {
    try {
      permissionPresets.optionOf('almost-full-access')
      state.presetAvailable = true
    } catch (err) {
      ctx.logger.warn('afaccess: preset almost-full-access not advertised: ' + String(err?.message ?? err))
    }
  }

  function audit(line) {
    try {
      if (auditDir === '') return
      appendFileSync(join(auditDir, '.afaccess-debug.log'), '[' + new Date().toISOString() + '] ' + line + '\n', 'utf8')
    } catch (err) { /* audit is best-effort */ }
  }

  function sessionWorkspace(agent) {
    try {
      if (sandboxPolicy !== undefined && agent !== undefined && agent.session !== undefined) {
        const policy = sandboxPolicy.resolve({ session: agent.session })
        if (policy !== undefined && typeof policy.root === 'string' && policy.root !== '') return policy.root
      }
      if (agent !== undefined && agent.session !== undefined && agent.session.header !== undefined && typeof agent.session.header.cwd === 'string') {
        return agent.session.header.cwd
      }
    } catch (err) { }
    return state.workspace
  }

  function currentPreset(agent) {
    try {
      if (permissionPresets !== undefined && agent !== undefined && agent.session !== undefined) {
        return permissionPresets.current(agent.session.events) || ''
      }
    } catch (err) { }
    return ''
  }

  function recordToWire(rec) {
    return {
      approvalId: rec.approvalId,
      toolName: rec.toolName,
      command: rec.command,
      commandHash: rec.commandHash,
      workdir: rec.workdir,
      workspaceRoot: rec.workspaceRoot,
      preset: rec.preset,
      source: rec.source,
      severity: rec.severity,
      ruleIds: rec.ruleIds,
      impacts: rec.impacts,
      category: rec.category,
      ts: rec.ts,
      decision: rec.decision,
      auto: rec.auto === true,
      truncated: rec.truncated === true
    }
  }

  function createApproval(rec) {
    return new Promise((resolve) => {
      let settled = false
      const settle = (d) => {
        if (settled) return
        settled = true
        rec.decision = d
        rec.decidedAt = Date.now()
        rec.expiresAt = Date.now() + 10000
        clearTimeout(rec.timeoutTimer)
        clearTimeout(rec.fallbackTimer)
        if (rec.abortHandler !== undefined) { try { rec.signal.removeEventListener('abort', rec.abortHandler) } catch (err) { } }
        pending.delete(rec.approvalId)
        decidedCache.set(rec.approvalId, rec)
        resolve(d)
      }
      rec.settle = settle
      pending.set(rec.approvalId, rec)
      rec.timeoutTimer = setTimeout(() => {
        audit('TIMEOUT ' + rec.approvalId + ' auto-denied after 10min')
        settle('timeout-denied')
      }, 600000)
      rec.abortHandler = () => { settle('aborted') }
      try { rec.signal.addEventListener('abort', rec.abortHandler, { once: true }) } catch (err) { }
      rec.fallbackTimer = setTimeout(async () => {
        if (settled || lastPollAt !== 0) return
        audit('FALLBACK ' + rec.approvalId + ' no client panel; falling back to text card')
        try {
          const answer = await userQuestions.ask({
            agent: rec.agent,
            signal: rec.signal,
            questions: [{
              id: 'afaccess-approve',
              header: '🛡️ Almost Full Access · 命令审批',
              question: '审查认为该命令可能影响系统，是否允许执行？',
              detail: ['命令：', '```', rec.command.slice(0, 3000), '```', '', '审查发现的具体影响：', rec.impacts.map((x, i) => (i + 1) + '. ' + x).join('\n'), '', '工作区目录：' + (rec.workspaceRoot || '（未知）')].join('\n'),
              options: [
                { label: '拒绝执行', description: '阻止该命令运行。' },
                { label: '允许执行', description: '放行该命令，由你承担影响。' }
              ]
            }]
          })
          const chosen = answer.answers.find((item) => item.id === 'afaccess-approve')
          settle(chosen !== undefined && chosen.selected.includes('允许执行') ? 'approved' : 'denied')
        } catch (err) {
          settle('denied')
        }
      }, 20000)
    })
  }

  function requestApproval(rec) {
    rec.approvalId = 'afacc-apr-' + String(++queueSeq).padStart(4, '0')
    const mem = remembered.get(rec.category)
    if (mem !== undefined) {
      rec.decision = mem
      rec.auto = true
      state.counters.autoDecided += 1
      audit('AUTO ' + rec.approvalId + ' category=' + rec.category + ' -> ' + mem)
      return Promise.resolve(mem)
    }
    audit('APPROVAL ' + rec.approvalId + ' source=' + rec.source + ' severity=' + rec.severity + ' category=' + rec.category + ' cmd=' + rec.command.slice(0, 120).replace(/\n/g, ' '))
    return createApproval(rec)
  }

  async function runReview(command, toolName, workdir, parent, signal, workspace, analysis) {
    const lines = [REVIEW_PROMPT.replace('{workspace}', workspace || '（未知）')]
    if (analysis !== undefined && Array.isArray(analysis.impacts) && analysis.impacts.length > 0) {
      lines.push('确定性预分析已发现以下风险（请逐条核对，并在 impacts 中补充更具体的描述，不得遗漏）：')
      analysis.impacts.forEach((x, i) => lines.push((i + 1) + '. ' + x))
      lines.push('')
    } else if (analysis !== undefined && analysis.ambiguous === true) {
      lines.push('该命令包含动态执行/网络下载/外部程序调用等间接行为，确定性分析无法判定，请重点审查其真实效果。')
      lines.push('')
    }
    lines.push('即将执行的命令（工具：' + toolName + '）：')
    lines.push('```')
    lines.push(command)
    lines.push('```')
    if (workdir) lines.push('工作目录：' + workdir)
    lines.push('')
    lines.push('输出要求：你的最终结论必须通过 structured_output 工具以 JSON 返回：')
    lines.push('- verdict："safe" 表示不存在上述三类风险；"risky" 表示存在至少一类风险')
    lines.push('- impacts：字符串数组，逐条用中文说明可能造成的具体影响；verdict 为 "safe" 时为空数组')
    const prompt = [{ type: 'text', text: lines.join('\n') }]
    const run = await subagents.start(providerName(), {
      label: 'almost-full-access-review',
      prompt,
      parent,
      signal,
      outputSchema: REVIEW_SCHEMA,
      toolFilter: { allow: [] }
    })
    reviewChildren.add(run.id)
    if (run.localAgent !== undefined) reviewChildren.add(run.localAgent.id)
    try {
      const result = await run.result
      if (result.stopReason !== 'completed' || result.structured === undefined) {
        return { verdict: 'risky', impacts: ['审查子代理未能正常完成（' + result.stopReason + '），无法确认命令安全性，需人工审批。'], source: 'degraded' }
      }
      const value = result.structured
      return {
        verdict: value.verdict === 'safe' ? 'safe' : 'risky',
        impacts: Array.isArray(value.impacts) ? value.impacts.map(String) : [],
        source: 'llm'
      }
    } finally {
      reviewChildren.delete(run.id)
      if (run.localAgent !== undefined) reviewChildren.delete(run.localAgent.id)
      await run.dispose().catch(() => { })
    }
  }

  function providerName() {
    const providers = subagents.list()
    if (providers.includes('spawn')) return 'spawn'
    if (providers.includes('fork')) return 'fork'
    return providers[0]
  }

  // ============ HTTP 端点（浏览器审批面板数据通道） ============
  ctx.effect(() => webServer.register({
    kind: 'exact',
    path: '/api/afaccess/queue',
    handler: (req, res) => {
      lastPollAt = Date.now()
      const now = Date.now()
      const items = []
      for (const rec of pending.values()) items.push(recordToWire(rec))
      for (const rec of decidedCache.values()) {
        if (rec.expiresAt > now) items.push(recordToWire(rec))
        else decidedCache.delete(rec.approvalId)
      }
      json(res, 200, { ok: true, items })
    }
  }), 'afaccess: queue route')

  ctx.effect(() => webServer.register({
    kind: 'exact',
    path: '/api/afaccess/decide',
    handler: async (req, res) => {
      if (req.method !== 'POST') return json(res, 405, { ok: false, reason: 'method' })
      const args = await readBody(req)
      const id = String(args !== null && typeof args === 'object' && args.approvalId !== undefined ? args.approvalId : '')
      const rec = pending.get(id)
      if (rec === undefined) return json(res, 200, { ok: false, reason: 'unknown' })
      if (rec.decision !== null) return json(res, 200, { ok: false, reason: 'already-decided' })
      const decision = args !== null && typeof args === 'object' && args.decision === 'approved' ? 'approved' : 'denied'
      if (args !== null && typeof args === 'object' && typeof args.rememberCategory === 'string' && args.rememberCategory !== '') {
        remembered.set(args.rememberCategory, decision)
        audit('REMEMBER ' + rec.category + ' -> ' + decision)
      }
      rec.settle(decision)
      json(res, 200, { ok: true })
    }
  }), 'afaccess: decide route')

  // ============ 诊断工具 ============
  const diagTool = defineTool({
    name: 'afaccess_status',
    description: 'Almost Full Access 插件诊断工具：返回插件激活状态、服务可用性、预设挂载、工作区、审查计数、审批队列与记忆。',
    parameters: {},
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          status: { type: 'string', required: true },
          presetAvailable: { type: 'boolean' },
          lastPreset: { type: 'string' },
          workspace: { type: 'string' },
          counters: { type: 'object', additionalProperties: true },
          queue: { type: 'array', items: { type: 'string' } },
          rememberedKeys: { type: 'array', items: { type: 'string' } }
        }
      },
      render: (args, value) => [{ type: 'text', text: [
        'status=' + value.status + ' presetAvailable=' + String(value.presetAvailable) + ' lastPreset=' + (value.lastPreset || '(none)'),
        'workspace=' + value.workspace,
        'counters=' + JSON.stringify(value.counters),
        'queue=' + JSON.stringify(value.queue),
        'remembered=' + JSON.stringify(value.rememberedKeys)
      ].join('\n') }]
    },
    execute: async () => ({
      status: 'active',
      presetAvailable: state.presetAvailable,
      lastPreset: state.lastPreset,
      workspace: state.workspace,
      counters: state.counters,
      queue: state.queue(),
      rememberedKeys: state.rememberedKeys()
    })
  })
  ctx.tools.register(diagTool)

  // ============ 门控 ============
  ctx.on('tools/pre-execute', async (exec, next) => {
    if (!GATED_TOOLS.has(exec.name)) return next()
    const agent = exec.agent
    if (agent === undefined || reviewChildren.has(agent.id)) return next()

    const preset = currentPreset(agent)
    if (preset !== '') state.lastPreset = preset
    if (preset !== 'almost-full-access') return next()

    const args = exec.arguments
    const command = (args !== null && typeof args === 'object' && typeof args.command === 'string')
      ? args.command
      : (typeof args === 'string' ? args : '')
    if (command.trim() === '') return next()
    const workdir = (args !== null && typeof args === 'object' && typeof args.workdir === 'string')
      ? args.workdir : ''
    const workspace = sessionWorkspace(agent)
    if (workspace !== '' && workspace !== state.workspace) state.workspace = workspace
    if (auditDir === '' && workspace !== '') auditDir = workspace
    audit('GATE ' + exec.name + ' preset=' + preset + ' cmd=' + command.slice(0, 200).replace(/\n/g, ' '))

    const analysis = analyzeCommand(command, workspace)
    audit('ANALYZE ambiguous=' + String(analysis.ambiguous) + ' impacts=' + JSON.stringify(analysis.impacts))

    let review
    if (analysis.ambiguous) {
      state.counters.llmReviewed += 1
      try {
        review = await runReview(command, exec.name, workdir, agent, exec.signal, workspace, analysis)
      } catch (err) {
        if (exec.signal.aborted) return next()
        review = { verdict: 'risky', impacts: ['命令审查子代理启动失败（' + String(err?.message ?? err) + '），无法自动判定安全性，需人工审批。'], source: 'degraded' }
      }
    } else if (analysis.impacts.length > 0) {
      state.counters.detRisky += 1
      review = { verdict: 'risky', impacts: analysis.impacts, source: 'deterministic' }
    } else {
      state.counters.detSafe += 1
      review = { verdict: 'safe', impacts: [], source: 'deterministic' }
    }
    if (exec.signal.aborted) return next()
    if (review.verdict === 'safe') return next()

    const source = review.source === 'llm' ? 'llm' : review.source === 'degraded' ? 'degraded' : 'deterministic'
    const ruleIds = source === 'deterministic' ? (analysis.ruleIds || []) : []
    const severity = source === 'degraded' ? 'low' : ruleIds.some((id) => HIGH_RULE_PREFIXES.some((pre) => id.indexOf(pre) === 0)) ? 'high' : 'medium'
    const category = ruleIds.length > 0 ? ruleIds[0] : source === 'llm' ? 'llm-risky' : 'degraded'
    const record = {
      toolName: exec.name,
      command: command.length > 8000 ? command.slice(0, 8000) : command,
      truncated: command.length > 8000,
      commandHash: hashCommand(command),
      workdir,
      workspaceRoot: workspace,
      preset,
      source,
      severity,
      ruleIds,
      impacts: Array.isArray(review.impacts) && review.impacts.length > 0 ? review.impacts : ['（审查未给出具体影响描述）'],
      category,
      ts: new Date().toISOString(),
      decision: null,
      auto: false,
      signal: exec.signal,
      agent
    }
    const decision = await requestApproval(record)
    state.counters.pending = pending.size
    if (decision === 'approved') {
      state.counters.approved += 1
      audit('DECISION ' + record.approvalId + ' approved' + (record.auto ? ' (remembered)' : ''))
      return next()
    }
    state.counters.denied += 1
    audit('DECISION ' + record.approvalId + ' ' + decision + (record.auto ? ' (remembered)' : ''))
    if (decision === 'aborted' && exec.signal.aborted) return next()
    const impactText = (record.impacts || []).map((line, i) => (i + 1) + '. ' + line).join('\n')
    return { kind: 'deny', reason: 'Almost Full Access：用户拒绝执行该命令。' + impactText.slice(0, 400) }
  })

  ctx.logger.info('afaccess: active (static)')
}

export { apply }
