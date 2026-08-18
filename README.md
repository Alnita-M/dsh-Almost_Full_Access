# 🛡️ dsh-Almost Full Access

介于 **workspace-write** 与 **Full access** 之间的权限模式，专为 [DeepSeek Harness](https://github.com/deepseek-ai) (dsh) Web 版设计。

## 一种权限预设 · 轻量规则 + 动态命令子代理审查

切换到 **🛡️ Almost Full Access**（位于 workspace-write 与 Full access 之间）后：

**确定性规则（毫秒级，命中即弹审批面板）** 只拦两类：
1. **不可逆损失**：删除/清空/覆写粉碎（rm、ri、Remove-Item、shred、truncate…）、卸载（winget/pip/npm uninstall、msiexec /x…）、格式化/分区；
2. **影响系统正确运行**：引导、服务、驱动、系统注册表（HKLM）、账户、策略、防火墙、计划任务、卷影副本、`setx /M`，以及**写系统关键路径**（C:\Windows、Program Files、ProgramData、/etc、/usr、`\\.\PhysicalDriveN` 等）。

**动态/间接命令（交 LLM 子代理快审）**：`iex`、`curl`/下载执行、`Start-Process`、`ssh`、`sudo`、脚本调用、`.NET` 写类调用、拼接构造等——子代理判 safe 直接放行，判 risky 才弹面板；同命令 5 分钟内复用审查结果。

**直接放行（可逆、用户级）**：工作区外新建/复制/解压到普通路径、HKCU 用户注册表、安装软件（winget/pip/msiexec /i）、`setx`（无 /M）、工作区内一切操作。

## Safe Mode 的两层审查

1. **确定性快路径（毫秒级）**：危险动词表（`bcdedit` / `diskpart` / `Stop-Service` / `pnputil` / `takeown` / `reg add HKLM` / `winget` / PowerShell 别名 `ri` `ni` `sc` `sp` …）+ 工作区外写路径包含判断（支持 `C:\`、`%TEMP%`、`$env:`、UNC、注册表路径、`..\` 相对路径穿越、`/etc` 等 POSIX 路径）+ .NET 静态调用/动态拼接/反引号等间接构造一律交子代理。
2. **LLM 子代理兜底**：只有动态/间接命令（`iex`、`Invoke-WebRequest`、下载、`.NET` 调用、调用运算符、字符串拼接、`$(…)`、外部程序调用等）才起子代理审查；**确定性命中的风险锁定为必审批，子代理无法改判放行**。

命中风险 → 弹出**风格 A 简约审批面板**（悬浮于输入框上方，蓝色品牌盾牌 logo）：

- 风险徽章（高风险/中风险/需确认）+ 判定来源
- 命令单行摘要（点击展开全文、一键复制）
- 逐条影响列表（高风险首条红色强调）
- 工作区/工作目录上下文
- **允许执行**（左，次按钮）/ **拒绝执行**（右，主按钮）· `Esc` = 拒绝
- **记住本次会话的此命令**：以命令哈希为键，仅内容完全相同的命令免重复审批（同类不同命令仍需确认）；高风险（引导类）命令不可记忆
- 10 分钟未决自动拒绝；Client 面板不可用时自动降级为文本审批卡

安全命令毫秒放行、零开销；切回其它权限模式（只读/工作区/Full access）时门控自动关闭。

---

## ✨ 一键安装

### 方式 A：npx（从 GitHub 直接安装，推荐）

```bash
npx --yes github:Alnita-M/dsh-Almost_Full_Access
```

### 方式 B：npm 全局安装后运行安装器

```bash
npm install -g dsh-almost-full-access
dsh-afaccess-install
```

### 方式 C：本地开发

```bash
git clone https://github.com/Alnita-M/dsh-Almost_Full_Access.git
cd dsh-almost-full-access
node scripts/install.mjs --dry-run   # 先预览
node scripts/install.mjs             # 实际安装
```

> 安装器会把插件复制到 `~/.dsh/profiles/node_modules/dsh-almost-full-access/`，
> 并幂等更新 `~/.dsh/profiles/web/cordis.patch.yml`（权限预设表 + 插件挂载）。
> **全新电脑**（`cordis.patch.yml` 为空或不存在）也会自动写入完整的预设块与挂载块；
> 若未检测到 DSH Web 配置目录会打印警告（请先安装 DeepSeek Harness 再装本插件）。
> 其他安装器选项：`--check` / `--dry-run` / `--no-enable` / `--help`。
>
> 要求 **Node.js ≥ 16**（安装器与插件使用 ESM / top-level await）。

### 安装后

1. **重启 dsh web**（静态插件随 DSH 启动自动加载，无需在会话中激活）；
2. 硬刷新浏览器（Ctrl+Shift+R）；
3. 在会话权限选择器中切换到 **🛡️ Almost Full Access**，然后在输入框工具行右侧的 **Fast / Safe** 选择器切换审查分支；
4. 输入命令即可体验：安全命令毫秒放行，危险命令弹出审批面板。

卸载：删除 `~/.dsh/profiles/node_modules/dsh-almost-full-access/` 并从
`~/.dsh/profiles/web/cordis.patch.yml` 移除对应两块（或重装后 `--no-enable` 对照还原）。

---

## 🖥️ 兼容性

| 项 | 要求 |
|---|---|
| DSH | Web 版（`profiles/web`），静态插件机制 |
| 平台 | Windows（命令审查目标为 PowerShell，`pwsh` 工具） |
| 权限模式 | 仅 `almost-full-access` 模式启用门控，其余模式零开销 |

---

## 🧩 架构

```
cordis.patch.yml       权限预设表覆盖（🛡️ almost-full-access 档位）+ 插件挂载
lib/index.js           静态 Host 插件：门控 / 确定性分析 / 审批队列 / HTTP 端点 / 审计
lib/client.js          静态 Client 插件：风格A简约审批面板（conversation.input.overlay）
scripts/install.mjs    一键安装器（复制 + patch 幂等更新）
assets/afaccess-logo.svg  徽章 logo（盾牌 + 审查放大镜）
```

- Host 端点：`GET /api/afaccess/queue`（轮询）、`POST /api/afaccess/decide`（决策，要求 `x-afaccess-client: 1` 请求头 + 回环 Origin，防 CSRF）
- 审计日志：`$DSH_HOME/afaccess/afaccess.log`（审查结论与审批结果，密钥模式已脱敏）
- 诊断：`afaccess_status` 模型工具（状态 / 计数 / 队列 / 会话记忆）

## 🔒 安全说明

- 默认拒绝：无法审查、面板不可达、超时未决、命令被中止一律按拒绝处理；
- 确定性命中 → 必审批：LLM 子代理只能裁决「仅模糊」的命令，不能把确定性风险改判放行；
- 审查提示词声明命令文本完全不可信（防提示注入），代码围栏对 ``` 转义；
- 会话记忆仅存于进程内存（键=命令哈希），不持久化，重启即清；高风险命令不可记忆；
- 决策链路：审批队列（Host）→ 浏览器面板 → `decide` 端点校验随机 `approvalId` + 回环 Origin + 自定义头后生效，先到先得；
- 门控覆盖 `pwsh`/`bash`/`powershell`/`cmd` 等 shell 执行工具；若宿主注册了其它命令执行工具，不在本插件审查范围内——请在可信任务中使用本预设。

## 📦 发布

```bash
# GitHub
git init && git add -A && git commit -m "release v1.0.0"
git remote add origin git@github.com:Alnita-M/dsh-Almost_Full_Access.git
git push -u origin main

# npm（记得先改 package.json 的 repository 字段并 `npm login`）
npm publish
```

## 📄 License

[MIT](./LICENSE)
