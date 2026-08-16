# 🛡️ dsh-Almost Full Access

介于 **workspace-write** 与 **Full access** 之间的权限模式，专为 [DeepSeek Harness](https://github.com/deepseek-ai) (dsh) Web 版设计。

在该模式下，文件沙箱与 Full access 相同（无限制），但**每一条 shell 命令**都会先经过两层审查：

1. **确定性快路径（毫秒级）**：危险动词表（`bcdedit` / `diskpart` / `Stop-Service` / `pnputil` / `takeown` / `reg add HKLM` / `winget` …）+ 工作区外写路径包含判断（与沙箱同款边界逻辑，支持 `C:\`、`%TEMP%`、`$env:`、UNC、注册表路径）。
2. **LLM 子代理兜底**：只有动态/间接命令（`iex`、`Invoke-WebRequest`、下载、外部程序调用等）才起子代理审查。

命中风险 → 弹出**风格 A 简约审批面板**（悬浮于输入框上方，蓝色品牌盾牌 logo）：

- 风险徽章（高风险/中风险/需确认）+ 判定来源
- 命令单行摘要（点击展开全文、一键复制）
- 逐条影响列表（高风险首条红色强调）
- 工作区/工作目录上下文
- **允许执行**（左，次按钮）/ **拒绝执行**（右，主按钮）· `Esc` = 拒绝
- **记住本次会话的此类操作**：同类命令（按类别键如 `sys:service`、`write-outside`）此后自动按记忆决策，不再弹面板
- 10 分钟未决自动拒绝；Client 面板不可用时自动降级为文本审批卡

安全命令毫秒放行、零开销；切回其它权限模式（只读/工作区/Full access）时门控自动关闭。

---

## ✨ 一键安装

### 方式 A：npx（从 GitHub 直接安装，推荐）

```bash
npx --yes github:<your-github-username>/dsh-almost-full-access
```

### 方式 B：npm 全局安装后运行安装器

```bash
npm install -g dsh-almost-full-access
dsh-afaccess-install
```

### 方式 C：本地开发

```bash
git clone https://github.com/<your-github-username>/dsh-almost-full-access.git
cd dsh-almost-full-access
node scripts/install.mjs --dry-run   # 先预览
node scripts/install.mjs             # 实际安装
```

> 安装器会把插件复制到 `~/.dsh/profiles/node_modules/dsh-almost-full-access/`，
> 并幂等更新 `~/.dsh/profiles/web/cordis.patch.yml`（权限预设表 + 插件挂载）。
> 其他安装器选项：`--check` / `--dry-run` / `--no-enable` / `--help`。

### 安装后

1. **重启 dsh web**（静态插件随 DSH 启动自动加载，无需在会话中激活）；
2. 硬刷新浏览器（Ctrl+Shift+R）；
3. 在会话权限选择器中切换到 **🛡️ Almost Full Access**（位于 workspace-write 与 Full access 之间）；
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

- Host 端点：`GET /api/afaccess/queue`（轮询）、`POST /api/afaccess/decide`（决策）
- 审计日志：工作区根目录 `.afaccess-debug.log`（每条命令的审查结论与审批结果）
- 诊断：`afaccess_status` 模型工具（状态 / 计数 / 队列 / 会话记忆）

## 🔒 安全说明

- 默认拒绝：无法审查、面板不可达、超时未决一律按拒绝处理；
- 会话记忆仅存于进程内存，不持久化，重启即清；
- 决策链路：审批队列（Host）→ 浏览器面板 → `decide` 端点校验 `approvalId` 归属后生效，先到先得。

## 📦 发布

```bash
# GitHub
git init && git add -A && git commit -m "release v1.0.0"
git remote add origin git@github.com:<your-github-username>/dsh-almost-full-access.git
git push -u origin main

# npm（记得先改 package.json 的 repository 字段并 `npm login`）
npm publish
```

## 📄 License

[MIT](./LICENSE)
