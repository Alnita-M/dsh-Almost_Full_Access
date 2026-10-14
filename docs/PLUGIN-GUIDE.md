# 🛡️ dsh-Almost Full Access — 插件简要说明

> 介于 **workspace-write** 与 **Full access** 之间的权限模式（v1.2.0）
> 支持 [DeepSeek Harness](https://github.com/deepseek-ai) (dsh) **桌面版（Electron）** 与 **Web 版**。

## 一、它是什么

在 **Full access** 的文件能力基础上，给 shell 命令加一道**轻量安全闸门**：

- **确定性规则**毫秒级拦截真正的危险命令（不可逆损失、系统级变更），弹出审批面板；
- **动态/间接命令**先交 **LLM 子代理快审**，判 risky 才弹面板，判 safe 直接放行；
- 其余（可逆写、安装软件、工作区内操作）**无感放行**——不繁琐、不打扰。

## 二、安装

```bash
# 方式 A：npm registry（推荐）
npm install -g dsh-almost-full-access
dsh-afaccess-install

# 方式 B：npx 从 GitHub（npm 12 需放行 git 源）
npx --yes --allow-git=all github:Alnita-M/dsh-Almost_Full_Access
```

安装后：**硬刷新浏览器** → 在会话权限选择器切换到 **🛡️ Almost Full Access**。

补丁写入哪些 profile：默认写入**已存在的客户端 profile**——`desktop`（桌面版）优先，其次 `web`；
两者都存在时都写。也可显式指定：

```bash
node scripts/install.mjs --profile desktop    # 只写桌面版
node scripts/install.mjs --all-profiles       # 写入所有已存在的 profile
node scripts/install.mjs --dry-run            # 只预览，不修改
```

`profiles/*/cordis.patch.yml` 由 `@deepseek-ai/dsh-hmr` 监听并**热重载**，通常**无需重启 dsh**；
若未生效再重启。插件包本体只装一份在 `profiles/node_modules/`，各 profile 共用。

要求：Node ≥ 16、dsh 桌面版或 Web 版。

## 三、使用

### 3.1 三条命令路径

| 命令类型 | 处理方式 |
|---|---|
| **不可逆损失**：删除/清空/覆写粉碎（`rm`、`ri`、`Remove-Item`、`shred`、`truncate`…）、卸载（`winget uninstall`、`pip uninstall`、`npm uninstall`、`msiexec /x`…）、格式化/分区 | 🔴 **弹审批面板** |
| **影响系统正确运行**：引导（`bcdedit`/`diskpart`/`format`/`shutdown`）、服务、驱动、HKLM 注册表、账户、策略、防火墙、计划任务、卷影副本、`setx /M`、**写系统关键路径**（`C:\Windows`、`Program Files`、`ProgramData`、`/etc`、`/usr`、`\\.\PhysicalDriveN` 等） | 🔴 **弹审批面板** |
| **动态/间接命令**：`iex`、`curl`/下载执行、`Start-Process`、`ssh`、`sudo`、脚本调用、`.NET` 写类调用、拼接/`$()` 构造 | 🟡 **LLM 子代理快审**（safe 放行 / risky 弹面板，同命令 5 分钟内复用结论） |
| **可逆/用户级**：工作区外新建/复制/解压/下载落地到普通路径、HKCU 注册表、安装软件、`setx` 无 /M、工作区内一切 | 🟢 **直接放行** |

### 3.2 审批面板操作

- **允许执行**（左）/ **拒绝执行**（右，默认焦点）· `Esc` = 拒绝；
- **记住本次会话的此命令**：内容完全相同的命令不再询问（按命令哈希记忆，进程内存，重启即清；高风险引导类命令不可记忆）；
- 10 分钟未决自动拒绝；面板不可达时自动降级为文本审批卡。

### 3.3 安全设计要点

- **确定性命中 → 必审批**：LLM 子代理不能把确定性风险改判放行（防提示注入）；
- **fail-closed**：审查失败、超时、命令被中止一律按拒绝处理；
- **CSRF 防护**：决策端点要求自定义请求头 + 回环 Origin；`approvalId` 为随机 UUID；
- **审计日志**：`$DSH_HOME/afaccess/afaccess.log`（密钥模式已脱敏）；
- **诊断**：会话中调用 `afaccess_status` 工具可查看状态/计数/队列/记忆。

## 四、常见问题

| 问题 | 说明 |
|---|---|
| 为什么安装软件不弹面板了？ | 安装可逆（可卸载），属于"可逆写"→ 直接放行；**卸载仍必拦** |
| 为什么 `curl -o C:\Windows\...` 被拦而 `curl -o C:\Users\me\...` 不拦？ | 前者写系统关键路径（影响系统运行），后者是可逆落地 |
| 动态命令安全吗？ | 每条动态命令都经 LLM 子代理审查后才执行；判 risky 需你人工确认 |
| 切回只读/workspace-write 模式会怎样？ | 门控自动关闭，插件零开销 |

## 五、卸载

```powershell
Remove-Item "$env:USERPROFILE\.dsh\profiles\node_modules\dsh-almost-full-access" -Recurse -Force
# 并从 ~/.dsh/profiles/<desktop|web>/cordis.patch.yml 移除「Almost Full Access」对应的两块
```

## 六、文档

- 完整 README：`README.md`
- 更新历史：`CHANGELOG.md`
- 安全策略：`SECURITY.md`
