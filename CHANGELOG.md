# 更新说明 Changelog

## v1.1.1（2026-09-10）— 适配 dsh 0.1.1-rc.2（破坏性 API 兼容修复）

> 修复 v1.1.0 在 dsh 升级到 0.1.1-rc.2 后的**门控静默失效**问题。

### 🐛 问题

dsh 0.1.1-rc.2 引入两处破坏性 API 变更，导致插件的命令门控完全失效（命令全部直接放行、无审查、无审批面板，且无任何报错）：

1. `permissionPresets.current()` 参数从 `events: SessionEvent[]` 改为 `session: Session`；
2. `Agent` 接口不再暴露 `session` 属性（仅剩 `id`）。

### 🔧 修复

- 新增 `sessionOf(agent)`：优先取 `agent.session`（兼容旧运行时），否则经 `sessions.get(agent.id)` 服务回退获取 Session；
- `currentPreset()` 改用新签名 `permissionPresets.current(session)`；
- `sessionWorkspace()` 同步适配；
- `inject` 声明补充 `sessions` 服务；
- 测试套件新增 **[13] 契约自检**（防止 API 回归）。

### 验证

- 204 项测试全部通过；
- 运行时验证需重启 dsh web 后生效（静态插件启动时加载）。

---

## v1.1.0（2026-08-18）— 审查模型重构：单一模式

> 本版本从 **v1.0.5** 起经历了一次大的规则与交互演进（开发期曾实现「Fast / Safe 双模式分支选择器」，最终按设计取舍**合并为单一 Almost Full Access 模式**）。以下为相对 v1.0.5 的全部变化。

### 🔄 核心变化：审查模型重构

| 维度 | v1.0.5（旧） | v1.1.0（新） |
|---|---|---|
| 权限预设 | 🛡️ Almost Full Access（全量规则） | 🛡️ Almost Full Access（**轻量规则 + 动态命令子代理审查**） |
| 确定性拦截范围 | 所有工作区外写 + 全部系统级规则 | **只拦两类**：① 不可逆损失（删除/清空/覆写粉碎/卸载/格式化/分区）；② 影响系统正确运行（引导/服务/驱动/系统注册表/账户/策略/防火墙/计划任务/卷影/`setx /M`/写系统关键路径） |
| 动态/间接命令 | LLM 子代理审查 | **LLM 子代理审查（保留）**，新增 **5 分钟同命令结果缓存**，不再重复起子代理 |
| 可逆写工作区外（新建/复制/解压/下载落地到普通路径） | 弹审批面板 | **直接放行**（可逆，删除即可恢复） |
| 安装软件（winget/pip/msiexec /i 等） | 弹审批面板 | **直接放行**（可逆，可卸载） |
| HKCU 用户注册表 / `setx`（无 /M） | 弹审批面板 | **直接放行**（用户级、可逆） |
| UI | — | 曾加入输入框 Fast/Safe 分支选择器，最终**移除**，回归单模式（无多余交互） |

### 🛡️ 确定性规则补强（严防死守）

- **不可逆删除类补齐**：PowerShell 别名 `ri`、`Clear-ItemProperty`、`deltree`、覆写粉碎类 `shred`、`sdelete`、`truncate`、`cipher /w`；
- **写动词表补齐**：`Replace-Item`、解压写入工具（`Expand-Archive`/`tar`/`unzip`/`7z`/`rar`，解压到系统路径同样拦截）；
- **下载落地拦截**：`curl -o/--output`、`-OutFile`、`-DestinationPath`、`certutil -urlcache/-decode/-encode`、`bitsadmin /transfer`（连字符与斜杠两种拼写均覆盖）——落地到系统关键路径即拦截，落地用户目录仍放行；
- **卸载类补齐**：`msiexec /x`、`winget/choco/scoop uninstall`、`pip uninstall`、`conda remove`、`gem uninstall`、`npm/pnpm/yarn uninstall|remove`、`cargo remove`、`dotnet tool uninstall`；
- **系统关键路径扩展**：`System Volume Information`、`$Recycle.Bin`、`Recovery`、`Windows.old`、`EFI`、POSIX 单级系统目录（`/etc`、`/usr` 等，`tar -C /etc` 场景）、**原始设备路径 `\\.\PhysicalDriveN` 与 `\Device\` 命名空间**（直写磁盘）；
- **POSIX 路径支持**：bash/WSL 下 `/etc/passwd` 等绝对路径纳入工作区外判定。

### ⚡ 审查去噪（不再繁琐）

- 读类 .NET 调用（`[Math]::Round`、`[DateTime]::Now`、`[Console]::WriteLine`）不再送子代理；
- 纯字符串拼接（`'a'+'b'`）与 `$()` 插值不再送审，**仅写意图命令内**的拼接/插值仍送审（防拼接构造写动词）；
- bash 后台符 `cmd1 & cmd2` 不再误送审（`&` 仅对 `& (...)`、`& '...'`、`& $var` 动态目标送审）；
- 常见只读/高频命令（`certutil -hashfile`、`wmic` 查询、`msbuild` 构建、`apt search`、`systemctl status`）无感放行。

### 🐛 修复

- `DOWNLOAD_WRITE_RE` 带 `g` 标志共享 `.test()` 导致 lastIndex 残留的偶发漏检；
- `\\.\` 原始设备前缀的 JS 转义错误（3 字符 vs 4 字符），现已正确判定；
- `bitsadmin /transfer` 斜杠拼写不匹配连字符规则。

### ⚙️ 其他

- 预设描述更新为「轻量规则 + 动态命令子代理审查」；
- 测试套件重构至 **198 项**（含单一模式拦截/放行/动态审查全矩阵与防误报回归）；
- 安装器、README 同步更新。

---

### 升级提示（从 v1.0.x 升级）

1. 重新运行安装器（`npm install -g dsh-almost-full-access && dsh-afaccess-install` 或 `npx --yes --allow-git=all github:Alnita-M/dsh-Almost_Full_Access`）；
2. 重启 dsh web 并硬刷新浏览器；
3. 行为变化提醒：**工作区外的可逆写与软件安装不再弹面板**（旧版会弹）；**删除/卸载/系统级/写系统目录仍然必拦**。如需更严格的逐条确认，请使用只读/workspace-write 模式。

---

## 历史版本

### v1.0.5（2026-08-17）— 规则精度调优

- `certutil` 仅写文件用途（`-urlcache/-decode/-encode`）送审，只读校验不送；
- `wmic` 仅 `process call create` 送审；移除 `msbuild/installutil` 全量误报；
- `sys:bash` 收紧为变更动词（`apt install` 拦、`apt update` 不拦）。

### v1.0.4（2026-08-17）— 规则盲区补强

- POSIX 绝对路径写目标；解压写入工具；账户/提权（`net user`/`net localgroup`）；`reg import`、`sc sdset`、`fltmc`、`vssadmin delete`、`setx`；LOLBin（`certutil`/`bitsadmin`/`regsvr32`/`rundll32`/`mshta`/`cscript`/`wscript`/`wmic`/`msbuild`）；`sudo`/`runas`/`cmd /c`；凭据工具（`mimikatz` 等）。

### v1.0.3（2026-08-17）— 安装器跨机器健壮性

- patch 编辑抽为可单测库；空/干净 patch 自动追加预设块；UTF-8 BOM 兼容；未装 dsh Web 时告警；`patch-lib.mjs` 入 npm 包清单；`engines node>=16`。

### v1.0.2（2026-08-17）— 安全审查修复（A1–A11）

- 别名写动词表、.NET/拼接/反引号模糊规则、相对路径穿越检测、确定性命中锁定必审批、随机 approvalId、CSRF 防护、按命令哈希记忆、abort fail-closed、审计日志迁移 DSH_HOME + 密钥脱敏、轮询新鲜度回退、body 上限/缓存 GC、安装器顶层块定位。

### v1.0.1 / v1.0.0

- 静态化发布、双路径引号提取与只读误判修复、初版规则库与安装器。
