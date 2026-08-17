# Security Policy

## Reporting a Vulnerability

本插件是命令审查/审批层，不替代操作系统沙箱。发现安全问题请通过 GitHub Issues
（标记 `security`）或直接联系维护者报告，请勿公开披露可利用的 0day。

## Scope

- `lib/index.js` 中的命令分析与审批队列逻辑；
- `lib/client.js` 审批面板的数据通道（同源 HTTP 端点）；
- `scripts/install.mjs` 安装器的文件操作与 patch 编辑（仅操作 `DSH_HOME` 内路径）。

## Notes

- 审批面板的 HTTP 端点仅供同源浏览器使用，不对外暴露；`decide` 要求自定义请求头
  `x-afaccess-client: 1` + 回环 Origin 校验（防 CSRF）；
- `approvalId` 为随机 UUID，不可枚举；
- 会话记忆仅存在于 Host 进程内存，键为命令哈希（同命令免重复审批），高风险
  （引导类）命令不可记忆；
- 确定性规则命中的命令锁定为必审批，LLM 子代理无法将其改判为 safe 放行；
- 审查提示词声明命令文本不可信（防提示注入），代码围栏对 ``` 做了转义；
- 命令在执行前被中断（abort）一律按拒绝处理（fail-closed）；
- 超时/降级一律按拒绝处理（fail-closed）；
- 审计日志写入 `$DSH_HOME/afaccess/afaccess.log`，常见密钥模式已脱敏；
- 门控覆盖 pwsh/bash/powershell/cmd 等 shell 执行工具；其他命令执行类工具
  （若宿主注册）不在审查范围，请在文档声明的边界内使用该预设。
