# Security Policy

## Reporting a Vulnerability

本插件是命令审查/审批层，不替代操作系统沙箱。发现安全问题请通过 GitHub Issues
（标记 `security`）或直接联系维护者报告，请勿公开披露可利用的 0day。

## Scope

- `lib/index.js` 中的命令分析与审批队列逻辑；
- `lib/client.js` 审批面板的数据通道（同源 HTTP 端点）；
- `scripts/install.mjs` 安装器的文件操作与 patch 编辑（仅操作 `DSH_HOME` 内路径）。

## Notes

- 审批面板的 HTTP 端点仅供同源浏览器使用，不对外暴露；
- 会话记忆仅存在于 Host 进程内存；
- 超时/降级一律按拒绝处理（fail-closed）。
