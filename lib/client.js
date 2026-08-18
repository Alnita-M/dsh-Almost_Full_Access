/**
 * dsh-Almost Full Access — 静态 Client 半区（浏览器）
 * ============================================================
 * 标准 dsh 客户端模块格式：window.__ModuleLoader__.load({ id, factory })。
 * 通过 package.json 的 dsh.client 声明 + exports["./client"] 被发现，
 * 由 dsh-client-modules 扫描加载 —— 重启后 UI 永久存在。
 *
 * 职责：在 conversation.input.overlay 槽位渲染「风格A简约」审批面板
 * （与斜杠菜单同款绝对定位浮层），轮询 Host 的 /api/afaccess/queue，
 * 用户决策 POST /api/afaccess/decide。CSS 使用 --dsw-alias-* 产品变量，
 * 自动跟随 light/dark 主题。
 */
window.__ModuleLoader__.load({
	id: "dsh-almost-full-access",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

		let React = require("react");

		//#region css（风格A简约 · 令牌=产品变量+规格fallback）
		const css = [
			".afacc-float{position:absolute;bottom:calc(100% + 10px);left:50%;transform:translateX(-50%);z-index:100;display:flex;flex-direction:column;align-items:center;width:min(560px,calc(100vw - 32px))}",
			".afacc-panel{box-sizing:border-box;width:100%;border-radius:10px;border:1px solid var(--dsw-alias-border-l1,#E5E7EB);background:var(--dsw-alias-bg-layer-2,#FFFFFF);box-shadow:0 4px 16px rgba(16,24,40,.10);overflow:hidden;font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",\"PingFang SC\",\"Microsoft YaHei\",sans-serif;color:var(--dsw-alias-label-primary,#1F2329)}",
			".afacc-header{display:flex;align-items:center;padding:12px 14px;border-bottom:1px solid var(--dsw-alias-border-l1,#E5E7EB)}",
			".afacc-title{font-size:13px;font-weight:600;white-space:nowrap;margin-left:8px}",
			".afacc-id{margin-left:8px;font-size:10px;font-family:\"SF Mono\",\"JetBrains Mono\",Consolas,\"Courier New\",monospace;color:var(--dsw-alias-label-tertiary,#9CA3AF);white-space:nowrap}",
			".afacc-close{margin-left:auto;width:24px;height:24px;border:none;border-radius:6px;background:transparent;color:var(--dsw-alias-label-secondary,#6B7280);cursor:pointer;font-size:14px;line-height:24px;padding:0}",
			".afacc-close:hover{background:var(--dsw-alias-interactive-bg-hover,#F2F4F7);color:var(--dsw-alias-label-primary,#1F2329)}",
			".afacc-body{padding:12px 14px}",
			".afacc-badge-row{display:flex;align-items:center;margin-bottom:10px}",
			".afacc-badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600;line-height:16px}",
			".afacc-badge-high{background:var(--dsw-alias-interactive-bg-hover-danger,#FDECEC);color:var(--dsw-alias-state-error-primary,#DC2626)}",
			".afacc-badge-medium{background:var(--dsw-alias-interactive-bg-hover-warn,#FDF3E3);color:var(--dsw-alias-state-warn-primary,#D97706)}",
			".afacc-badge-low{background:var(--dsw-alias-interactive-bg-hover-info,#EFF4FF);color:var(--dsw-alias-brand-primary,#2563EB)}",
			".afacc-source{margin-left:8px;font-size:11px;color:var(--dsw-alias-label-secondary,#6B7280)}",
			".afacc-cmd{display:flex;align-items:flex-start;gap:6px;padding:6px 10px;border-radius:6px;background:var(--dsw-alias-bg-layer-1,#FAFBFC);border:1px solid var(--dsw-alias-border-l2,#EEF0F3);cursor:pointer}",
			".afacc-cmd code{flex:1;min-width:0;font-family:\"SF Mono\",\"JetBrains Mono\",Consolas,\"Courier New\",monospace;font-size:12.5px;line-height:20px;color:var(--dsw-alias-label-primary,#1F2329);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;word-break:break-all}",
			".afacc-cmd.afacc-open code{white-space:pre-wrap;max-height:220px;overflow:auto}",
			".afacc-copy{flex:none;width:24px;height:24px;border-radius:6px;border:1px solid var(--dsw-alias-border-l1,#E5E7EB);background:var(--dsw-alias-bg-layer-2,#FFFFFF);color:var(--dsw-alias-label-secondary,#6B7280);cursor:pointer;font-size:12px;line-height:22px;padding:0}",
			".afacc-copy:hover{border-color:var(--dsw-alias-brand-primary,#2563EB);color:var(--dsw-alias-brand-primary,#2563EB)}",
			".afacc-copy.afacc-copied{color:var(--dsw-alias-state-success-primary,#16A34A);border-color:var(--dsw-alias-state-success-primary,#16A34A)}",
			".afacc-truncated{font-size:11px;color:var(--dsw-alias-label-tertiary,#9CA3AF);margin-top:2px}",
			".afacc-impacts{margin-top:10px}",
			".afacc-impact-title{font-size:11px;font-weight:600;color:var(--dsw-alias-label-secondary,#6B7280)}",
			".afacc-impacts ul{margin:4px 0 0 0;padding:0 0 0 18px;list-style:none}",
			".afacc-impacts li{margin-bottom:4px;display:flex}",
			".afacc-num{font-size:11px;color:var(--dsw-alias-label-tertiary,#9CA3AF);margin-right:6px;flex:none}",
			".afacc-imp-text{font-size:12.5px;line-height:20px;color:var(--dsw-alias-label-primary,#1F2329)}",
			".afacc-imp-text.afacc-top{color:var(--dsw-alias-state-error-primary,#DC2626);font-weight:600}",
			".afacc-more{border:none;background:transparent;padding:0;cursor:pointer;font-size:11px;font-weight:600;color:var(--dsw-alias-brand-primary,#2563EB);font-family:inherit}",
			".afacc-more:hover{color:var(--dsw-alias-brand-primary-hover,#1D4ED8)}",
			".afacc-context{margin-top:8px;font-size:11px;line-height:18px;color:var(--dsw-alias-label-tertiary,#9CA3AF);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}",
			".afacc-remember{display:flex;align-items:center;margin-top:10px;cursor:pointer;font-family:inherit}",
			".afacc-remember input{width:18px;height:18px;accent-color:var(--dsw-alias-brand-primary,#2563EB);margin:0;cursor:pointer}",
			".afacc-remember span{margin-left:8px;font-size:12px;color:var(--dsw-alias-label-primary,#1F2329)}",
			".afacc-footer{padding:12px 14px;border-top:1px solid var(--dsw-alias-border-l2,#EEF0F3)}",
			".afacc-actions{display:flex;justify-content:flex-end;gap:8px}",
			".afacc-btn{height:30px;padding:0 14px;border-radius:6px;font-size:12px;cursor:pointer;font-family:inherit}",
			".afacc-btn:disabled{opacity:.55;cursor:not-allowed}",
			".afacc-btn-allow{background:transparent;color:var(--dsw-alias-label-secondary,#6B7280);border:1px solid var(--dsw-alias-border-l1,#E5E7EB);font-weight:400}",
			".afacc-btn-allow:hover:not(:disabled){border-color:var(--dsw-alias-brand-primary,#2563EB);color:var(--dsw-alias-brand-primary,#2563EB)}",
			".afacc-btn-deny{background:var(--dsw-alias-state-error-primary,#DC2626);color:#FFFFFF;border:none;font-weight:600}",
			".afacc-btn-deny:hover:not(:disabled){filter:brightness(.92)}",
			".afacc-result{display:flex;justify-content:flex-end;align-items:center;gap:8px}",
			".afacc-result-text{font-size:12.5px;font-weight:600}",
			".afacc-result-approved{color:var(--dsw-alias-state-success-primary,#16A34A)}",
			".afacc-result-denied{color:var(--dsw-alias-state-error-primary,#DC2626)}",
			".afacc-result-neutral{color:var(--dsw-alias-label-secondary,#6B7280)}",
			".afacc-auto{font-size:11px;color:var(--dsw-alias-label-tertiary,#9CA3AF)}",
			".afacc-queue{padding:6px 12px;font-size:12px;color:var(--dsw-alias-label-secondary,#6B7280)}",
			".afacc-cleared{padding:6px 12px;font-size:12px;color:var(--dsw-alias-state-success-primary,#16A34A)}",
			".afacc-error{box-sizing:border-box;width:min(560px,calc(100vw - 32px));padding:8px 12px;border-radius:6px;border:1px solid var(--dsw-alias-state-error-primary,#DC2626);background:var(--dsw-alias-interactive-bg-hover-danger,#FDECEC);color:var(--dsw-alias-state-error-primary,#DC2626);font-size:12px;display:flex;align-items:center;gap:8px;font-family:inherit}",
			".afacc-error button{height:24px;padding:0 10px;border-radius:6px;border:1px solid var(--dsw-alias-state-error-primary,#DC2626);background:transparent;color:var(--dsw-alias-state-error-primary,#DC2626);font-size:12px;cursor:pointer;font-family:inherit}",
			".afacc-decide-error{padding:8px 14px;border-top:1px solid var(--dsw-alias-border-l2,#EEF0F3);background:var(--dsw-alias-interactive-bg-hover-danger,#FDECEC);color:var(--dsw-alias-state-error-primary,#DC2626);font-size:11px}",
			// v1.1.0：分支选择器（Fast/Safe，位于权限模式控件右侧的工具行）
			".afacc-mode{display:flex;align-items:center;gap:4px;padding:2px;border-radius:8px;background:var(--dsw-alias-bg-layer-1,#FAFBFC);border:1px solid var(--dsw-alias-border-l2,#EEF0F3)}",
			".afacc-mode-label{font-size:11px;color:var(--dsw-alias-label-secondary,#6B7280);margin:0 2px;white-space:nowrap}",
			".afacc-mode-btn{height:22px;padding:0 10px;border-radius:6px;border:1px solid transparent;background:transparent;color:var(--dsw-alias-label-secondary,#6B7280);font-size:11px;font-weight:600;cursor:pointer;font-family:inherit}",
			".afacc-mode-btn:hover:not(:disabled){color:var(--dsw-alias-brand-primary,#2563EB)}",
			".afacc-mode-btn.afacc-mode-active{background:var(--dsw-alias-brand-primary,#2563EB);color:#FFFFFF}",
			".afacc-mode-btn:disabled{opacity:.6;cursor:default}"
		].join("\n");
		const cssTagId = "afaccess-panel-css";
		if (typeof document !== "undefined" && document.querySelector("style[data-plugin-css=\"" + cssTagId + "\"]") === null) {
			const tag = document.createElement("style");
			tag.dataset.plugin = "dsh-almost-full-access";
			tag.dataset.pluginCss = cssTagId;
			tag.textContent = css;
			document.head.append(tag);
		}
		//#endregion

		//#region store + 数据通道（同源 fetch）
		const store = { items: [], error: false, revision: 0, decidedLocal: {}, hideUntil: {}, clearedAt: 0, remember: false, deciding: false, decideError: "" };
		const listeners = new Set();
		const emit = () => { store.revision += 1; listeners.forEach((cb) => cb()); };
		const subscribe = (cb) => { listeners.add(cb); return () => listeners.delete(cb); };

		let pollTimer = null;
		let failStreak = 0;
		let lastEmptyAt = 0;
		let lastItemsJson = "";

		async function poll() {
			try {
				const res = await fetch("/api/afaccess/queue", { headers: { accept: "application/json" } });
				const data = await res.json();
				if (data !== null && typeof data === "object" && data.ok === true && Array.isArray(data.items)) {
					failStreak = 0;
					store.error = false;
					if (data.items.length === 0) {
						if (Date.now() - lastEmptyAt < 10000) return;
						lastEmptyAt = Date.now();
					} else {
						lastEmptyAt = 0;
					}
					const json = JSON.stringify(data.items);
					if (json !== lastItemsJson) {
						lastItemsJson = json;
						store.items = data.items;
						emit();
					}
					return;
				}
			} catch (err) { }
			failStreak += 1;
			if (failStreak >= 3) store.error = true;
			emit();
		}

		function startPoll() {
			if (pollTimer === null) pollTimer = setInterval(poll, 2000);
		}

		async function decide(approvalId, decision, remember) {
			if (store.deciding) return false;
			store.deciding = true;
			store.decideError = "";
			emit();
			try {
				const payload = { approvalId: approvalId, decision: decision };
				if (remember === true) payload.remember = true; // A5/A6：键由服务端绑定（回忆命令哈希），客户端只声明意图
				const res = await fetch("/api/afaccess/decide", {
					method: "POST",
					headers: { "content-type": "application/json", accept: "application/json", "x-afaccess-client": "1" }, // A5：CSRF 防护头
					body: JSON.stringify(payload)
				});
				const data = await res.json();
				if (data !== null && typeof data === "object" && data.ok === true) {
					store.decidedLocal[approvalId] = decision;
					setTimeout(() => {
						store.hideUntil[approvalId] = true;
						const left = store.items.filter((it) => it.approvalId !== approvalId && it.decision === null);
						if (left.length === 0) {
							store.clearedAt = Date.now();
							setTimeout(() => { store.clearedAt = 0; emit(); }, 1600);
						}
						emit();
					}, 1400);
					emit();
					store.deciding = false;
					return true;
				}
				store.decideError = "决策未生效: " + (data !== null && typeof data === "object" && data.reason ? data.reason : "unknown");
			} catch (err) {
				store.decideError = "决策失败: " + (err && err.message ? err.message : String(err));
			}
			store.deciding = false;
			emit();
			return false;
		}
		//#endregion

		//#region 分支选择器数据通道（Fast/Safe）
		const modeStore = { mode: "safe", preset: "unknown", syncing: false };
		let modeTimer = null;

		async function fetchMode(sessionId) {
			try {
				const res = await fetch("/api/afaccess/mode?session=" + encodeURIComponent(sessionId || ""), { headers: { accept: "application/json" } });
				const data = await res.json();
				if (data !== null && typeof data === "object" && data.ok === true) {
					const nextMode = data.mode === "fast" ? "fast" : "safe";
					const nextPreset = typeof data.preset === "string" ? data.preset : "unknown";
					if (nextMode !== modeStore.mode || nextPreset !== modeStore.preset) {
						modeStore.mode = nextMode;
						modeStore.preset = nextPreset;
						emit();
					}
				}
			} catch (err) { }
		}

		async function setMode(sessionId, mode) {
			if (modeStore.syncing || sessionId === "") return;
			modeStore.syncing = true;
			emit();
			try {
				const res = await fetch("/api/afaccess/mode", {
					method: "POST",
					headers: { "content-type": "application/json", accept: "application/json", "x-afaccess-client": "1" },
					body: JSON.stringify({ session: sessionId, mode: mode })
				});
				const data = await res.json();
				if (data !== null && typeof data === "object" && data.ok === true) {
					modeStore.mode = data.mode === "fast" ? "fast" : "safe";
				}
			} catch (err) { }
			modeStore.syncing = false;
			emit();
		}
		//#endregion

		//#region 组件
		function shieldIcon() {
			return React.createElement("svg", { viewBox: "0 0 48 48", width: 15, height: 15, "aria-hidden": true, style: { display: "block", flex: "none" } },
				React.createElement("path", { d: "M24 4 C18.5 4 13.5 6 9 8.5 L9 23 C9 33 15.5 41 24 44 Z", fill: "var(--dsw-alias-brand-primary,#2563EB)", opacity: 0.9 }),
				React.createElement("path", { d: "M24 4 C29.5 4 34.5 6 39 8.5 L39 23 C39 33 32.5 41 24 44 Z", fill: "var(--dsw-alias-brand-primary,#2563EB)", opacity: 0.45 }),
				React.createElement("path", { d: "M19.5 23 L22.5 26 L29 18.5", fill: "none", stroke: "#FFFFFF", strokeWidth: 4, strokeLinecap: "round", strokeLinejoin: "round" })
			);
		}

		function PanelHeader(props) {
			return React.createElement("div", { className: "afacc-header" },
				shieldIcon(),
				React.createElement("span", { className: "afacc-title", id: "afacc-title" }, "Almost Full Access · 命令审批"),
				React.createElement("span", { className: "afacc-id" }, props.record.approvalId),
				React.createElement("button", { type: "button", className: "afacc-close", "aria-label": "拒绝并关闭 (Esc)", onClick: props.onClose }, "×")
			);
		}

		function RiskBadge(props) {
			const sev = props.severity === "high" ? "high" : props.severity === "low" ? "low" : "medium";
			const label = { high: "高风险", medium: "中风险", low: "需确认" }[sev];
			const srcText = props.source === "deterministic" ? "来源: 规则命中" : props.source === "llm" ? "来源: 子代理审查" : "来源: 审查降级";
			return React.createElement("div", { className: "afacc-badge-row" },
				React.createElement("span", { className: "afacc-badge afacc-badge-" + sev }, label),
				React.createElement("span", { className: "afacc-source", title: "判定来源: " + props.source }, srcText)
			);
		}

		function CommandSummary(props) {
			const [expanded, setExpanded] = React.useState(false);
			const [copied, setCopied] = React.useState(false);
			const doCopy = (e) => {
				e.stopPropagation();
				try {
					if (typeof navigator !== "undefined" && navigator.clipboard) {
						navigator.clipboard.writeText(props.record.command).then(() => {
							setCopied(true);
							setTimeout(() => setCopied(false), 1200);
						}).catch(() => { });
					}
				} catch (err) { }
			};
			return React.createElement("div", null,
				React.createElement("div", {
					className: "afacc-cmd" + (expanded ? " afacc-open" : ""),
					onClick: () => setExpanded(!expanded),
					title: expanded ? "点击收起" : "点击展开全文"
				},
					React.createElement("code", null, props.record.command),
					React.createElement("button", { type: "button", className: "afacc-copy" + (copied ? " afacc-copied" : ""), "aria-label": "复制命令", onClick: doCopy }, copied ? "✓" : "⧉")
				),
				props.record.truncated === true ? React.createElement("div", { className: "afacc-truncated" }, "…(已截断)") : null
			);
		}

		function ImpactList(props) {
			const [expanded, setExpanded] = React.useState(false);
			const impacts = props.record.impacts || [];
			const shown = expanded ? impacts : impacts.slice(0, 2);
			const nums = ["①", "②", "③", "④", "⑤", "⑥", "⑦", "⑧", "⑨", "⑩"];
			const highEmphasis = props.record.severity === "high";
			return React.createElement("div", { className: "afacc-impacts" },
				React.createElement("div", { className: "afacc-impact-title", id: "afacc-impact" }, "影响"),
				React.createElement("ul", null,
					shown.map((imp, i) => React.createElement("li", { key: i },
						React.createElement("span", { className: "afacc-num" }, nums[i % 10] || (i + 1) + "."),
						React.createElement("span", { className: "afacc-imp-text" + (highEmphasis && i === 0 ? " afacc-top" : "") }, imp)
					))
				),
				!expanded && impacts.length > 2
					? React.createElement("button", { type: "button", className: "afacc-more", onClick: () => setExpanded(true) }, "+" + (impacts.length - 2) + " 更多 …")
					: null
			);
		}

		function ContextLine(props) {
			const ws = props.record.workspaceRoot || "（未知）";
			const wd = props.record.workdir || "（默认）";
			const ellipsis = (s) => s.length > 51 ? s.slice(0, 24) + " … " + s.slice(s.length - 24) : s;
			return React.createElement("div", { className: "afacc-context" }, "工作区: " + ellipsis(ws) + " · 目录: " + wd);
		}

		function RememberCheckbox(props) {
			return React.createElement("label", { className: "afacc-remember", title: "相同命令（内容完全一致）在本会话内不再弹面板" },
				React.createElement("input", { type: "checkbox", checked: props.checked, onChange: (e) => props.onChange(e.target.checked) }),
				React.createElement("span", null, "记住本次会话的此命令（相同命令不再询问）")
			);
		}

		function DecisionBar(props) {
			return React.createElement("div", { className: "afacc-actions" },
				React.createElement("button", { type: "button", className: "afacc-btn afacc-btn-allow", disabled: props.busy, onClick: props.onAllow }, "允许执行"),
				React.createElement("button", { type: "button", className: "afacc-btn afacc-btn-deny", disabled: props.busy, autoFocus: true, onClick: props.onDeny }, "拒绝执行")
			);
		}

		function ResultState(props) {
			const d = props.decision;
			const map = {
				approved: ["✓ 已允许执行", "afacc-result-approved"],
				denied: ["✕ 已拒绝", "afacc-result-denied"],
				aborted: ["已取消(未执行)", "afacc-result-neutral"],
				"timeout-denied": ["已取消(未执行)", "afacc-result-neutral"]
			};
			const c = map[d] || ["已取消(未执行)", "afacc-result-neutral"];
			return React.createElement("div", { className: "afacc-result", "aria-live": "polite" },
				React.createElement("span", { className: "afacc-result-text " + c[1] }, c[0]),
				props.auto === true ? React.createElement("span", { className: "afacc-auto" }, "auto (remembered)") : null
			);
		}

		function ApprovalRoot() {
			const [, setRev] = React.useState(0);
			React.useEffect(() => subscribe(() => setRev((r) => r + 1)), []);
			React.useEffect(() => { startPoll(); return () => { if (pollTimer !== null) { clearInterval(pollTimer); pollTimer = null; } }; }, []);
			const visible = store.items.filter((it) => store.hideUntil[it.approvalId] !== true);
			const head = visible[0];
			const rest = Math.max(0, visible.length - 1);
			const error = store.error;
			const cleared = store.clearedAt !== 0 && Date.now() - store.clearedAt < 1600 && visible.length === 0;

			if (error) {
				return React.createElement("div", { className: "afacc-float" },
					React.createElement("div", { className: "afacc-error" },
						React.createElement("span", { style: { flex: 1 } }, "⚠ 审批服务不可用,命令已被挂起"),
						React.createElement("button", { type: "button", onClick: () => { store.error = false; failStreak = 0; poll(); } }, "重试")
					)
				);
			}
			if (!head) {
				if (cleared) {
					return React.createElement("div", { className: "afacc-float" },
						React.createElement("div", { className: "afacc-cleared" }, "✓ 审批队列已清空,无等待项")
					);
				}
				return null;
			}

			const rec = head;
			const decided = rec.decision !== null ? rec.decision : (store.decidedLocal[rec.approvalId] || null);
			const canRemember = rec.rememberable !== false; // A6：高风险（引导类）命令不可记忆
			const rememberPayload = store.remember === true && canRemember;

			return React.createElement("div", { className: "afacc-float" },
				rest > 0 ? React.createElement("div", { className: "afacc-queue" }, "等待审批 ×" + rest) : null,
				React.createElement("section", {
					className: "afacc-panel",
					role: "alertdialog",
					"aria-labelledby": "afacc-title",
					"aria-describedby": "afacc-impact",
					"data-approval-id": rec.approvalId,
					"data-severity": rec.severity || "medium"
				},
					React.createElement(PanelHeader, { record: rec, onClose: () => { if (decided === null) decide(rec.approvalId, "denied", false); } }),
					React.createElement("div", { className: "afacc-body" },
						React.createElement(RiskBadge, { severity: rec.severity || "medium", source: rec.source || "degraded" }),
						React.createElement(CommandSummary, { record: rec }),
						React.createElement(ImpactList, { record: rec }),
						React.createElement(ContextLine, { record: rec }),
						decided === null && canRemember ? React.createElement(RememberCheckbox, { checked: store.remember, onChange: (v) => { store.remember = v; emit(); } }) : null
					),
					React.createElement("div", { className: "afacc-footer" },
						decided === null
							? React.createElement(DecisionBar, {
								busy: store.deciding,
								onAllow: () => decide(rec.approvalId, "approved", rememberPayload),
								onDeny: () => decide(rec.approvalId, "denied", rememberPayload)
							})
							: React.createElement(ResultState, { decision: decided, auto: rec.auto === true })
					),
					store.decideError !== "" ? React.createElement("div", { className: "afacc-decide-error" }, store.decideError) : null
				)
			);
		}
		//#endregion

		//#region 分支选择器（Fast/Safe，位于权限模式控件右侧的工具行）
		function ModeSelector(props) {
			const [, setRev] = React.useState(0);
			const sessionId = props && typeof props.sessionId === "string" ? props.sessionId : "";
			React.useEffect(() => subscribe(() => setRev((r) => r + 1)), []);
			React.useEffect(() => { fetchMode(sessionId); }, [sessionId]);
			React.useEffect(() => {
				if (modeTimer === null) modeTimer = setInterval(() => fetchMode(sessionId), 4000);
				return () => { if (modeTimer !== null) { clearInterval(modeTimer); modeTimer = null; } };
			}, [sessionId]);
			// 仅在会话处于 Almost Full Access 预设时显示
			if (modeStore.preset !== "almost-full-access") return null;
			const btn = (m, label, tip) => React.createElement("button", {
				type: "button",
				className: "afacc-mode-btn" + (modeStore.mode === m ? " afacc-mode-active" : ""),
				disabled: modeStore.syncing,
				title: tip,
				onClick: () => setMode(sessionId, m),
				"aria-pressed": modeStore.mode === m
			}, label);
			return React.createElement("div", { className: "afacc-mode", role: "group", "aria-label": "Almost Full Access 审查分支" },
				React.createElement("span", { className: "afacc-mode-label" }, "分支"),
				btn("fast", "Fast", "Fast Mode：只拦不可逆损失/影响系统正确运行的严肃命令，动态命令直接放行"),
				btn("safe", "Safe", "Safe Mode：每条 shell 命令都经规则 + 子代理审查（默认）")
			);
		}
		//#endregion

		// Esc = 拒绝
		if (typeof document !== "undefined") {
			document.addEventListener("keydown", (e) => {
				if (e.key === "Escape" && store.items.length > 0) {
					const head = store.items.find((it) => store.hideUntil[it.approvalId] !== true && it.decision === null);
					if (head) decide(head.approvalId, "denied", false);
				}
			});
		}

		// 面板渲染完全由 Host 审批队列驱动：只有 Almost Full Access 模式才会入队
		exports.inject = ["slots", "timer"];
		exports.apply = (ctx) => {
			const slots = ctx.get("slots");
			if (slots === undefined) return;
			ctx.effect(() => slots.inject("conversation.input.overlay", () => slots.register(
				{ name: "conversation.input.overlay", id: "afacc-approval" },
				() => React.createElement(ApprovalRoot, null)
			)), "afaccess: approval panel slot");
			// v1.1.0：分支选择器 —— 输入框工具行内、权限模式控件右侧（conversation.input.left）
			ctx.effect(() => slots.inject("conversation.input.left", () => slots.register(
				{ name: "conversation.input.left", id: "afacc-mode" },
				(props) => React.createElement(ModeSelector, { sessionId: props && props.sessionId })
			)), "afaccess: branch selector slot");
		};
		return module.exports;
	}
});
