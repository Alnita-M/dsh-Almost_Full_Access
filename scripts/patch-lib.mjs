#!/usr/bin/env node
/**
 * dsh-Almost Full Access — cordis.patch.yml 编辑库（纯函数，可独立单测）
 * ============================================================
 * 被 scripts/install.mjs 与 scripts/test.mjs 引用。零依赖，不做任何 IO。
 *
 * 跨电脑安装健壮性（v1.0.3）：
 * - 剥离 UTF-8 BOM（Windows 记事本保存的 patch 常见），避免 `- id: permission`
 *   匹配失败；
 * - 新增 ensurePermissionBlock：当 patch 里没有顶层 permission 块（全新电脑
 *   或干净 profile）时**追加**预设块，而不是只挂载插件导致模式缺失；
 * - 用解析函数 patchCounts 代替脆弱正则统计块数量（BOM/缩进/嵌套免疫）。
 */
export const PKG_NAME = "dsh-almost-full-access";

/** 默认按此顺序挑选客户端 profile（两者都存在时都写入）。 */
export const CLIENT_PROFILES = ["desktop", "web"];

/** 本插件在 patch 中自有注释行的标记（用于收敛历史累积的重复注释）。 */
export const OWN_COMMENT_MARK = "dsh-Almost Full Access:";

export const PERMISSION_BLOCK = `# dsh-Almost Full Access: 权限模式预设（🛡️ Almost Full Access）
- id: permission
  config:
    presets:
      read-only:
        sandbox: read-only
        approval: ask
      workspace-write:
        sandbox: workspace-write
        approval: ask
      almost-full-access:
        sandbox: danger-full-access
        approval: never
        name: 🛡️ Almost Full Access
        description: Full file access with lightweight checks — only irreversible actions (deletes, uninstalls, formatting) and changes that affect normal boot or system/drivers require approval; dynamic/indirect commands are reviewed by a subagent before execution.
      danger-full-access:
        sandbox: danger-full-access
        approval: never

`;

export const INSERT_BLOCK = `# dsh-Almost Full Access: 插件本体挂载
- insert:
    - id: afaccess
      name: dsh-almost-full-access

`;

/** 剥离文件头 UTF-8 BOM。 */
export function stripBom(text) {
	return String(text).replace(/^\uFEFF/, "");
}

/** 解析有意义的 patch 行（剥离 BOM、忽略空行/注释/文档分隔符）。 */
export function meaningfulPatchLines(text) {
	return stripBom(text).split(/\r?\n/).map((line, index) => ({
		index,
		indent: line.match(/^[ \t]*/)?.[0].length ?? 0,
		content: line.trim()
	})).filter(({ content }) => content !== "" && !content.startsWith("#") && content !== "---" && content !== "...");
}

/** Remove a YAML document whose only value is the empty root sequence `[]`. */
export function withoutEmptySequenceRoot(text) {
	const txt = stripBom(text);
	const meaningful = meaningfulPatchLines(txt);
	if (meaningful.length === 0) return txt;
	const rootIndent = Math.min(...meaningful.map(({ indent }) => indent));
	const emptyRoot = meaningful.find(({ indent, content }) => indent === rootIndent && /^\[\](?:[ \t]+#.*)?$/.test(content));
	if (emptyRoot === void 0) return txt;
	const lines = txt.split(/\r?\n/);
	const inlineComment = lines[emptyRoot.index].match(/^([ \t]*)\[\][ \t]+(#.*)$/);
	if (inlineComment === null) lines.splice(emptyRoot.index, 1);
	else lines[emptyRoot.index] = `${inlineComment[1]}${inlineComment[2]}`;
	return lines.filter((line) => line.trim() !== "...").join("\n").trimEnd();
}

/**
 * 替换/追加 permission 预设块（config 为整体替换，必须完整覆盖 dsh-base 的预设表）。
 * 若已有顶层 `- id: permission`（缩进 0）条目，则从该行替换到下一个顶层条目之前。
 * 找不到顶层块时返回 { replaced:false }（由调用方 ensurePermissionBlock 兜底追加）。
 *
 * 幂等性（v1.2.0 修复）：替换范围要**连同该条目自己的注释行**一起吃掉，
 * 否则每重跑一次安装器就会多累积一行注释；同时替换区间的右边界要回退到
 * 下一个顶层条目的注释之前，否则那条注释会被误删。文件头部注释块永不吞噬。
 */
export function replacePermissionBlock(text) {
	const txt = stripBom(text);
	const lines = txt.split(/\r?\n/);
	const meaningful = meaningfulPatchLines(txt);
	const start = meaningful.find(({ indent, content }) => indent === 0 && (content === "- id: permission" || /^-?\s*id:\s*permission\s*$/.test(content)));
	if (start === void 0) return { text: withoutEmptySequenceRoot(txt), replaced: false };
	// 左边界：连同该条目自己的注释行一起替换（但不吃文件头部注释块，也不吃第 0 行）。
	// 只吞噬**本插件自有标记**的注释行（可跨其间的空行），这样历史版本累积的
	// 重复注释会在下次安装时收敛为一行，且绝不会误伤文件头或其它插件的注释。
	let headEnd = start.index;
	let cursor = headEnd - 1;
	let from = headEnd;
	let sawOwnComment = false;
	while (cursor >= 0) {
		const line = lines[cursor];
		if (/^[ \t]*#/.test(line)) {
			if (!line.includes(OWN_COMMENT_MARK)) break;
			sawOwnComment = true;
			from = cursor;
			cursor -= 1;
			continue;
		}
		if (sawOwnComment && /^[ \t]*$/.test(line)) {
			from = cursor;
			cursor -= 1;
			continue;
		}
		break;
	}
	if (sawOwnComment && from > 0) headEnd = from;
	// 右边界：下一个顶层条目（缩进 0 且以 "- " 开头，且不是该块自身的延续）
	let end = lines.length;
	for (let i = start.index + 1; i < lines.length; i++) {
		const line = lines[i];
		if (/^[ \t]*$/.test(line) || /^\s*#/.test(line)) continue;
		const indent = line.match(/^[ \t]*/)[0].length;
		if (indent === 0 && line.trim().startsWith("- ")) {
			end = i;
			break;
		}
	}
	// 右边界回退：保留下一个顶层条目自己的注释行
	while (end - 1 > start.index && /^[ \t]*#/.test(lines[end - 1])) end -= 1;
	const head = lines.slice(0, headEnd).join("\n").trimEnd();
	const tail = lines.slice(end).join("\n").trimStart();
	let out = head;
	if (head !== "") out += "\n\n";
	out += PERMISSION_BLOCK.trimEnd();
	if (tail !== "") out += "\n\n" + tail;
	return { text: out, replaced: true };
}

/** 确保顶层 permission 预设块存在（无则追加到末尾）——全新电脑空 patch 的关键兜底。 */
export function ensurePermissionBlock(text) {
	const txt = stripBom(text);
	const meaningful = meaningfulPatchLines(txt);
	const hasTop = meaningful.some(({ indent, content }) => indent === 0 && (content === "- id: permission" || /^-?\s*id:\s*permission\s*$/.test(content)));
	if (hasTop) return txt;
	const base = withoutEmptySequenceRoot(txt).trimEnd();
	return base === "" ? PERMISSION_BLOCK.trimEnd() : `${base}\n\n${PERMISSION_BLOCK.trimEnd()}`;
}

/** 确保插件 insert 块存在（幂等）。 */
export function ensureInsertBlock(text) {
	const txt = stripBom(text);
	if (meaningfulPatchLines(txt).some(({ content }) => content === "name: dsh-almost-full-access")) return txt;
	return txt.trim() === "" ? INSERT_BLOCK.trimEnd() : `${txt.trimEnd()}\n\n${INSERT_BLOCK.trimEnd()}`;
}

/** 解析式统计 patch 中的插件挂载与顶层 permission 块数量（BOM/缩进/嵌套免疫）。 */
export function patchCounts(text) {
	const meaningful = meaningfulPatchLines(text);
	return {
		plugin: meaningful.filter(({ content }) => content === "name: dsh-almost-full-access").length,
		permission: meaningful.filter(({ indent, content }) => indent === 0 && (content === "- id: permission" || /^-?\s*id:\s*permission\s*$/.test(content))).length
	};
}

/**
 * 选出本次要写入补丁的 profile（纯函数，便于单测）。
 * - 显式 requested（--profile）优先，去重后原样使用；
 * - allProfiles（--all-profiles）→ 所有已存在的 profile；
 * - 否则默认取已存在的客户端 profile（desktop 优先，其次 web）。
 * 旧版安装器把目标硬编码为 web，桌面版（Electron）因此装了不生效。
 * @param {object} input
 * @param {string[]} [input.present]   $DSH_HOME/profiles 下已存在的 profile 名
 * @param {string[]} [input.requested] 显式指定的 profile 名
 * @param {boolean} [input.allProfiles]
 * @returns {{targets: string[], explicit: boolean}}
 */
export function selectTargetProfiles({ present = [], requested = [], allProfiles = false } = {}) {
	if (requested.length > 0) return { targets: [...new Set(requested)], explicit: true };
	if (allProfiles) return { targets: [...present], explicit: false };
	return { targets: CLIENT_PROFILES.filter((name) => present.includes(name)), explicit: false };
}