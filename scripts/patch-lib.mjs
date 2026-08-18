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

export const PERMISSION_BLOCK = `# dsh-Almost Full Access: 权限模式预设（介于 workspace-write 与 Full access 之间）
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
        description: Full file access, but every pwsh/bash shell command is first reviewed by rules and a subagent; commands that may affect files outside the workspace, normal boot, or system drivers require explicit approval.
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
 */
export function replacePermissionBlock(text) {
	const txt = stripBom(text);
	const lines = txt.split(/\r?\n/);
	const meaningful = meaningfulPatchLines(txt);
	const start = meaningful.find(({ indent, content }) => indent === 0 && (content === "- id: permission" || /^-?\s*id:\s*permission\s*$/.test(content)));
	if (start === void 0) return { text: withoutEmptySequenceRoot(txt), replaced: false };
	// 下一个顶层条目（缩进 0 且以 "- " 开头，且不是该块自身的延续）
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
	const head = lines.slice(0, start.index).join("\n").trimEnd();
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