#!/usr/bin/env node
/**
 * dsh-Almost Full Access — 一键安装器
 * ============================================================
 * 用法：
 *   npx --yes github:Alnita-M/dsh-Almost_Full_Access [options]
 *   或本地：node scripts/install.mjs [options]
 *
 * 选项：
 *   --check      校验已安装的包与 patch（不修改）
 *   --dry-run    打印将执行的安装路径与变更
 *   --no-enable  只复制文件，不修改 cordis.patch.yml
 *   --help       帮助
 *
 * 默认 DSH_HOME=~/.dsh。安装后重启 dsh web 并硬刷新浏览器。
 */
import { cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const knownFlags = new Set(["--check", "--dry-run", "--no-enable", "--help"]);
const args = new Set(process.argv.slice(2));
for (const arg of args) {
	if (!knownFlags.has(arg)) {
		console.error(`Unknown option: ${arg}`);
		process.exit(2);
	}
}

if (args.has("--help")) {
	console.log(`dsh-almost-full-access installer

Usage:
  npx --yes github:Alnita-M/dsh-Almost_Full_Access [options]

Options:
  --check      Verify the installed package and Cordis patch without changing them
  --dry-run    Print the resolved paths and planned changes
  --no-enable  Install files without editing cordis.patch.yml
  --help       Show this help

Set DSH_HOME to override the default ~/.dsh location.`);
	process.exit(0);
}

const PKG_NAME = "dsh-almost-full-access";
const PLUGIN_LINE = /^\s+name:\s*dsh-almost-full-access\s*$/gm;
const PERMISSION_ID_LINE = /^\s*-\s+id:\s*permission\s*$/gm;

const sourceRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const sourcePackage = JSON.parse(await readFile(join(sourceRoot, "package.json"), "utf8"));
const dshHome = process.env.DSH_HOME ?? join(homedir(), ".dsh");
const target = join(dshHome, "profiles", "node_modules", PKG_NAME);
const patchPath = join(dshHome, "profiles", "web", "cordis.patch.yml");

const PERMISSION_BLOCK = `# dsh-Almost Full Access: 权限模式预设（介于 workspace-write 与 Full access 之间）
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
        description: Full file access, but every command is first reviewed by a subagent; commands that may affect files outside the workspace, normal boot, or system drivers require explicit approval.
      danger-full-access:
        sandbox: danger-full-access
        approval: never

`;

const INSERT_BLOCK = `# dsh-Almost Full Access: 插件本体挂载
- insert:
    - id: afaccess
      name: dsh-almost-full-access

`;

function meaningfulPatchLines(text) {
	return String(text).split(/\r?\n/).map((line, index) => ({
		index,
		indent: line.match(/^[ \t]*/)?.[0].length ?? 0,
		content: line.trim()
	})).filter(({ content }) => content !== "" && !content.startsWith("#") && content !== "---" && content !== "...");
}

/** Remove a YAML document whose only value is the empty root sequence `[]`. */
function withoutEmptySequenceRoot(text) {
	const meaningful = meaningfulPatchLines(text);
	if (meaningful.length === 0) return text;
	const rootIndent = Math.min(...meaningful.map(({ indent }) => indent));
	const emptyRoot = meaningful.find(({ indent, content }) => indent === rootIndent && /^\[\](?:[ \t]+#.*)?$/.test(content));
	if (emptyRoot === void 0) return text;
	const lines = String(text).split(/\r?\n/);
	const inlineComment = lines[emptyRoot.index].match(/^([ \t]*)\[\][ \t]+(#.*)$/);
	if (inlineComment === null) lines.splice(emptyRoot.index, 1);
	else lines[emptyRoot.index] = `${inlineComment[1]}${inlineComment[2]}`;
	return lines.filter((line) => line.trim() !== "...").join("\n").trimEnd();
}

/**
 * 替换/追加 permission 预设块（config 为整体替换，必须完整覆盖 dsh-base 的预设表）。
 * 若已有 `- id: permission` 顶层条目，则从该行替换到下一个顶层条目之前。
 */
function replacePermissionBlock(text) {
	const lines = String(text).split(/\r?\n/);
	const meaningful = meaningfulPatchLines(text);
	const start = meaningful.find(({ content }) => /^-?\s*id:\s*permission\s*$/.test(content) || content === "- id: permission");
	if (start === void 0) return { text: withoutEmptySequenceRoot(text), replaced: false };
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

/** 确保插件 insert 块存在（幂等）。 */
function ensureInsertBlock(text) {
	if ([...text.matchAll(PLUGIN_LINE)].length > 0) return text;
	return text.trim() === "" ? INSERT_BLOCK.trimEnd() : `${text.trimEnd()}\n\n${INSERT_BLOCK.trimEnd()}`;
}

async function readOptional(path) {
	try {
		return await readFile(path, "utf8");
	} catch (error) {
		if (error?.code === "ENOENT") return null;
		throw error;
	}
}

async function verify(expectEnabled) {
	const installedRaw = await readOptional(join(target, "package.json"));
	if (installedRaw === null) throw new Error(`package is not installed at ${target}`);
	const installed = JSON.parse(installedRaw);
	if (installed.name !== sourcePackage.name || installed.version !== sourcePackage.version) {
		throw new Error(`installed package is ${installed.name ?? "unknown"}@${installed.version ?? "unknown"}; expected ${sourcePackage.name}@${sourcePackage.version}`);
	}
	if (expectEnabled) {
		const patch = await readOptional(patchPath);
		const count = patch === null ? 0 : [...patch.matchAll(PLUGIN_LINE)].length;
		if (count !== 1) throw new Error(`expected exactly one ${PKG_NAME} entry in ${patchPath}; found ${count}`);
		const permCount = patch === null ? 0 : [...patch.matchAll(PERMISSION_ID_LINE)].length;
		if (permCount !== 1) throw new Error(`expected exactly one permission preset block in ${patchPath}; found ${permCount}`);
	}
	console.log(`Verified ${sourcePackage.name}@${sourcePackage.version}`);
	console.log(`  package: ${target}`);
	if (expectEnabled) console.log(`  patch:   ${patchPath}`);
}

const enable = !args.has("--no-enable");
if (args.has("--dry-run")) {
	console.log(`Would install ${sourcePackage.name}@${sourcePackage.version}`);
	console.log(`  package: ${target}`);
	console.log(`  patch:   ${enable ? patchPath : "unchanged (--no-enable)"}`);
	console.log(`  preset:  almost-full-access (sandbox=danger-full-access, approval=never)`);
	process.exit(0);
}

if (args.has("--check")) {
	await verify(enable);
	process.exit(0);
}

await mkdir(target, { recursive: true });
for (const entry of ["lib", "cordis.patch.yml", "package.json", "README.md", "LICENSE", "SECURITY.md", "assets"]) {
	await cp(join(sourceRoot, entry), join(target, entry), { recursive: true, force: true });
}
await mkdir(join(target, "scripts"), { recursive: true });
await cp(fileURLToPath(import.meta.url), join(target, "scripts", "install.mjs"), { force: true });

if (enable) {
	await mkdir(dirname(patchPath), { recursive: true });
	let current = await readOptional(patchPath) ?? "";
	let next = replacePermissionBlock(current).text;
	next = ensureInsertBlock(next);
	if (next !== current) await writeFile(patchPath, next, "utf8");
}

await verify(enable);
console.log("Installation complete. Restart dsh web, then hard-refresh the browser.");
console.log("启用方式：在会话权限选择器中切换到「🛡️ Almost Full Access」。");
