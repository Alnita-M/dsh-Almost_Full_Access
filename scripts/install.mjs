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
 *
 * 跨电脑安装健壮性（v1.0.3）：
 * - patch 编辑逻辑抽到 scripts/patch-lib.mjs（纯函数）：顶层 permission 块缺失时
 *   自动追加（全新电脑空 patch 不再丢失预设）、剥离 UTF-8 BOM、解析式计数；
 * - 未检测到 DSH Web 配置目录时给出明确警告（不静默"成功"）；
 * - patch-lib.mjs 随包复制到目标安装目录，npm 全局安装的安装器可正常 import。
 */
import { cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
	PKG_NAME,
	replacePermissionBlock,
	ensurePermissionBlock,
	ensureInsertBlock,
	patchCounts
} from "./patch-lib.mjs";

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

const sourceRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const sourcePackage = JSON.parse(await readFile(join(sourceRoot, "package.json"), "utf8"));
const dshHome = process.env.DSH_HOME ?? join(homedir(), ".dsh");
const target = join(dshHome, "profiles", "node_modules", PKG_NAME);
const patchPath = join(dshHome, "profiles", "web", "cordis.patch.yml");

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
		const counts = patch === null ? { plugin: 0, permission: 0 } : patchCounts(patch);
		if (counts.plugin !== 1) throw new Error(`expected exactly one ${PKG_NAME} entry in ${patchPath}; found ${counts.plugin}`);
		if (counts.permission !== 1) throw new Error(`expected exactly one permission preset block in ${patchPath}; found ${counts.permission}`);
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

// v1.0.3：未安装 DSH Web 时给出明确警告，避免"安装成功但无效"
if (!existsSync(join(dshHome, "profiles", "web"))) {
	console.warn("⚠️  未检测到 DSH Web 配置目录：" + join(dshHome, "profiles", "web"));
	console.warn("   请确认这台电脑已安装 DeepSeek Harness（Web 版）且 DSH_HOME 指向正确；");
	console.warn("   否则本插件虽然会复制到 " + dshHome + "，但 dsh 不会加载它。");
}

await mkdir(target, { recursive: true });
for (const entry of ["lib", "cordis.patch.yml", "package.json", "README.md", "LICENSE", "SECURITY.md", "assets"]) {
	await cp(join(sourceRoot, entry), join(target, entry), { recursive: true, force: true });
}
await mkdir(join(target, "scripts"), { recursive: true });
await cp(fileURLToPath(import.meta.url), join(target, "scripts", "install.mjs"), { force: true });
// v1.0.3：patch-lib 必须随包复制，否则全局安装后 install.mjs 的 import 会失败
await cp(join(sourceRoot, "scripts", "patch-lib.mjs"), join(target, "scripts", "patch-lib.mjs"), { force: true });

if (enable) {
	await mkdir(dirname(patchPath), { recursive: true });
	let current = await readOptional(patchPath) ?? "";
	let next = replacePermissionBlock(current).text;
	next = ensurePermissionBlock(next); // 无顶层 permission 块的干净 patch：追加预设（否则模式缺失）
	next = ensureInsertBlock(next);
	if (next !== current) await writeFile(patchPath, next, "utf8");
}

await verify(enable);
console.log("Installation complete. Restart dsh web, then hard-refresh the browser.");
console.log("启用方式：在会话权限选择器中切换到「🛡️ Almost Full Access」。");