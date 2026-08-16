#!/usr/bin/env node
/**
 * dsh-Almost Full Access — 测试套件
 * ============================================================
 * 运行：node scripts/test.mjs
 * 覆盖：
 *   1. 确定性分析规则（安全/危险/模糊三类命令的正反用例）
 *   2. 命令哈希稳定性
 *   3. 包结构（package.json 的 dsh/exports/files 声明）
 *   4. patch 内容（preset 档位 + 插件挂载）
 *   5. 语法检查（lib/*.js、scripts/*.mjs）
 *   6. 安装器幂等（--check）
 */
import { execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeCommand, hashCommand } from "../lib/analyze.js";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const WS = "C:\\Users\\18107\\Desktop\\DeepSeek Harness";

let passed = 0;
let failed = 0;
const failures = [];

function check(name, cond, detail = "") {
	if (cond) {
		passed += 1;
		console.log(`  ✓ ${name}`);
	} else {
		failed += 1;
		failures.push(`${name}${detail ? " — " + detail : ""}`);
		console.log(`  ✗ ${name}${detail ? " — " + detail : ""}`);
	}
}

function analyze(cmd) {
	const r = analyzeCommand(cmd, WS);
	return { impacts: r.impacts, ambiguous: r.ambiguous, ruleIds: r.ruleIds };
}

// ============ 1. 确定性分析规则 ============
console.log("\n[1] 确定性分析规则");

console.log("  -- 安全命令（应为 safe：无 impacts、非 ambiguous）");
const SAFE = [
	"Get-Date",
	"Get-Process -Name explorer",
	"Get-Content 'C:\\Windows\\System32\\drivers\\etc\\hosts'",
	"Get-ChildItem C:\\Windows",
	"New-Item -Path '.\\foo.txt' -ItemType File -Force",
	"Set-Content -Path 'C:\\Users\\18107\\Desktop\\DeepSeek Harness\\a.txt' -Value x",
	"Write-Output 'hello'",
	"Format-Table Name, Id",
	"git status",
	"npm install",
	"Select-Object -First 1",
	"Get-Date -Format 'yyyy-MM-dd'"
];
for (const cmd of SAFE) {
	const r = analyze(cmd);
	check(`safe: ${cmd.slice(0, 50)}`, r.impacts.length === 0 && !r.ambiguous, JSON.stringify(r));
}

console.log("  -- 危险命令（应命中对应规则 id）");
const DANGER = [
	["bcdedit /enum {current}", "boot:bcdedit"],
	["bootrec /fixmbr", "boot:bootrec"],
	["diskpart", "boot:diskpart"],
	["shutdown /r /t 0", "boot:shutdown"],
	["Stop-Service -Name Spooler -Force", "sys:service"],
	["net stop spooler", "sys:sc"],
	["sc config spooler start= disabled", "sys:sc"],
	["reg add HKLM\\Software\\Test /v x /t REG_SZ /d 1 /f", "sys:hklm"],
	["winget install notepadplusplus", "sys:software"],
	["pnputil /add-driver x.inf", "sys:pnputil"],
	["pip install requests", "sys:packages"],
	["Remove-Item C:\\Windows\\Temp\\a.txt", "write-outside"],
	["Set-Content -Path $env:TEMP\\a.txt -Value x", "write-outside"],
	["New-Item -Path 'C:\\Windows\\Temp\\a.txt'", "write-outside"],
	["Set-ItemProperty HKCU:\\Software\\Test -Name x -Value 1", "write-outside"]
];
for (const [cmd, expectId] of DANGER) {
	const r = analyze(cmd);
	const hit = r.impacts.length > 0 && r.ruleIds.includes(expectId);
	check(`danger: ${cmd.slice(0, 50)} -> ${expectId}`, hit, JSON.stringify(r));
}

console.log("  -- 模糊命令（应 ambiguous=true）");
const AMBIGUOUS = [
	"iex 'Write-Output 1'",
	"Invoke-WebRequest -Uri http://example.com",
	"Start-Process notepad",
	"& '.\\script.ps1'",
	"Invoke-Expression (Get-Content a.txt)"
];
for (const cmd of AMBIGUOUS) {
	const r = analyze(cmd);
	check(`ambiguous: ${cmd.slice(0, 50)}`, r.ambiguous === true, JSON.stringify(r));
}

console.log("  -- 只读系统路径不得误判（回归）");
const READS = [
	"Get-Content C:\\Windows\\Temp\\x.txt",
	"Get-ChildItem C:\\Windows\\System32",
	"reg query HKLM\\Software"
];
for (const cmd of READS) {
	const r = analyze(cmd);
	check(`read-only: ${cmd.slice(0, 50)}`, r.impacts.length === 0 && !r.ambiguous, JSON.stringify(r));
}

// ============ 2. 命令哈希 ============
console.log("\n[2] 命令哈希");
const h1 = hashCommand("Stop-Service Spooler");
const h2 = hashCommand("Stop-Service Spooler");
const h3 = hashCommand("Start-Service Spooler");
check("相同命令哈希一致", h1 === h2, `${h1} vs ${h2}`);
check("不同命令哈希不同", h1 !== h3, `${h1} vs ${h3}`);
check("哈希格式", /^h[0-9a-f]+$/.test(h1), h1);

// ============ 3. 包结构 ============
console.log("\n[3] 包结构（package.json）");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
check("name 正确", pkg.name === "dsh-almost-full-access", pkg.name);
check("main 指向 lib/index.js", pkg.main === "lib/index.js", pkg.main);
check("exports[.]", pkg.exports?.["."] === "./lib/index.js");
check("exports[./client]", pkg.exports?.["./client"] === "./lib/client.js");
check("dsh.bundle.patch", pkg.dsh?.bundle?.patch === "./cordis.patch.yml");
check("dsh.client.platform=web", pkg.dsh?.client?.platform === "web");
check("files 含 lib", Array.isArray(pkg.files) && pkg.files.includes("lib/"));
check("files 含 cordis.patch.yml", pkg.files.includes("cordis.patch.yml"));
check("files 含 install 脚本", pkg.files.includes("scripts/install.mjs"));
check("bin 已声明", pkg.bin?.["dsh-afaccess-install"] === "scripts/install.mjs");
check("非 private", pkg.private !== true);
check("repository 指向 Alnita-M/dsh-Almost_Full_Access", String(pkg.repository?.url ?? "").includes("Alnita-M/dsh-Almost_Full_Access"), pkg.repository?.url);
check("无占位符残留", !JSON.stringify(pkg).includes("your-github-username"));

// ============ 4. patch 内容 ============
console.log("\n[4] cordis.patch.yml");
const patch = readFileSync(join(root, "cordis.patch.yml"), "utf8");
check("含 almost-full-access 档位", patch.includes("almost-full-access"));
check("档位名带 🛡️", patch.includes("🛡️ Almost Full Access"));
check("sandbox=danger-full-access", patch.includes("sandbox: danger-full-access"));
check("含 permission 预设覆盖", patch.includes("- id: permission"));
check("含插件挂载", patch.includes("name: dsh-almost-full-access"));
check("含 read-only / workspace-write / danger-full-access 完整预设", ["read-only", "workspace-write", "danger-full-access"].every((k) => patch.includes(k)));

// ============ 5. 语法检查 ============
console.log("\n[5] 语法检查");
for (const f of ["lib/index.js", "lib/client.js", "scripts/install.mjs", "scripts/test.mjs"]) {
	try {
		execFileSync(process.execPath, ["--check", join(root, f)], { stdio: "pipe" });
		check(`node --check ${f}`, true);
	} catch (err) {
		check(`node --check ${f}`, false, String(err?.stderr ?? err));
	}
}

// ============ 6. 安装器幂等 ============
console.log("\n[6] 安装器 --check（本机 DSH_HOME）");
try {
	const out = execFileSync(process.execPath, [join(root, "scripts/install.mjs"), "--check"], { stdio: "pipe" }).toString();
	check("install.mjs --check 通过", out.includes("Verified dsh-almost-full-access"), out.trim().split("\n").pop());
} catch (err) {
	check("install.mjs --check 通过", false, String(err?.stderr ?? err));
}

// ============ 汇总 ============
console.log(`\n========================================`);
console.log(`结果：${passed} 通过 / ${failed} 失败`);
if (failures.length > 0) {
	console.log("\n失败明细：");
	for (const f of failures) console.log(`  - ${f}`);
	process.exit(1);
}
console.log("全部通过 ✅");
