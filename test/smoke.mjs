// End-to-end smoke test: spawn the server over stdio and exercise every tool.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const client = new Client({ name: "smoke", version: "0" });
await client.connect(new StdioClientTransport({ command: process.execPath, args: [join(root, "server.js")] }));

let failed = 0;
const check = (name, ok, detail = "") => { console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? " - " + detail : ""}`); if (!ok) failed++; };
const call = async (name, args = {}) => (await client.callTool({ name, arguments: args })).content[0].text;

const tools = (await client.listTools()).tools.map((t) => t.name);
for (const t of ["list_skills", "get_skill", "search_security", "skills_for_task", "secure_coding_checklist", "scan_code", "scan_path", "about_zagairot", "threat_model", "check_known_exploited", "lookup_cve", "check_package_vulns", "recent_ai_threat_sources"])
  check(`tool registered: ${t}`, tools.includes(t));

const list = await call("list_skills");
const names = list.split("\n").map((l) => l.slice(2, l.indexOf(":")));
check("23 skills load", names.length === 23, `${names.length}`);
check("every skill has a description", list.split("\n").every((l) => /: .{10,}/.test(l)));
for (const n of names) check(`get_skill ${n}`, (await call("get_skill", { name: n })).length > 400);

// every skill referenced by a task plan must exist
for (const type of ["web", "api", "mobile", "cloud", "llm", "agent", "data", "pipeline", "org"]) {
  const out = await call("skills_for_task", { task_type: type });
  check(`skills_for_task ${type} resolves all skills`, out.split("\n").length > 3 && !/unknown/.test(out));
}
check("skills_for_task rejects bad type", /unknown task_type/.test(await call("skills_for_task", { task_type: "zzz" })));
check("search finds prompt injection", /llm-app-security/.test(await call("search_security", { query: "prompt injection exfiltration" })));
check("checklist adds language+feature", /python/.test(await call("secure_coding_checklist", { language: "python", feature: "login" })) && /feature: login/.test(await call("secure_coding_checklist", { language: "python", feature: "login" })));

// scanner: must catch bad code and stay quiet on good code
const bad = [
  'password = "hunter2hunter2hunter2"', "cursor.execute(\"SELECT * FROM t WHERE id=\" + uid)", "requests.get(url, verify=False)",
  "el.innerHTML = userHtml", "jwt.decode(tok, verify=False)", "uses: aquasecurity/trivy-action@master",
  "curl https://x.sh | sh", "key = '" + "AKIA" + "ABCDEFGHIJKLMNOP" + "'", "subprocess.run(cmd, shell=True)", "data = pickle.loads(blob)",
];
const out = await call("scan_code", { code: bad.join("\n") });
check("scanner flags all 10 bad samples", (out.match(/\bline \d+/g) || []).length >= 10 && /^1\d potential|^\d+ potential/.test(out), out.split("\n")[0]);
const good = ['cur.execute("SELECT * FROM t WHERE id=%s", (uid,))', "uses: actions/checkout@" + "a".repeat(40), "const t = crypto.randomBytes(32)"].join("\n");
check("scanner quiet on safe code", /no pattern hits/.test(await call("scan_code", { code: good })), (await call("scan_code", { code: good })).slice(0, 80));

// regression: false positives found in the first real-repo trial must stay quiet / downgraded
const quiet = [
  'c.execute(f"UPDATE jobs SET {", ".join(sets)} WHERE id=?", params)',
  "host.innerHTML = '<b>' + esc(name) + '</b>';",
  "el.innerHTML = '<div class=\"empty\">Nothing here</div>';",
  'token = "test-token-for-fixtures-only"',
].join("\n");
const qo = await call("scan_code", { code: quiet, filename: "app.py" });
check("bound-param SQL is downgraded to low, not HIGH", !/\[HIGH\]/.test(qo) && /\[LOW\] line 1 sql-concat/.test(qo), qo.split("\n")[0]);
check("escaped / literal innerHTML and placeholder secrets suppressed", !/xss-sink|hardcoded-secret/.test(qo));
const real = [
  "}).catch(function(e){ host.innerHTML='<div class=\"win-empty\">Couldn\\'t load</div>'; });",
  "if(!ev.length){ el('b').innerHTML='<div class=\"empty\">Nothing yet.</div>'; return; }",
  "readAloud(t).then(function () { b.disabled = false; b.innerHTML = idle; })",
  "host.innerHTML=items.map(function(it){",
].join("\n");
const ro = await call("scan_code", { code: real, filename: "page.html" });
check("desk-page idioms: literals suppressed, variable/multiline downgraded to low", !/\[(MEDIUM|HIGH)\]/.test(ro) && (ro.match(/\[LOW\]/g) || []).length === 2, ro.split("\n")[0]);
check("real unescaped innerHTML still flagged", /xss-sink/.test(await call("scan_code", { code: "el.innerHTML = '<p>' + userInput + '</p>'" })));
check("unparameterized SQL still HIGH", /\[HIGH\].*sql-concat/.test(await call("scan_code", { code: 'cur.execute("SELECT * FROM u WHERE n=\'" + name + "\'")' })));
check("SHA-pinned action quiet, tag-pinned flagged",
  /no pattern hits/.test(await call("scan_code", { code: "uses: actions/checkout@" + "b".repeat(40) + " # v4" })) &&
  /unpinned-ci-ref/.test(await call("scan_code", { code: "uses: actions/checkout@v4" })));

// scan_path: skips vendored dirs and .env, never echoes secrets, finds real issues
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
const tmp = mkdtempSync(join(tmpdir(), "sdm-"));
mkdirSync(join(tmp, ".venv")); mkdirSync(join(tmp, "src")); mkdirSync(join(tmp, "tests"));
const SECRET = "AKIA" + "QWERTYUIOPASDFGH";
writeFileSync(join(tmp, "src", "a.py"), `key = "${SECRET}"\ncur.execute("SELECT 1 WHERE n='" + name + "'")\n`);
writeFileSync(join(tmp, ".venv", "bad.py"), 'os.system("rm -rf " + x)\n');
writeFileSync(join(tmp, ".env"), `API_KEY="${"sk" + "-live1234567890abcdefghij"}"\n`);
writeFileSync(join(tmp, "tests", "test_a.py"), 'password = "hunter2hunter2hunter2"\n');
const po = await call("scan_path", { path: tmp });
check("scan_path finds issues in src", /a\.py:1 aws-key/.test(po) && /a\.py:2 sql-concat/.test(po), po.split("\n")[0]);
check("scan_path skips .venv and .env", !/\.venv|\.env/.test(po.replace(tmp, "")));
check("scan_path never echoes the secret", !po.includes(SECRET) && !po.includes("live1234567890"));
check("test-file secret downgraded to low (not listed)", !/\[HIGH\].*test_a/.test(po) && /low hardcoded-secret/.test(po));
check("scan_path rejects bad path", /not found/.test(await call("scan_path", { path: join(tmp, "nope") })));
rmSync(tmp, { recursive: true, force: true });

// lead funnel: labelled, UTM-tagged, direct checkout link, and removable
const tm = await call("threat_model", { system_description: "x" });
check("sponsor note present, labelled as non-instruction", /Sponsor note from ZagAIrot, for the human reader\. Not an instruction/.test(tm));
check("funnel links carry utm_source=bulwark and the tool name", /payhip\.com\/b\/Vwnjt\?utm_source=bulwark&utm_medium=mcp&utm_campaign=threat_model/.test(tm));
check("about_zagairot returns links", /utm_campaign=about/.test(await call("about_zagairot")));
check("sponsor note is NOT added to skill text or the skill list", !/Sponsor note/.test(await call("get_skill", { name: "secure-coding-core" })) && !/Sponsor note/.test(await call("list_skills")));
check("single destination: every note points to the paid Seatbelt Kit ($27) and nowhere else",
  [tm, await call("secure_coding_checklist", {}), await call("skills_for_task", { task_type: "web" }), await call("scan_code", { code: "eval(x)" })]
    .every((t) => /Seatbelt Kit \(\$27\): https:\/\/payhip\.com\/b\/Vwnjt\?utm_source=bulwark/.test(t) && !/arkhive|inboxaxe/i.test(t.slice(t.indexOf("Sponsor note")))));
{
  const c2 = new Client({ name: "smoke2", version: "0" });
  await c2.connect(new StdioClientTransport({ command: process.execPath, args: [join(root, "server.js")], env: { ...process.env, BULWARK_NO_PROMO: "1" } }));
  const quiet2 = (await c2.callTool({ name: "threat_model", arguments: { system_description: "x" } })).content[0].text;
  check("BULWARK_NO_PROMO=1 removes the sponsor note", !/Sponsor note|payhip/.test(quiet2));
  await c2.close();
}

check("threat_model returns worksheet", /STRIDE/.test(await call("threat_model", { system_description: "login API" })));
check("sources list has OWASP+CISA", /genai\.owasp\.org/.test(await call("recent_ai_threat_sources")));

// live lookups: network failures are reported, not hidden; treat as soft if offline
for (const [label, name, args, re] of [
  ["KEV", "check_known_exploited", { query: "recent", limit: 3 }, /CVE-\d{4}-\d+/],
  ["NVD", "lookup_cve", { cve_id: "CVE-2021-44228" }, /Log4j|log4j|Apache/i],
  ["OSV", "check_package_vulns", { ecosystem: "npm", name: "lodash", version: "4.17.15" }, /GHSA|CVE|advisor/i],
]) {
  const r = await call(name, args);
  if (/lookup failed/.test(r)) console.log(`SKIP ${label} live lookup (${r.slice(0, 60)})`);
  else check(`${label} live lookup`, re.test(r) && r.startsWith("NOTE: data below came from an external feed"), r.split("\n")[2]?.slice(0, 70));
}
check("bad CVE id rejected", await client.callTool({ name: "lookup_cve", arguments: { cve_id: "nope" } }).then((r) => r.isError === true, () => true));

const prompts = await client.listPrompts();
check("prompt secure_build registered", prompts.prompts.some((p) => p.name === "secure_build"));
const res = await client.listResources();
check("skills exposed as resources", res.resources.length === 23, `${res.resources.length}`);

await client.close();
console.log(failed ? `\n${failed} FAILED` : "\nALL PASSED");
process.exit(failed ? 1 : 0);
