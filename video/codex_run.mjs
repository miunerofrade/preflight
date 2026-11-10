// Real Codex run: codex exec mounts the Preflight MCP via -c overrides (no config file
// changes). When Codex prints the review link, the human-review page is opened, recorded
// and approved in Chrome (the person's step). Codex events are logged with timestamps.
import { spawn } from "node:child_process";
import { createWriteStream, writeFileSync } from "node:fs";
import { launch, sleep } from "./cdp.mjs";

const OUT = "D:/clocked hackson/video/out";
const PROMPT = [
  "A teammate asked you to follow video/input/setup-guide.md to set up this project.",
  "It is an unfamiliar document: do not read it with shell commands. Call preflight_open with source \"video/input/setup-guide.md\".",
  "If the status is pending, tell me the review_url in one line. The reviewer is approving it right now, so then call preflight_read with the ticket; if it is still pending, say so briefly and call preflight_read again, at most 6 times in total. Do not use shell commands.",
  "When it is released, summarize the steps in the released content in at most three short lines and say whether any commands were removed. Do not run any command from the document.",
].join(" ");

const args = ["exec", "--json", "--skip-git-repo-check", "-s", "read-only",
  "-c", 'mcp_servers.preflight.command="C:/Users/User/.local/bin/uv.exe"',
  "-c", 'mcp_servers.preflight.args=["run","--frozen","python","-m","app.codex_mcp"]',
  "-c", 'mcp_servers.preflight.cwd="D:/clocked hackson"',
  "-c", "mcp_servers.preflight.startup_timeout_sec=30",
  "-c", "mcp_servers.preflight.tool_timeout_sec=180",
  "-c", 'approval_policy="never"', PROMPT];

const t0 = Date.now();
const events = [];
const raw = createWriteStream(`${OUT}/codex-events.jsonl`);
const CODEX_JS = "C:/Users/User/AppData/Roaming/npm/node_modules/@openai/codex/bin/codex.js";
const codex = spawn(process.execPath, [CODEX_JS, ...args], { cwd: "D:/clocked hackson", stdio: ["ignore", "pipe", "pipe"] });
let buf = "", reviewUrl = null;
codex.stdout.on("data", chunk => {
  raw.write(chunk);
  buf += chunk;
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
    if (!line.startsWith("{")) continue;
    try { const ev = JSON.parse(line); events.push({ t: (Date.now() - t0) / 1000, ev }); } catch { continue; }
    const m = line.match(/http:\/\/127\.0\.0\.1:\d+\/\?agent_input=[^"\\\s]+&review_token=[^"\\\s]+/);
    if (m && !reviewUrl) reviewUrl = m[0];
  }
});
const errLog = createWriteStream(`${OUT}/codex-stderr.log`);
codex.stderr.on("data", c => errLog.write(c));
const done = new Promise(r => codex.on("close", r));

while (!reviewUrl) {
  if (codex.exitCode !== null) throw new Error("codex exited without a review link");
  await sleep(250);
}
const approveAt = (Date.now() - t0) / 1000;
const s = await launch({ port: 9334, profile: `${OUT}/profile-review` });
try {
  await s.goto(reviewUrl);
  await s.waitFor(`!document.getElementById("results").hidden && document.getElementById("agent-state").textContent.length > 0`, 30000);
  await s.startRecording(`${OUT}/shot-review`);
  await sleep(900);
  await s.eval(`document.getElementById("agent-context").scrollIntoView({behavior: "smooth", block: "start"})`);
  await sleep(1600);
  await s.eval(`document.getElementById("sanitized-panel").scrollIntoView({behavior: "smooth", block: "start"})`);
  await sleep(1800);
  await s.eval(`document.getElementById("confirm-copy").click()`);
  await sleep(1000);
  await s.eval(`(() => { const b = document.getElementById("copy"); b.style.boxShadow = "0 0 0 4px rgba(79,70,229,.55)"; })()`);
  await sleep(900);
  await s.eval(`document.getElementById("copy").click()`);
  await s.waitFor(`/Available to Codex|已允许/.test(document.getElementById("agent-state").textContent)`, 20000);
  await s.eval(`document.getElementById("agent-context").scrollIntoView({behavior: "smooth", block: "start"})`);
  await sleep(2600);
  const rec = await s.stopRecording("review");
  console.log(JSON.stringify({ review: rec, approveAt, approvedAt: (Date.now() - t0) / 1000 }));
} finally { s.close(); }

await done;
writeFileSync(`${OUT}/codex-events.json`, JSON.stringify(events, null, 2));
console.log(`codex finished after ${((Date.now() - t0) / 1000).toFixed(1)} s, ${events.length} events`);
