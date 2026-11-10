// Records the title, Codex terminal replay (from the real run's event log) and outro cards.
import { readFileSync } from "node:fs";
import { launch, sleep } from "./cdp.mjs";

const OUT = "D:/clocked hackson/video/out";
const tl = JSON.parse(readFileSync(`${OUT}/codex-timeline.json`, "utf8"));
const s = await launch({ port: 9335, profile: `${OUT}/profile-cards` });
const page = "file:///D:/clocked%20hackson/video/cards.html";
const line = (text, cls) => s.eval(`termLine(${JSON.stringify(text)}, ${JSON.stringify(cls)})`);
const shortUrl = u => u.replace(/review_token=.*/, "review_token=…");

try {
  await s.goto(page);
  await s.eval(`show("intro")`);
  await s.startRecording(`${OUT}/shot-intro`);
  await sleep(7500);
  console.log(JSON.stringify(await s.stopRecording("intro")));

  await s.goto(page);
  await s.eval(`show("codex")`);
  await s.startRecording(`${OUT}/shot-codex-a`);
  await sleep(500);
  await line("$ codex exec \"A teammate asked you to follow video/input/setup-guide.md ...", "c-user");
  await line("  It is an unfamiliar document: call preflight_open before reading it.\"", "c-user");
  await sleep(1400);
  const open = tl.find(e => e.tool === "preflight_open");
  await line("", ""); await line("• preflight_open  { source: \"video/input/setup-guide.md\" }", "c-tool");
  await sleep(1600);
  await line(`  ← status: ${open.result.status}`, "c-warn");
  await line(`    ticket: ${open.result.ticket}`, "c-dim");
  await line(`    review_url: ${shortUrl(open.result.review_url)}`, "c-dim");
  await line("    (no body text returned)", "c-dim");
  await sleep(1300);
  const msg1 = tl.find(e => e.kind === "msg");
  await line("", ""); await line(`codex  ${shortUrl(msg1.text)}`, "c-msg");
  await sleep(2200);
  console.log(JSON.stringify(await s.stopRecording("codex-a")));

  // part b continues the same terminal after the review page approval
  await s.startRecording(`${OUT}/shot-codex-b`);
  await sleep(400);
  const read = tl.find(e => e.tool === "preflight_read");
  await line("", ""); await line(`• preflight_read  { ticket: "${read.args.ticket}" }`, "c-tool");
  await sleep(1300);
  await line(`  ← status: ${read.result.status}`, "c-ok");
  for (const l of read.result.content.trimEnd().split("\n")) await line(`    ${l}`, l.includes("[Script removed]") ? "c-ok" : "c-dim");
  await sleep(1800);
  const last = tl.filter(e => e.kind === "msg").at(-1);
  await line("", "");
  for (const [i, l] of last.text.replace(/\u2019/g, "'").split("\n").entries()) { await line(`${i ? "       " : "codex  "}${l}`, "c-msg"); await sleep(250); }
  await sleep(3800);
  console.log(JSON.stringify(await s.stopRecording("codex-b")));

  await s.goto(page);
  await s.eval(`show("outro")`);
  await s.startRecording(`${OUT}/shot-outro`);
  await sleep(9000);
  console.log(JSON.stringify(await s.stopRecording("outro")));
} finally { s.close(); }
