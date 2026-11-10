// Records the web-interface shots against the local app. Real scans: spends credits.
// usage: node video/shots.mjs <shot> [<shot> ...]   shots: setup, zh, url
import { readFileSync, writeFileSync } from "node:fs";
import { launch, sleep } from "./cdp.mjs";

const OUT = "D:/clocked hackson/video/out";
const BASE = "http://127.0.0.1:8765/";
const setupGuide = readFileSync("D:/clocked hackson/video/input/setup-guide.md", "utf8").trimEnd();

const s = await launch({ profile: `${OUT}/profile` });
const js = expr => s.eval(expr);
const scrollTo = async (sel, block = "start", wait = 1200) => {
  await js(`document.querySelector(${JSON.stringify(sel)}).scrollIntoView({behavior: "smooth", block: ${JSON.stringify(block)}})`);
  await sleep(wait);
};
const scrollBy = async (y, wait = 1000) => { await js(`window.scrollBy({top: ${y}, behavior: "smooth"})`); await sleep(wait); };
// a soft ring around what the viewer should look at (not part of the product UI)
const ring = async (sel, ms = 1600) => {
  await js(`(() => { const el = document.querySelector(${JSON.stringify(sel)}); if (!el) return;
    el.style.transition = "box-shadow .25s"; el.style.boxShadow = "0 0 0 4px rgba(79,70,229,.55)";
    setTimeout(() => { el.style.boxShadow = ""; }, ${ms}); })()`);
  await sleep(ms + 250);
};
const typeInto = async (text, ms = 1800) => {
  const steps = 36;
  for (let i = 1; i <= steps; i++) {
    const part = Array.from(text).slice(0, Math.round(Array.from(text).length * i / steps)).join("");
    await js(`(() => { const el = document.getElementById("input"); el.value = ${JSON.stringify(part)};
      el.dispatchEvent(new Event("input", {bubbles: true})); el.scrollTop = el.scrollHeight; })()`);
    await sleep(ms / steps);
  }
};
const fresh = async lang => {
  await s.goto(BASE);
  await js(`localStorage.setItem("preflight-lang", ${JSON.stringify(lang)})`);
  await s.goto(BASE);
  await js(`(() => { if ((document.documentElement.lang || "en").slice(0,2) !== ${JSON.stringify(lang)}) document.getElementById("lang-toggle").click(); })()`);
  await js(`window.scrollTo(0, 0)`);
  await sleep(500);
};
const waitResult = () => s.waitFor(`!document.getElementById("results").hidden && !document.getElementById("run").disabled && document.getElementById("progress").hidden`, 150000);
const usage = () => js(`document.getElementById("stats").innerText.replace(/\\n/g, " | ")`);

const shots = {
  async setup() {
    await fresh("en");
    await s.startRecording(`${OUT}/shot-setup`);
    await sleep(900);
    await js(`document.getElementById("input").focus()`);
    await typeInto(setupGuide);
    await sleep(700);
    await ring("#run", 700);
    await js(`document.getElementById("run").click()`);
    await sleep(600);
    await scrollTo("#progress", "center", 400);
    await waitResult();
    await sleep(300);
    await scrollTo(".verdict", "start", 1400);
    await ring("#conclusion", 2200);
    await scrollTo("#source", "center", 1300);
    await ring("#source", 2400);
    await scrollTo("#sanitized-panel", "start", 1400);
    await ring("#sanitized", 2600);
    await js(`document.getElementById("handoff-diff-label").click()`);
    await sleep(3800);
    await js(`document.getElementById("detail-close").click()`);
    await sleep(700);
    await ring("#handoff-confirm", 1600);
    return usage();
  },
  async zh() {
    await fresh("zh");
    await s.startRecording(`${OUT}/shot-zh`);
    await sleep(800);
    await ring("#example-grid .example:nth-child(2)", 900);
    await js(`document.querySelector("#example-grid .example:nth-child(2)").click()`);
    await sleep(500);
    await scrollTo("#progress", "center", 300);
    await waitResult();
    await sleep(300);
    await scrollTo(".verdict", "start", 1300);
    await ring("#conclusion", 1800);
    await scrollTo("#source", "center", 1200);
    await ring("#source", 2000);
    await scrollTo("#sanitized-panel", "start", 1300);
    await ring("#sanitized", 2600);
    return usage();
  },
  async url() {
    await fresh("en");
    await js(`document.getElementById("examples-toggle").click()`);
    await sleep(300);
    const idx = await js(`[...document.querySelectorAll("#example-grid .example")].findIndex(b => /QQ Music/.test(b.textContent)) + 1`);
    await s.startRecording(`${OUT}/shot-url`);
    await scrollTo(`#example-grid .example:nth-child(${idx})`, "center", 900);
    await ring(`#example-grid .example:nth-child(${idx})`, 900);
    await js(`document.querySelector("#example-grid .example:nth-child(${idx})").click()`);
    await sleep(400);
    await scrollTo("#progress", "center", 300);
    await waitResult();
    await sleep(300);
    await scrollTo(".verdict", "start", 1600);
    await scrollTo("#url-cards", "start", 1600);
    await js(`document.querySelector('#url-cards [data-detail="evidence"]').click()`);
    await sleep(1600);
    await js(`(() => { const b = document.getElementById("detail-body"); const r = b.querySelector(".receipt-list"); if (r) r.closest("section").scrollIntoView({behavior: "smooth", block: "center"}); })()`);
    await sleep(1200);
    await ring("#detail-body .receipt-list", 3000);
    await js(`document.getElementById("detail-close").click()`);
    await sleep(500);
    return usage();
  },
};

const log = {};
try {
  for (const name of process.argv.slice(2)) {
    const used = await shots[name]();
    const rec = await s.stopRecording(name);
    log[name] = { ...rec, usage: used };
    console.log(JSON.stringify(log[name]));
  }
} finally {
  writeFileSync(`${OUT}/shots-log-${Date.now()}.json`, JSON.stringify(log, null, 2));
  s.close();
}
