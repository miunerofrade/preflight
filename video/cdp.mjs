// Minimal Chrome DevTools Protocol driver for recording the demo (no dependencies).
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const CHROME = "C:/Program Files/Google/Chrome/Application/chrome.exe";
export const sleep = ms => new Promise(r => setTimeout(r, ms));

export async function launch({ port = 9333, profile, width = 1280, height = 720, headless = true }) {
  mkdirSync(profile, { recursive: true });
  const args = [`--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, "--no-first-run",
    "--no-default-browser-check", "--disable-extensions", "--hide-scrollbars", "--mute-audio",
    "--force-device-scale-factor=1.5", `--window-size=${width},${height + (headless ? 0 : 88)}`,
    "--disable-features=Translate,MediaRouter", "--lang=en-US"];
  if (headless) args.push("--headless=new");
  const proc = spawn(CHROME, [...args, "about:blank"], { stdio: "ignore" });
  let targets;
  for (let i = 0; i < 100; i++) {
    try { targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json(); if (targets.some(t => t.type === "page")) break; }
    catch { /* not up yet */ }
    await sleep(100);
  }
  const page = targets.find(t => t.type === "page");
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  const session = new Session(ws);
  await session.send("Page.enable");
  await session.send("Runtime.enable");
  await session.send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1.5, mobile: false });
  session.close = () => { try { ws.close(); } catch {} proc.kill(); };
  return session;
}

class Session {
  constructor(ws) {
    this.ws = ws; this.id = 0; this.pending = new Map(); this.handlers = new Map();
    ws.onmessage = ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { res, rej } = this.pending.get(msg.id); this.pending.delete(msg.id);
        msg.error ? rej(new Error(msg.error.message)) : res(msg.result);
      } else if (msg.method) (this.handlers.get(msg.method) || []).forEach(h => h(msg.params));
    };
  }
  send(method, params = {}) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((res, rej) => this.pending.set(id, { res, rej }));
  }
  on(method, fn) { this.handlers.set(method, [...(this.handlers.get(method) || []), fn]); }
  async eval(expr) {
    const r = await this.send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
    return r.result.value;
  }
  async goto(url) {
    const loaded = new Promise(r => this.on("Page.loadEventFired", r));
    await this.send("Page.navigate", { url });
    await loaded;
  }
  async waitFor(expr, timeout = 120000) {
    const end = Date.now() + timeout;
    while (Date.now() < end) { if (await this.eval(`!!(${expr})`)) return; await sleep(150); }
    throw new Error(`timeout waiting for ${expr}`);
  }
  // Screencast frames arrive only on change; keep timestamps so ffmpeg can hold each one.
  async startRecording(dir) {
    mkdirSync(dir, { recursive: true });
    this.frames = []; this.frameDir = dir; this.wallStart = Date.now();
    if (!this.castBound) {
      this.on("Page.screencastFrame", async p => {
        this.send("Page.screencastFrameAck", { sessionId: p.sessionId }).catch(() => {});
        if (!this.frameDir) return;
        const t = p.metadata.timestamp - this.wallStart / 1000;
        const file = join(this.frameDir, `f${String(this.frames.length).padStart(5, "0")}.jpg`);
        writeFileSync(file, Buffer.from(p.data, "base64"));
        this.frames.push({ file, t: Math.max(0, t) });
      });
      this.castBound = true;
    }
    await this.send("Page.startScreencast", { format: "jpeg", quality: 92, maxWidth: 1920, maxHeight: 1080, everyNthFrame: 1 });
  }
  async stopRecording(name) {
    await sleep(300);
    await this.send("Page.stopScreencast");
    const end = (Date.now() - this.wallStart) / 1000;
    const frames = this.frames; const dir = this.frameDir; this.frameDir = null;
    // concat demuxer: each frame lasts until the next; the last one until the stop time
    const lines = ["ffconcat version 1.0"];
    frames.forEach((f, i) => {
      const next = i + 1 < frames.length ? frames[i + 1].t : Math.max(f.t + 0.5, end);
      lines.push(`file '${f.file.replace(/\\/g, "/").split("/").pop()}'`, `duration ${(next - f.t).toFixed(3)}`);
    });
    lines.push(`file '${frames.at(-1).file.replace(/\\/g, "/").split("/").pop()}'`);
    writeFileSync(join(dir, "list.ffconcat"), lines.join("\n"));
    return { name, dir, frames: frames.length, seconds: end };
  }
}
