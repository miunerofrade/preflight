/* Security-relevant UI behavior without a browser or a network connection. */
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function ui(language = "zh") {
  const elements = new Map();
  const copied = [];
  function element() {
    const classes = new Set();
    return {
      value: "", textContent: "", innerHTML: "", hidden: false, disabled: false, checked: false, open: false,
      showModal() { this.open = true; }, close() { this.open = false; },
      style: {}, dataset: {},
      classList: { add: (...xs) => xs.forEach(x => classes.add(x)), remove: (...xs) => xs.forEach(x => classes.delete(x)),
        contains: x => classes.has(x), toggle: (x, on) => on ? classes.add(x) : classes.delete(x) },
      setAttribute() {}, addEventListener() {}, appendChild() {}, closest() { return this; },
      querySelectorAll() { return []; },
    };
  }
  const get = id => { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); };
  const context = vm.createContext({
    URL,
    document: { getElementById: get, createElement: element, querySelector: get,
      querySelectorAll: () => [], addEventListener() {}, documentElement: { lang: "", classList: element().classList } },
    localStorage: { getItem: () => language, setItem() {} },
    navigator: { clipboard: { async writeText(text) { copied.push(text); } } },
    setTimeout() {},
  });
  for (const file of ["i18n.js", "reports.js", "app.js"]) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, "../app/static", file), "utf8"), context);
  }
  return { run: code => vm.runInContext(code, context), get, context, copied };
}

test("source highlights use code points after emoji and escape HTML", () => {
  const app = ui();
  assert.equal(app.run('paintSpans("📋 <bad>", [{start: 2, end: 7, cls: "inj"}])'),
    '📋 <mark class="mark-inj">&lt;bad&gt;</mark>');
});

test("overlapping evidence keeps both annotation types and localizes SDK labels", () => {
  const app = ui();
  const html = app.run('paintSpans("📋 <mail>", [{start:2,end:8,cls:"inj"},{start:3,end:7,cls:"pii"}])');
  assert.match(html, /<mark class="mark-inj"><mark class="mark-pii">mail<\/mark><\/mark>/);
  assert.doesNotMatch(html, /<mail>/);
  app.run('renderInjection({verdict:"injection",severity:"critical",injection:.995,categories:{"instruction override":.52,"tool misuse or data exfiltration":.44}})');
  assert.match(app.get("body-injection").innerHTML, /提示注入: 严重/);
  assert.match(app.get("body-injection").innerHTML, /指令覆盖/);
  assert.doesNotMatch(app.get("body-injection").innerHTML, /instruction override|critical/);
  app.run('renderScript(null, {contains_code:false}, false)');
  assert.equal(app.get("card-script").hidden, true);
  assert.equal(app.run('localizedFlag({title:"Download destination is set by script",detail:"https://example.com/file"}).title'), "下载目标由脚本指定");
});

test("copy is unavailable until an edited review copy is explicitly acknowledged", async () => {
  const app = ui();
  app.context.payload = { handoff: { status: "review", text: "Checked copy", changes: { removed: 1, masked: 0 },
    reason: "edited_checked", verification: null } };
  app.run("lastReport = payload; renderHandoff(payload)");
  assert.equal(app.get("copy").disabled, true);
  await app.run("copySanitized()");
  assert.equal(app.copied.length, 0);
  app.get("confirm-copy").checked = true;
  await app.run("copySanitized()");
  assert.deepEqual(app.copied, ["Checked copy"]);
});

test("a withheld result clears the previous text and cannot be copied", async () => {
  const app = ui();
  app.context.payload = { handoff: { status: "ready", text: "Old copy", changes: { removed: 0, masked: 0 },
    reason: "original_checked" } };
  app.run("lastReport = payload; renderHandoff(payload)");
  assert.equal(app.get("sanitized").textContent, "Old copy");
  app.context.payload = { handoff: { status: "withheld", text: null, changes: { removed: 0, masked: 0 },
    reason: "recheck_failed" } };
  app.run("lastReport = payload; renderHandoff(payload)");
  assert.equal(app.get("sanitized").textContent, "");
  assert.equal(app.get("sanitized").hidden, true);
  assert.equal(app.get("copy").disabled, true);
  app.get("confirm-copy").checked = true;
  await app.run("copySanitized()");
  assert.equal(app.copied.length, 0);
});

test("an unverified edited draft is visible without enabling handoff copying", async () => {
  const app = ui();
  app.context.payload = { handoff: { status: "withheld", text: null,
    draft_text: "Keep this. [Instruction removed]", changes: { removed: 1, masked: 0 },
    reason: "residual_risk", verification: null } };
  app.run("lastReport = payload; renderHandoff(payload)");
  assert.equal(app.get("sanitized").hidden, false);
  assert.equal(app.get("sanitized").textContent, "Keep this. [Instruction removed]");
  assert.match(app.get("handoff-status").textContent, /处理稿待复核/);
  assert.equal(app.get("copy").disabled, true);
  app.get("confirm-copy").checked = true;
  await app.run("copySanitized()");
  assert.equal(app.copied.length, 0);
});

test("clean results omit status labels while unresolved recheck findings remain visible", () => {
  const app = ui();
  app.run('renderInjection({ verdict: "benign", severity: "none", injection: 0.01, categories: {benign: 0.99} })');
  assert.doesNotMatch(app.get("body-injection").innerHTML, /chip|benign/);
  app.run('renderPii({ entities: [], counts: {} })');
  assert.doesNotMatch(app.get("body-pii").innerHTML, /chip|未发现/);
  app.context.payload = { handoff: { status: "review", text: "Checked text", reason: "edited_checked",
    verification: { layers: { injection: { verdict: "benign" }, pii: { entities: [] }, script: null },
      action: { choice: "review" } } } };
  app.run("renderHandoff(payload)");
  assert.equal(app.get("handoff-checks").hidden, true);
  app.context.payload.handoff.verification.layers.injection.verdict = "injection";
  app.run("renderHandoff(payload)");
  assert.equal(app.get("handoff-checks").hidden, false);
  assert.match(app.get("handoff-checks").innerHTML, /提示注入/);
  assert.doesNotMatch(app.get("handoff-checks").innerHTML, /个人信息|无需脚本检查|chip/);
});

test("language catalogs cover the same keys, including every disposition rule", () => {
  const app = ui();
  assert.equal(app.run("JSON.stringify(Object.keys(I18N.zh).sort())"),
    app.run("JSON.stringify(Object.keys(I18N.en).sort())"));
});

test("Markdown exports identify human review and never substitute a PII-only copy", () => {
  const app = ui("en");
  app.context.report = {
    action: { choice: "block", model_choice: "allow", confidence: 0.99 },
    source: { kind: "text" }, usage: { calls: 8, input_tokens: 20, output_tokens: 2 }, total_ms: 50,
    layers: { injection: {}, script: null, pii: { anonymized_text: "UNVERIFIED PII-ONLY COPY" } },
    policy: { version: "test", reasons: [{ code: "injection_high", action: "block" }] },
    handoff: { status: "review", reason: "edited_checked", text: "Edited checked copy",
      changes: { removed: 1, masked: 0 } },
  };
  const markdown = app.run('markdownOf(report, "original")');
  assert.match(markdown, /Human review/);
  assert.match(markdown, /Model recommendation: Allow/);
  assert.match(markdown, /Edited checked copy/);
  assert.doesNotMatch(markdown, /UNVERIFIED/);
});

test("English is the initial language and Markdown follows the selected language", () => {
  const app = ui(null);
  assert.equal(app.run("LANG"), "en");
  app.context.report = { action: { choice: "review" }, source: { kind: "text" }, layers: {},
    handoff: { status: "review", reason: "edited_checked", text: "Original source stays unchanged" } };
  assert.match(app.run('markdownOf(report, null)'), /Preflight report/);
  app.run('LANG = "zh"');
  const markdown = app.run('markdownOf(report, null)');
  assert.match(markdown, /安检报告/);
  assert.match(markdown, /需确认/);
  assert.match(markdown, /Original source stays unchanged/);
  assert.doesNotMatch(markdown, /Human review/);
});

test("Fill report is cached per scan and language, escaped and never changes disposition", async () => {
  const app = ui("en");
  let calls = 0;
  app.context.payload = { action: { choice: "block" }, layers: {}, handoff: { status: "withheld" } };
  app.context.fetch = async (_url, request) => {
    calls++;
    assert.equal(JSON.parse(request.body).language, "en");
    return { ok: true, json: async () => ({ language: "en", generated: {
      title: '<img src=x onerror="bad()">', summary: "Review this", review_steps: "Verify the source" }, calls: 1, total_ms: 20 }) };
  };
  app.run("lastReport = payload");
  await app.run("generateReviewReport()");
  assert.match(app.get("detail-body").innerHTML, /&lt;img/);
  assert.doesNotMatch(app.get("detail-body").innerHTML, /<img/);
  assert.equal(app.context.payload.action.choice, "block");
  assert.equal(app.context.payload.handoff.status, "withheld");
  await app.run("generateReviewReport()");
  assert.equal(calls, 1);
  app.run('LANG = "zh"');
  assert.equal(app.run("currentReview()"), null);
});

test("new evidence and edit markup escapes content and refuses non-web source links", () => {
  const app = ui();
  assert.equal(app.run('sourceLink("javascript:alert(1)", "Source")'), "Source");
  assert.match(app.run('sourceLink("https://www.wikidata.org/wiki/Q1", "Record")'), /rel="noopener noreferrer"/);
  app.context.payload = { handoff: { status: "review", text: "[Instruction removed]", reason: "edited_checked",
    changes: { removed: 1, masked: 0 }, edits: [{ kind: "remove", start: 0, end: 8,
      before: "<script>", after: "[Instruction removed]" }] } };
  app.run("renderHandoff(payload)");
  assert.equal(app.get("handoff-diff").hidden, false);
  assert.match(app.get("handoff-edits").innerHTML, /&lt;script&gt;/);
  assert.doesNotMatch(app.get("handoff-edits").innerHTML, /<script>/);
  app.context.payload = { source: { kind: "url" }, handoff: { status: "unavailable", text: null,
    reason: "url_source", changes: { removed: 0, masked: 0 }, edits: [] } };
  app.run("renderHandoff(payload)");
  assert.equal(app.get("sanitized-panel").hidden, true);
  assert.equal(app.get("handoff-diff").hidden, true);
  assert.equal(app.get("copy").disabled, true);
  app.context.evidence = { claim_source: "QQ音乐下载页", claims: [
    { value: "QQ音乐", quote: "QQ音乐", start: 0, end: 4, status: "quoted" },
    { value: "QQ音乐", quote: "QQ音乐", start: 0, end: 4, status: "quoted" }], sources: [] };
  const preview = app.run("renderUrlEvidence(evidence)");
  assert.match(preview, /查看详情/);
  assert.doesNotMatch(preview, /<details|blockquote/);
  app.run('lastReport = { source: { kind: "url" }, url: evidence }; openDetail("evidence")');
  assert.equal(app.get("detail-dialog").open, true);
  assert.equal((app.get("detail-body").innerHTML.match(/class="detail-quote"/g) || []).length, 1);
  assert.equal(app.run('document.documentElement.classList.contains("modal-open")'), true);
  app.run("closeDetail()");
  assert.equal(app.get("detail-dialog").open, false);
  assert.equal(app.get("detail-body").innerHTML, "");
  assert.equal(app.run('document.documentElement.classList.contains("modal-open")'), false);
});
