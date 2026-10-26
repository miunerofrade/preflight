/* Human-readable exports use the selected language; source evidence stays verbatim. */
"use strict";
const REPORT_LABELS = {
  en: {
    title: "Preflight report", generated: "Generated", source: "Source", verdict: "Verdict",
    confidence: "Model confidence", usage: "Scan usage", calls: "calls", tokens: "tokens", time: "ms",
    policy: "Disposition policy", model: "Model recommendation", injection: "Prompt injection",
    script: "Script safety", pii: "Personal data", severity: "Severity", score: "Score", counts: "Counts",
    evidence: "Source evidence", sources: "Sources and retrieval receipt", url: "Requested URL",
    final: "Analyzed URL", fetched: "Retrieved at", hash: "Response SHA-256", redirects: "Redirects",
    claims: "Page claims", flags: "Domain signals", identity: "Impersonation and intent",
    brand: "Brand identity", intent: "Content intent", passages: "Selected passages", pdf: "PDF text-layer inspection",
    pdfScope: "Text properties only; no rendering, OCR or occlusion check.", page: "Page", status: "Status",
    copy: "Prepared copy", reason: "Reason", changes: "Edits", removed: "Instruction spans removed",
    masked: "Personal-data spans masked", recheck: "Copy recheck", human: "Human review of the edited content is required before forwarding.",
    edits: "Edits against the original", before: "Before", after: "After", range: "Source code points",
    draft: "Edited draft: not approved for forwarding", review: "Generated review draft", summary: "Risk summary",
    steps: "Human-review suggestions", generatedNote: "Generated notes require human review. The scan verdict and source evidence below remain authoritative.",
    generationUsage: "Report generation usage", unknown: "Unknown", record: "Record", quote: "Source quote",
    allow: "Allow", block: "Block", reviewAction: "Review", ready: "Ready", withheld: "Withheld", unavailable: "Report only",
    text: "Text", image: "Image", urlKind: "URL", person: "Person", email: "Email", phone: "Phone", address: "Address",
    benign: "Benign", injectionValue: "Injection", suspicious: "Suspicious", malicious: "Malicious",
    none: "None", low: "Low", medium: "Medium", high: "High", critical: "Critical",
    legitimate: "Legitimate", impersonation: "Impersonation", credential_harvesting: "Credential harvesting", scam_or_bait: "Scam or bait", not_established: "Not established", risk: "Malicious / pirated site probability",
  },
  zh: {
    title: "Preflight 安检报告", generated: "生成时间", source: "检查对象", verdict: "最终处置",
    confidence: "模型置信度", usage: "扫描用量", calls: "次调用", tokens: "令牌", time: "毫秒",
    policy: "处置规则", model: "模型建议", injection: "提示注入", script: "脚本安全", pii: "个人信息",
    severity: "严重程度", score: "分数", counts: "检出数量", evidence: "原文证据", sources: "来源与抓取记录",
    url: "请求网址", final: "分析网址", fetched: "抓取时间", hash: "响应 SHA-256", redirects: "跳转记录",
    claims: "页面声称", flags: "域名信号", identity: "仿冒与意图", brand: "品牌身份", intent: "内容意图",
    passages: "选取段落", pdf: "PDF 文本层检查", pdfScope: "仅检查文字属性，不包含渲染、OCR 或遮挡检查。",
    page: "页码", status: "状态", copy: "待转交副本", reason: "原因", changes: "删改记录",
    removed: "移除指令数量", masked: "遮盖个人信息数量", recheck: "副本复检",
    human: "转交前需要人工核对删改后的内容。", edits: "删改对照", before: "原文", after: "处理后",
    range: "原文字符位置", draft: "处理稿：尚未获准转交", review: "生成的复核报告草稿", summary: "风险摘要",
    steps: "人工复核建议", generatedNote: "生成内容需人工核对，判定和证据以以下扫描记录为准。",
    generationUsage: "报告生成用量", unknown: "未知", record: "记录", quote: "原文引用",
    allow: "通过", block: "拦截", reviewAction: "需确认", ready: "可复制", withheld: "待复核", unavailable: "仅提供报告",
    text: "文本", image: "图片", urlKind: "网址", person: "姓名", email: "邮箱", phone: "电话", address: "地址",
    benign: "无害", injectionValue: "提示注入", suspicious: "可疑", malicious: "恶意",
    none: "无", low: "低", medium: "中", high: "高", critical: "严重",
    legitimate: "正常品牌身份", impersonation: "品牌仿冒", credential_harvesting: "索取凭据", scam_or_bait: "欺诈或诱导", not_established: "尚未确定", risk: "恶意或盗版网站概率",
  },
};

function reportMarkdown(report, language = "en", reviewReport = null) {
  const L = REPORT_LABELS[language] || REPORT_LABELS.en;
  const translate = value => ({ review: L.reviewAction, injection: L.injectionValue, url: L.urlKind }[value] || L[value] || value || L.unknown);
  const message = key => I18N[language]?.[key] || I18N.en[key] || key;
  const percentage = value => `${(Math.max(0, Math.min(1, value || 0)) * 100).toFixed(1)}%`;
  // HTML tags in evidence remain visible literal text when Markdown is rendered.
  const literal = value => String(value ?? L.unknown).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const lines = [`# ${L.title}`, "", `- ${L.generated}: ${new Date().toISOString()}`];
  const item = (label, value) => lines.push(`- ${label}: ${literal(value)}`);
  const section = label => lines.push("", `## ${label}`, "");
  const quote = value => lines.push(...String(value).split("\n").map(line => `> ${literal(line)}`));
  const usage = (value, calls, ms) => `${calls || 0} ${L.calls}, ${value?.input_tokens || 0} / ${value?.output_tokens || 0} ${L.tokens}, ${ms || 0} ${L.time}`;
  const action = report.action || {};
  item(L.source, `${translate(report.source?.kind)}${report.source?.name ? `: ${report.source.name}` : ""}`);
  item(L.verdict, translate(action.choice)); item(L.confidence, percentage(action.confidence));
  if (report.risk?.malicious_probability != null) item(L.risk, percentage(report.risk.malicious_probability));
  item(L.usage, usage(report.usage, report.usage?.calls, report.total_ms));
  if (reviewReport?.language === language) {
    section(L.review); lines.push(literal(reviewReport.generated.title), "", L.generatedNote);
    lines.push("", `### ${L.summary}`, "", literal(reviewReport.generated.summary));
    lines.push("", `### ${L.steps}`, "", literal(reviewReport.generated.review_steps));
    item(L.generationUsage, usage(reviewReport.usage, reviewReport.calls, reviewReport.total_ms));
  }
  section(L.policy); item(L.model, translate(action.model_choice || action.choice));
  if (report.policy?.version) item(L.policy, report.policy.version);
  for (const rule of report.policy?.reasons || []) lines.push(`- ${literal(message(`policy.${rule.code}`))}`);
  const layers = report.layers || {};
  for (const [key, scoreKey, heading] of [["injection", "injection", L.injection], ["script", "malicious", L.script]]) {
    const layer = layers[key];
    if (!layer) continue;
    section(heading); item(L.score, percentage(layer[scoreKey]));
    item(L.verdict, translate(layer.verdict)); item(L.severity, translate(layer.severity));
    for (const e of layer.evidence || []) { item(L.range, `${e.start}–${e.end}`); quote(e.quote ?? e.text ?? ""); }
  }
  const pii = layers.pii || {};
  if (Object.keys(pii.counts || {}).length) {
    section(L.pii);
    for (const [kind, count] of Object.entries(pii.counts)) item(translate(kind), count);
  }
  const u = report.url;
  if (u) {
    section(L.sources); const receipt = u.snapshot || {};
    item(L.url, receipt.requested_url || u.url); item(L.final, receipt.url); item(L.fetched, receipt.fetched_at); item(L.hash, receipt.sha256);
    for (const hop of receipt.redirects || []) item(L.redirects, `${hop.from} -> ${hop.to}`);
    for (const c of u.claims || []) { item(L.claims, c.value); item(L.status, message(`evidence.status.${c.status}`)); if (c.quote) quote(c.quote); }
    for (const s of u.sources || []) {
      item(message(`evidence.kind.${s.kind}`), s.value ?? s.domains?.join(", "));
      item(L.status, message(`evidence.status.${s.status}`));
      if (s.url || s.server) item(L.source, s.url || s.server);
      if (s.checked_at) item(L.fetched, s.checked_at);
    }
    if (u.flags?.length) { section(L.flags); for (const f of u.flags) item(translate(f.severity), `${f.title}: ${f.detail}`); }
    const imp = layers.impersonation;
    if (imp) { section(L.identity); item(L.brand, `${translate(imp.brand?.choice)} (${percentage(imp.brand?.confidence)})`); item(L.intent, `${translate(imp.intent?.choice)} (${percentage(imp.intent?.confidence)})`); }
    if (layers.identity) { section(message("url.identity")); quote(JSON.stringify(layers.identity.claims || layers.identity, null, 2)); }
    if (layers.passages?.picked?.length) { section(L.passages); for (const p of layers.passages.picked) quote(p.text); }
  }
  if (report.pdf_inspection) {
    const pdf = report.pdf_inspection; section(L.pdf); lines.push(L.pdfScope);
    item(L.status, message(`pdf.status.${pdf.status}`)); item(L.page, `${pdf.pages_checked}/${pdf.pages}`);
    for (const f of pdf.findings || []) { item(message(`pdf.kind.${f.kind}`), f.page ?? L.record); quote(f.text); }
    for (const entry of pdf.metadata || []) item(entry.field, entry.value);
  }
  const h = report.handoff;
  if (h) {
    section(L.copy); item(L.status, translate(h.status)); item(L.reason, message(`handoff.reason.${h.reason}`));
    if (h.changes?.removed) item(L.removed, h.changes.removed);
    if (h.changes?.masked) item(L.masked, h.changes.masked);
    if (h.verification) item(L.recheck, translate(h.verification.action.choice));
    if (h.status === "review") lines.push("", L.human);
    if (typeof h.text === "string") quote(h.text);
    else if (typeof h.draft_text === "string") { lines.push("", `### ${L.draft}`, ""); quote(h.draft_text); }
    if (h.edits?.length) {
      lines.push("", `### ${L.edits}`, "");
      for (const e of h.edits) { item(L.range, `${e.start}–${e.end}`); lines.push(`**${L.before}**`); quote(e.before); lines.push(`**${L.after}**`); quote(e.after); }
    }
  }
  return lines.join("\n");
}
