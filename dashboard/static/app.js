/* auto-hole 只读面板前端：原生 JS，无外部依赖，所有动态内容均转义。 */
"use strict";

const S = { runs: [], runId: "", view: "overview", page: 1, size: 20,
            severity: "", loading: false, token: "", jobTimer: null,
            jobLogId: "", jobStatuses: {}, triageTimer: null, triageJobId: "" };

const TITLES = {
  overview: "总览", newjob: "新建任务", triage: "目标体检", targets: "目标清单",
  runs: "运行详情", assets: "资产", findings: "命中", authz: "越权检测",
  evolution: "进化历史", audit: "审计流水"
};
const NEED_RUN = new Set(["runs", "assets", "findings", "authz", "triage", "audit"]);

function esc(v) {
  return String(v === null || v === undefined ? "" : v)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n.toLocaleString("zh-CN") : esc(v);
}
function pct(v) { return (Number(v) || 0).toFixed(1) + "%"; }
function empty(msg) { return `<div class="empty">${esc(msg)}</div>`; }
function badge(text, cls) { return `<span class="badge ${esc(cls || "")}">${esc(text)}</span>`; }

async function api(path) {
  const res = await fetch(path, { headers: { "Accept": "application/json" } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function postJSON(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json",
      "X-AutoHole-Token": S.token
    },
    body: JSON.stringify(body || {})
  });
  let data = {};
  try { data = await res.json(); } catch (e) { data = {}; }
  if (!res.ok) {
    const err = new Error(data.error || `HTTP ${res.status}`);
    err.payload = data;
    throw err;
  }
  return data;
}

function runLabel(r) {
  return `${r.target || "未命名"} · ${r.generated_at || "-"}`;
}

function runOptions(selected) {
  return S.runs.map(r =>
    `<option value="${esc(r.id)}"${r.id === selected ? " selected" : ""}>${esc(runLabel(r))}</option>`
  ).join("");
}

function currentRun() {
  return S.runs.find(r => r.id === S.runId) || S.runs[0] || null;
}

async function loadRuns() {
  const data = await api("/api/runs");
  S.runs = data.items || [];
  if (!S.runId || !S.runs.some(r => r.id === S.runId)) {
    S.runId = S.runs.length ? S.runs[0].id : "";
  }
  const picker = document.getElementById("run-picker");
  picker.innerHTML = S.runs.length ? runOptions(S.runId) : "";
  document.getElementById("run-picker-wrap").hidden = !S.runs.length;
}

function pager(data) {
  return `<div class="pager">
    <button class="act" data-action="page" data-dir="-1" ${data.page <= 1 ? "disabled" : ""}>上一页</button>
    <span class="muted">第 ${num(data.page)} / ${num(data.pages)} 页 · 共 ${num(data.total)} 条</span>
    <button class="act" data-action="page" data-dir="1" ${data.page >= data.pages ? "disabled" : ""}>下一页</button>
  </div>`;
}

function card(k, v, hint) {
  return `<div class="card"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div>
    ${hint ? `<div class="h">${esc(hint)}</div>` : ""}</div>`;
}

function sevBars(sev) {
  const items = Object.entries(sev || {}).sort((a, b) => b[1] - a[1]);
  if (!items.length) return empty("暂无命中等级数据");
  const max = Math.max(...items.map(x => Number(x[1]) || 0), 1);
  return `<div class="bars">` + items.map(([k, v]) =>
    `<div class="bar-row">
      <span>${badge(k, k)}</span>
      <div class="bar-track"><div class="bar-fill ${esc(k)}" style="width:${(Number(v) / max * 100).toFixed(1)}%"></div></div>
      <span class="num">${num(v)}</span>
    </div>`).join("") + `</div>`;
}

/* ---------------------------------------------------------------- 视图 */
async function renderOverview() {
  const d = await api("/api/overview");
  document.getElementById("view-sub").textContent =
    `运行 ${num(d.runs)} 次 · ${esc(d.status || "")}`;
  const latest = d.latest;
  const latestHtml = latest
    ? `<div class="kv">
        <span>目标</span><span>${esc(latest.target)}</span>
        <span>时间</span><span>${esc(latest.generated_at)}</span>
        <span>档位</span><span>${esc(latest.profile || "-")}</span>
        <span>耗时</span><span>${num(latest.elapsed_s)} s</span>
        <span>资产 / 命中</span><span>${num(latest.assets_alive)} / ${num(latest.findings_total)}</span>
        <span>警告</span><span>${num(latest.warnings)}</span>
      </div>`
    : empty("暂无运行数据");
  document.getElementById("view").innerHTML = `
    <div class="cards">
      ${card("累计运行", num(d.runs), "去重后（同目标+时间）")}
      ${card("资产", num(d.assets), "累计存活资产")}
      ${card("命中", num(d.findings), "含误报标记")}
      ${card("越权疑似", num(d.authz_suspects || 0), "IDOR / 垂直越权（只读 GET）")}
      ${card("误报率", d.false_positive_rate === null ? "—" : pct(d.false_positive_rate), `误报 ${num(d.false_positives)} 条`)}
      ${card("平均耗时", d.avg_elapsed_s === null ? "—" : num(d.avg_elapsed_s) + " s", "仅统计有耗时的运行")}
    </div>
    <div class="two-col">
      <div class="panel"><h2>命中等级分布</h2>${sevBars(d.severity)}</div>
      <div class="panel"><h2>最近一次运行</h2>${latestHtml}</div>
    </div>`;
}

async function renderTargets() {
  const d = await api("/api/targets");
  const items = d.items || [];
  document.getElementById("view-sub").textContent = `可挖 ${items.filter(x => x.executable).length} · blocked ${items.filter(x => !x.executable).length}`;
  if (!items.length) { document.getElementById("view").innerHTML = empty("暂无授权档案（main.py import）"); return; }
  document.getElementById("view").innerHTML = `
    <div class="panel"><h2>目标清单</h2>
      <table><thead><tr><th>厂商</th><th>状态</th><th class="num">资产</th><th>档位</th>
      <th>越权</th><th>上次运行</th><th class="num">上次命中</th><th>原因</th></tr></thead><tbody>
      ${items.map(t => `<tr>
        <td>${esc(t.vendor)}</td>
        <td>${t.executable ? badge("可执行", "S") : badge("blocked", "high")} ${esc(t.status)}</td>
        <td class="num">${num(t.asset_count)}</td>
        <td>${esc(t.tier)}</td>
        <td>${t.authz_configured ? badge("已配置", "info") : "-"}</td>
        <td class="mono">${esc(t.last_run || "-")}</td>
        <td class="num">${num(t.last_hits)}</td>
        <td class="muted">${esc((t.reasons || []).join("；") || "-")}</td>
      </tr>`).join("")}</tbody></table>
    </div>`;
}

async function renderRuns() {
  const runs = S.runs;
  if (!runs.length) { document.getElementById("view").innerHTML = empty("暂无运行产物"); return; }
  const rows = runs.map(r => `<tr data-action="select-run" data-id="${esc(r.id)}" style="cursor:pointer">
    <td>${r.kind === "triage" ? badge(`体检 · ${r.triage_verdict || "已完成"}`, "info") : badge("侦察", "")}</td>
    <td>${esc(r.target)}</td>
    <td class="mono">${esc(r.generated_at)}</td>
    <td>${esc(r.profile || "-")}</td>
    <td class="num">${num(r.elapsed_s)} s</td>
    <td class="num">${num(r.assets_alive)}</td>
    <td class="num">${num(r.findings_total)}</td>
    <td class="num">${r.has_authz ? num(r.authz_suspects) : "-"}</td>
    <td class="num">${num(r.requests_probe)} + ${num(r.requests_scan_estimated)}*</td>
    <td>${r.warnings ? badge("有警告", "medium") : badge("完成", "S")}</td>
  </tr>`).join("");
  document.getElementById("view").innerHTML = `
    <div class="panel"><h2>运行列表（*扫描请求为估算）</h2>
      <table><thead><tr><th>类型</th><th>目标</th><th>时间</th><th>档位</th><th class="num">耗时</th>
      <th class="num">资产</th><th class="num">命中</th><th class="num">越权</th>
      <th class="num">探测+扫描</th><th>状态</th></tr></thead>
      <tbody>${rows}</tbody></table>
    </div><div id="run-detail"></div>`;
  if (S.runId) await renderRunDetail(S.runId);
}

async function renderRunDetail(id) {
  const d = await api(`/api/run?id=${encodeURIComponent(id)}`);
  const el = document.getElementById("run-detail");
  if (!el) return;
  const stages = d.stages || [];
  const req = d.requests || {};
  const lim = d.limiter || {};
  const quota = d.quota || {};
  const stageHtml = stages.length ? `<div class="bars">` + stages.map(s =>
    `<div class="bar-row"><span>${esc(s.stage)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${Number(s.percent) || 0}%"></div></div>
      <span class="num">${num(s.seconds)}s / ${pct(s.percent)}</span></div>`).join("") + `</div>`
    : empty("暂无阶段耗时");
  el.innerHTML = `
    <div class="panel"><h2>运行详情 · ${esc(d.run.target)}</h2>
      <div class="cards">
        ${card("探测请求（实测）", num(req.probe_measured))}
        ${card("扫描请求（估算）", num(req.scan_estimated), "URL × 15，非实测")}
        ${card("探测日配额（账本）", `${num(quota.used)} / ${num(quota.daily_limit)}`, `剩余 ${num(quota.remaining)}`)}
        ${card("限速/熔断", `${num(lim.throttled)} / ${num(lim.budget_stop)}`, `circuit=${esc(lim.circuit)}`)}
      </div>
      <div class="two-col" style="margin-top:14px">
        <div><h2>阶段耗时占比</h2>${stageHtml}</div>
        <div><h2>配额与限速</h2>
          <div class="kv">
            <span>扫描 URL</span><span>${num(req.scan_urls)}</span>
            <span>实测速率</span><span>${lim.effective_rps === null || lim.effective_rps === undefined ? "-" : esc(lim.effective_rps)} rps</span>
            <span>限速事件</span><span>${num(lim.throttled)}</span>
            <span>配额中止</span><span>${num(lim.budget_stop)}</span>
            <span>请求错误</span><span>${num(lim.errors)}</span>
          </div>
          <p class="muted" style="margin-top:10px">限速/熔断计数来自审计流水；未记录的事件显示 0。</p>
        </div>
      </div>
      ${(d.warnings || []).length ? `<div class="panel"><h2>警告</h2>${d.warnings.map(w => `<div class="muted">${esc(w)}</div>`).join("")}</div>` : ""}
    </div>`;
}

async function renderAssets() {
  const run = currentRun();
  if (!run) { document.getElementById("view").innerHTML = empty("暂无运行数据"); return; }
  const d = await api(`/api/assets?id=${encodeURIComponent(run.id)}&page=${S.page}&size=${S.size}`);
  document.getElementById("view-sub").textContent = `${run.target} · 资产 ${num(d.total)} 条`;
  if (!d.items.length) { document.getElementById("view").innerHTML = empty("该运行没有资产数据"); return; }
  document.getElementById("view").innerHTML = `
    <div class="panel"><h2>资产</h2>
      <table><thead><tr><th>主机</th><th class="num">端口</th><th class="num">状态</th>
      <th>标题</th><th>指纹（置信度）</th><th>来源</th></tr></thead><tbody>
      ${d.items.map(a => `<tr>
        <td class="mono">${esc(a.host)}</td>
        <td class="num">${num(a.port)}</td>
        <td class="num">${num(a.status)}</td>
        <td>${esc(a.title || "-")}</td>
        <td>${(a.products || []).map(p => `${esc(p.product)}<span class="muted"> (${(Number(p.confidence) || 0).toFixed(2)})</span>`).join("<br>") || "-"}</td>
        <td class="muted">${esc((a.sources || []).join(", ") || "-")}</td>
      </tr>`).join("")}</tbody></table>
      ${pager(d)}
    </div>`;
}

async function renderFindings() {
  const run = currentRun();
  if (!run) { document.getElementById("view").innerHTML = empty("暂无运行数据"); return; }
  const sev = S.severity ? `&severity=${encodeURIComponent(S.severity)}` : "";
  const d = await api(`/api/findings?id=${encodeURIComponent(run.id)}&page=${S.page}&size=${S.size}${sev}`);
  document.getElementById("view-sub").textContent = `${run.target} · 命中 ${num(d.total)} 条`;
  const filter = `<select id="sev-filter">
    ${["", "critical", "high", "medium", "low", "info"].map(x =>
      `<option value="${esc(x)}"${x === S.severity ? " selected" : ""}>${x ? esc(x) : "全部等级"}</option>`).join("")}
    </select>`;
  if (!d.items.length) {
    document.getElementById("view").innerHTML = `<div class="panel">${filter}</div>` + empty("该运行没有命中（或当前筛选为空）");
    bindSeverity();
    return;
  }
  document.getElementById("view").innerHTML = `
    <div class="panel"><h2>命中 ${filter}</h2>
      <table><thead><tr><th>等级</th><th>评分</th><th>漏洞</th><th>产品</th>
      <th>命中地址</th><th>tags</th><th>证据 / 报告</th></tr></thead><tbody>
      ${d.items.map(f => `<tr>
        <td>${badge(f.severity, f.severity)}</td>
        <td>${f.grade ? badge(f.grade, f.grade) : "-"} <span class="muted">${num(f.score)}</span></td>
        <td>${esc(f.name)}<div class="muted mono">${esc(f.template_id)}</div></td>
        <td>${esc(f.product || "-")}</td>
        <td class="mono">${esc(f.matched_at || "-")}</td>
        <td>${(f.tags || []).map(t => `<span class="tag">${esc(t)}</span>`).join("") || "-"}</td>
        <td>
          <details><summary>查看证据</summary>
            <pre class="evidence">${esc(f.request || "（无请求摘录）")}\n\n${esc(f.response || "（无响应摘录）")}${f.truncated ? "\n…（已截断）" : ""}</pre>
            ${f.curl ? `<pre class="evidence">${esc(f.curl)}</pre>` : ""}
          </details>
          ${f.has_report ? `<button class="act" data-action="report" data-template="${esc(f.template_id)}">导出报告</button>` : ""}
        </td>
      </tr>`).join("")}</tbody></table>
      ${pager(d)}
    </div>`;
  bindSeverity();
}

function bindSeverity() {
  const el = document.getElementById("sev-filter");
  if (!el) return;
  el.addEventListener("change", () => {
    S.severity = el.value; S.page = 1; renderFindings();
  });
}

/* ---------------------------------------------------------------- 目标体检 */
function triageFormHTML() {
  return `<div class="panel"><h2>提交目标体检</h2>
    <div class="form-grid">
      <label>厂商名 <input id="t-vendor" placeholder="与授权档案一致"></label>
      <label>补天项目链接或编号（授权依据） <input id="t-program" placeholder="链接或 Company 编号"></label>
      <label class="wide">资产范围（一行一个，不要写协议/路径）
        <textarea id="t-scope" rows="4" placeholder="a.example.com&#10;1.2.3.4"></textarea>
      </label>
      <label class="wide">平台禁止项（原文）
        <textarea id="t-restrictions" rows="2" placeholder="允许低速率自动化侦察；禁止破坏性测试"></textarea>
      </label>
      <label>体检请求上限 <input id="t-max" type="number" value="60" min="1" max="200"></label>
      <label class="check"><input type="checkbox" id="t-confirm"> 我确认对该资产有测试授权</label>
    </div>
    <div id="triage-errors" class="errors"></div>
    <button class="act" id="triage-submit">开始体检</button>
    <p class="secret-note">只做种子采集 / 存活探测 / 指纹 / 暴露面梳理 / 研判；<b>不调用 nuclei 或模板扫描</b>，请求上限默认 60。</p>
    <div id="triage-status" class="muted" style="margin-top:8px"></div>
  </div><div id="triage-result"></div>`;
}

async function renderTriage() {
  document.getElementById("view-sub").textContent =
    "只做侦察与研判，零扫描请求；输出 triage.md / triage.json";
  document.getElementById("view").innerHTML = triageFormHTML();
  document.getElementById("triage-submit").addEventListener("click", submitTriage);
  let run = currentRun();
  if (!run || !run.has_triage) {
    const latest = S.runs.find(x => x.has_triage);
    if (latest) {
      S.runId = latest.id;
      run = latest;
      const picker = document.getElementById("run-picker");
      if (picker) picker.value = latest.id;
    }
  }
  if (run && run.has_triage) await renderTriageReport(run);
  else document.getElementById("triage-result").innerHTML = empty("暂无体检报告；提交一个目标开始体检");
}

async function submitTriage() {
  const errBox = document.getElementById("triage-errors");
  const status = document.getElementById("triage-status");
  errBox.innerHTML = "";
  const payload = {
    kind: "triage",
    tier: "light",
    vendor: document.getElementById("t-vendor").value.trim(),
    program_url: document.getElementById("t-program").value.trim(),
    scope: document.getElementById("t-scope").value,
    include_subdomains: true,
    include_third_party: false,
    restrictions_raw: document.getElementById("t-restrictions").value.trim(),
    max_requests: Number(document.getElementById("t-max").value) || 60,
    authorized: document.getElementById("t-confirm").checked
  };
  try {
    const res = await postJSON("/api/jobs", payload);
    status.textContent = `已提交 ${res.job.id}（排队中）`;
    startTriagePolling(res.job.id, payload.vendor);
  } catch (e) {
    const errs = (e.payload && e.payload.errors) || [e.message];
    errBox.innerHTML = errs.map(x => `<div class="errmsg">${esc(x)}</div>`).join("");
  }
}

function startTriagePolling(jobId, vendor) {
  stopTriagePolling();
  S.triageJobId = jobId;
  S.triageTimer = setInterval(async () => {
    if (S.view !== "triage") { stopTriagePolling(); return; }
    try {
      const d = await api(`/api/jobs/${encodeURIComponent(jobId)}?tail=40`);
      const j = d.job;
      const el = document.getElementById("triage-status");
      if (el) el.textContent = `${JOB_STATUS[j.status] || j.status} · ${j.stage || "-"}`;
      if (["done", "failed", "canceled"].includes(j.status)) {
        stopTriagePolling();
        if (j.status === "done") {
          await loadRuns();
          const run = S.runs.find(x => x.has_triage && x.target === vendor) ||
                      S.runs.find(x => x.has_triage);
          if (run) {
            S.runId = run.id;
            const picker = document.getElementById("run-picker");
            if (picker) picker.value = run.id;
            await renderTriageReport(run);
          }
          if (el) el.textContent = "体检完成，报告已刷新";
        } else {
          const tail = (d.log_tail || []).slice(-5).join("\n");
          if (el) el.textContent = `体检失败：${j.error || j.status}\n${tail}`;
        }
      }
    } catch (e) {
      const el = document.getElementById("triage-status");
      if (el) el.textContent = "任务状态读取失败：" + e.message;
    }
  }, 2000);
}

function stopTriagePolling() {
  if (S.triageTimer) { clearInterval(S.triageTimer); S.triageTimer = null; }
}

async function renderTriageReport(run) {
  const box = document.getElementById("triage-result");
  if (!box) return;
  if (!run || !run.has_triage) { box.innerHTML = empty("该运行没有体检报告"); return; }
  let d;
  try { d = await api(`/api/triage?id=${encodeURIComponent(run.id)}`); }
  catch (e) { box.innerHTML = empty("体检报告读取失败：" + e.message); return; }
  const r = d.report || {};
  const b = r.basics || {};
  const tech = r.tech || [];
  const exp = r.exposures || [];
  const risks = r.risks || [];
  const dup = r.duplicates || [];
  const cost = r.cost || {};
  const conc = r.conclusion || {};
  const waf = r.waf || [];
  const verdictClass = conc.verdict === "建议深挖" ? "S" : (conc.verdict === "可试" ? "medium" : "high");
  const cards = `<div class="cards">
    ${card("存活主机", num(b.alive_hosts), `响应 ${num(b.responses)} 条`)}
    ${card("端口", (b.ports || []).join(", ") || "-")}
    ${card("耗时中位数", b.median_response_ms === null || b.median_response_ms === undefined ? "-" : num(b.median_response_ms) + " ms")}
    ${card("请求预算", `${num((b.request_budget || {}).used)} / ${num((b.request_budget || {}).limit)}`, (b.request_budget || {}).exhausted ? "预算已用尽" : "共享令牌桶")}
    ${card("结论", conc.verdict || "-", `评分 ${num(conc.score)}`)}
  </div>`;
  const techHtml = tech.length ? `<table><thead><tr><th>主机</th><th>产品</th><th>版本</th>
    <th>版本来源</th><th class="num">置信度</th></tr></thead><tbody>
    ${tech.map(t => `<tr><td class="mono">${esc(t.host)}</td><td>${esc(t.product)}</td>
      <td>${esc(t.version || "未识别")}</td><td class="muted">${esc(t.version_source || "-")}</td>
      <td class="num">${(Number(t.confidence) || 0).toFixed(2)}</td></tr>`).join("")}</tbody></table>`
    : empty("未识别到技术栈");
  const expHtml = exp.length ? `<table><thead><tr><th>类别</th><th>URL</th>
    <th class="num">状态</th><th>标题/说明</th></tr></thead><tbody>
    ${exp.map(e => `<tr><td>${badge(e.category, "info")}</td><td class="mono">${esc(e.url)}</td>
      <td class="num">${num(e.status)}</td><td>${esc(e.title || e.reason || "-")}</td></tr>`).join("")}</tbody></table>`
    : empty("未发现可记录的暴露面");
  const riskHtml = risks.length ? risks.map(x => `<div class="kv" style="margin-bottom:8px">
      <span>${esc(x.product)} ${esc(x.version || "（版本未识别）")}</span><span>${badge("推断", "medium")} ${esc(x.severity)}</span>
      <span>方向</span><span>${esc(x.direction)}${(x.cves || []).length ? "；参考 " + esc(x.cves.join(", ")) : ""}</span>
      <span>依据</span><span class="muted">${esc(x.basis)}</span></div>`).join("")
    : empty("没有匹配到本地离线风险库的方向");
  const dupHtml = dup.length ? dup.map(x => `<div class="muted">- ${esc(x.product)}：高重复概率（${esc(x.reason)}）</div>`).join("")
    : empty("未命中热门产品/本地已公开披露库");
  const wafHtml = waf.length ? waf.map(x => badge(x.name, "high")).join(" ") : "-";
  box.innerHTML = `<div class="panel"><h2>体检报告 · ${esc(r.target || run.target)}</h2>
    <div class="kv">
      <span>模式</span><span>triage（零 nuclei/模板扫描）</span>
      <span>生成时间</span><span class="mono">${esc(r.generated_at || "-")}</span>
      <span>WAF/CDN</span><span>${wafHtml}</span>
      <span>导出</span><span><a class="act" href="/api/triage?id=${encodeURIComponent(run.id)}&format=md" download="triage.md">Markdown</a>
        <a class="act" href="/api/triage?id=${encodeURIComponent(run.id)}&format=json" download="triage.json">JSON</a></span>
    </div>${cards}
    <p class="secret-note">风险方向、重复概率、成本与结论均为推断，不是已发现漏洞；报告基于实际探测数据生成。</p>
  </div>
  <div class="panel"><h2>1. 基础面</h2><div class="kv">
    <span>存活主机</span><span>${num(b.alive_hosts)}</span>
    <span>开端口</span><span>${esc((b.ports || []).join(", ") || "-")}</span>
    <span>状态码分布</span><span>${esc(JSON.stringify(b.status_distribution || {}))}</span>
    <span>响应耗时中位数</span><span>${b.median_response_ms === null || b.median_response_ms === undefined ? "-" : num(b.median_response_ms) + " ms"}</span>
  </div></div>
  <div class="panel"><h2>2. 技术栈（带版本号优先）</h2>${techHtml}</div>
  <div class="panel"><h2>3. 暴露面（只探测，不利用）</h2>${expHtml}</div>
  <div class="panel"><h2>4. 风险方向（推断）</h2>${riskHtml}</div>
  <div class="panel"><h2>5. 重复风险提示（推断）</h2>${dupHtml}</div>
  <div class="panel"><h2>6. 成本预估（推断）</h2><div class="kv">
    <span>预估请求数</span><span>${num(cost.estimated_requests)}</span>
    <span>预估耗时</span><span>${num(cost.estimated_seconds)} s</span>
    <span>建议档位</span><span>${esc(cost.recommended_tier || "-")}</span>
    <span>依据</span><span class="muted">${esc(cost.basis || "-")}</span>
  </div></div>
  <div class="panel"><h2>7. 结论</h2>
    <div class="kv"><span>判定</span><span>${badge(conc.verdict || "-", verdictClass)}</span>
      <span>评分</span><span>${num(conc.score)}</span>
      <span>理由</span><span>${esc(conc.reason || "-")}</span>
      <span>信号</span><span>${esc((conc.signals || []).join("；") || "-")}</span></div>
    ${(r.warnings || []).length ? `<p class="muted">警告：${esc(r.warnings.join("；"))}</p>` : ""}
  </div>`;
}

async function renderAuthz() {
  const run = currentRun();
  if (!run) { document.getElementById("view").innerHTML = empty("暂无运行数据"); return; }
  const d = await api(`/api/authz?id=${encodeURIComponent(run.id)}&page=${S.page}&size=${S.size}`);
  const s = d.summary || {};
  document.getElementById("view-sub").textContent =
    `${run.target} · 越权疑似 ${num(s.suspects || 0)} 条（只读 GET）`;
  if (!d.has_authz) {
    document.getElementById("view").innerHTML = empty("该运行未执行越权检测（提交任务时未配置两账号，或检测阶段失败）");
    return;
  }
  const base = s.paths || {};
  const ident = (s.identities || []).map(i => `${i.name}（${i.role}）`).join(" / ");
  const cards = `
    <div class="cards">
      ${card("疑似越权", num(s.suspects || 0), `水平 ${num(s.horizontal_suspects || 0)} / 垂直 ${num(s.vertical_suspects || 0)}`)}
      ${card("公共页抑制", num(s.suppressed_public || 0), "匿名访问与 A 内容相同，已抑制")}
      ${card("正常/负样本", num(s.normal || 0), `垂直测试 ${num(s.vertical_tested || 0)} · 水平测试 ${num(s.horizontal_tested || 0)}`)}
      ${card("请求预算", `${num(s.requests || 0)} / ${num(s.max_requests || 0)}`, s.budget_exhausted ? "预算已用尽，提前停止" : "共享令牌桶")}
    </div>`;
  const meta = `<div class="panel"><h2>检测参数</h2>
    <div class="kv">
      <span>身份</span><span>${esc(ident || "-")}</span>
      <span>相似度阈值</span><span>${num(s.threshold || 0)}（公共页 ${num(s.public_similarity || 0)}）</span>
      <span>候选 URL</span><span>${num(s.candidates || 0)}；GET 重放，不测试写方法</span>
      <span>账号元数据</span><span class="mono">${esc((s.accounts || {}).path || "-")}</span>
      <span>报告</span><span class="mono">${esc(base.report || "-")}</span>
    </div>
    <p class="secret-note">凭据只在内存解密；本页、审计、summary、报告均不显示 cookie/header 原文。</p>
  </div>`;
  const rows = (d.items || []).map(item => `<tbody>
    <tr>
      <td>${item.kind === "vertical" ? badge("垂直", "medium") : badge("水平/IDOR", "high")}</td>
      <td class="mono">${esc(item.url)}</td>
      <td class="num">${num(item.a_status)} / ${num(item.b_status)}</td>
      <td class="num">${(Number(item.similarity) || 0).toFixed(3)}</td>
      <td>${esc(item.reason)}<div class="muted">${esc((item.sensitive_fields || []).join(", ") || "")}</div></td>
      <td><details class="authz-evidence"><summary>对比 A/B 响应（脱敏）</summary>
        <div class="sample-grid">
          <div><h3>A · ${esc(item.identity_a)} · HTTP ${num(item.a_status)} · ${num(item.a_len)} B</h3>
            <pre class="evidence">${esc(item.a_sample || "（空）")}</pre></div>
          <div><h3>B · ${esc(item.identity_b)} · HTTP ${num(item.b_status)} · ${num(item.b_len)} B</h3>
            <pre class="evidence">${esc(item.b_sample || "（空）")}</pre></div>
        </div>
      </details></td>
    </tr>
  </tbody>`).join("");
  const table = rows
    ? `<div class="panel"><h2>疑似越权（同一 URL 的 A/B 响应并排）</h2>
        <table><thead><tr><th>类型</th><th>URL</th><th class="num">A/B 状态</th>
        <th class="num">相似度</th><th>判定依据 / 敏感字段</th><th>证据</th></tr></thead>
        ${rows}</table>${pager(d)}</div>`
    : `<div class="panel"><h2>疑似越权</h2>${empty("未发现疑似越权；负样本与公共页抑制计数见上方")}</div>`;
  document.getElementById("view").innerHTML = cards + meta + table;
}

async function renderEvolution() {
  const d = await api("/api/evolution");
  const candidates = d.candidates || [];
  const versions = d.versions || [];
  document.getElementById("view-sub").textContent =
    `候选 ${num(candidates.length)} 条 · 版本 ${num(versions.length)} 个`;
  const cHtml = candidates.length ? `<table><thead><tr><th>ID</th><th>类型</th><th>状态</th>
    <th>产品</th><th>验证结果</th></tr></thead><tbody>
    ${candidates.map(c => `<tr>
      <td class="mono">${esc(c.id)}</td>
      <td>${esc(c.kind)}</td>
      <td>${badge(c.status, c.status === "passed" ? "S" : "high")}</td>
      <td>${esc(c.product || "-")}</td>
      <td class="muted mono">${esc(JSON.stringify(c.validation || {}).slice(0, 220))}</td>
    </tr>`).join("")}</tbody></table>` : empty("暂无候选（evolve propose）");
  const vHtml = versions.length ? `<table><thead><tr><th>版本</th><th>动作</th>
    <th>候选</th><th>说明</th><th>时间</th></tr></thead><tbody>
    ${versions.map(v => `<tr>
      <td class="num">v${esc(v.version)}</td>
      <td>${esc(v.action || "-")}</td>
      <td class="mono">${esc(v.candidate || "-")}</td>
      <td>${esc(v.note || "")}</td>
      <td class="mono">${esc(v.created_at || "-")}</td>
    </tr>`).join("")}</tbody></table>` : empty("暂无版本记录（evolve approve）");
  document.getElementById("view").innerHTML = `
    <div class="panel"><h2>候选规则 / 模板（正负样本回归）</h2>${cHtml}</div>
    <div class="panel"><h2>版本快照与回滚</h2>${vHtml}</div>`;
}

async function renderAudit() {
  const run = currentRun();
  if (!run) { document.getElementById("view").innerHTML = empty("暂无运行数据"); return; }
  const d = await api(`/api/audit?id=${encodeURIComponent(run.id)}&page=${S.page}&size=${S.size}`);
  document.getElementById("view-sub").textContent = `${run.target} · 审计 ${num(d.total)} 条`;
  if (!d.items.length) { document.getElementById("view").innerHTML = empty("该运行没有审计流水"); return; }
  document.getElementById("view").innerHTML = `
    <div class="panel"><h2>审计流水</h2>
      <table><thead><tr><th>时间</th><th>事件</th><th>主机</th><th>URL</th>
      <th class="num">状态</th><th class="num">耗时 ms</th><th class="num">速率</th><th>结果</th></tr></thead><tbody>
      ${d.items.map(a => `<tr>
        <td class="mono">${esc(a.ts || "")}</td>
        <td>${esc(a.event || "")}</td>
        <td class="mono">${esc(a.host || "")}</td>
        <td class="mono">${esc(a.url || "")}</td>
        <td class="num">${a.status === undefined || a.status === null ? "-" : num(a.status)}</td>
        <td class="num">${a.elapsed_ms === undefined ? "-" : esc(a.elapsed_ms)}</td>
        <td class="num">${a.rps === undefined ? "-" : esc(a.rps)}</td>
        <td>${esc(a.outcome || a.reason || "")}</td>
      </tr>`).join("")}</tbody></table>
      ${pager(d)}
    </div>`;
}

/* ---------------------------------------------------------------- 新建任务 */
const JOB_STATUS = { queued: "排队", running: "运行中", done: "完成",
                     failed: "失败", canceled: "已取消" };

function newJobHTML() {
  return `
    <div class="panel">
      <h2>新建任务</h2>
      <div class="form-grid">
        <label>厂商名 <input id="j-vendor" placeholder="与补天项目页一致"></label>
        <label>补天项目链接或编号（授权依据） <input id="j-program" placeholder="补天项目页链接或 Company 编号"></label>
        <label class="wide">资产范围（一行一个，不要写协议/路径）
          <textarea id="j-scope" rows="5" placeholder="a.example.com&#10;1.2.3.4"></textarea>
        </label>
        <label>档位
          <select id="j-tier"><option value="light">light</option><option value="standard">standard</option></select>
        </label>
        <label class="check"><input type="checkbox" id="j-subdomains"> 含子域</label>
        <label class="check"><input type="checkbox" id="j-thirdparty"> 含第三方托管</label>
        <label class="wide">平台禁止项（原文）
          <textarea id="j-restrictions" rows="3" placeholder="允许低速率自动化扫描；禁止拒绝服务/破坏性测试"></textarea>
        </label>
        <label class="check wide"><input type="checkbox" id="j-confirm">
          我确认对该资产有测试授权，且授权依据真实有效</label>
      </div>
      <div class="sub-panel">
        <h2>只读越权检测（可选）</h2>
        <label class="check"><input type="checkbox" id="j-authz-enable"> 启用 IDOR / 水平 + 垂直越权检测（仅 GET）</label>
        <div id="j-authz-fields" hidden>
          <div class="form-grid">
            <label>身份 A 名称 <input id="j-a-name" value="A"></label>
            <label>身份 A 角色 <select id="j-a-role"><option value="high">high</option><option value="low">low</option><option value="user">user</option></select></label>
            <label class="wide">身份 A Cookie <input id="j-a-cookie" type="password" autocomplete="new-password" placeholder="sid=..."></label>
            <label class="wide">身份 A 会话校验 URL <input id="j-a-check" placeholder="完整 URL，例如 /api/me"></label>
            <label class="wide">身份 A 自定义 Header（一行一个 Name: value）
              <textarea id="j-a-headers" rows="2" placeholder="Authorization: Bearer ..."></textarea>
            </label>
            <label class="wide">身份 A 采集入口（一行一个，仅 GET）
              <textarea id="j-a-start" rows="2" placeholder="完整 URL，例如 127.0.0.1:18091/orders"></textarea>
            </label>
            <label>身份 B 名称 <input id="j-b-name" value="B"></label>
            <label>身份 B 角色 <select id="j-b-role"><option value="low">low</option><option value="high">high</option><option value="user">user</option></select></label>
            <label class="wide">身份 B Cookie <input id="j-b-cookie" type="password" autocomplete="new-password" placeholder="sid=..."></label>
            <label class="wide">身份 B 会话校验 URL <input id="j-b-check" placeholder="完整 URL，例如 /api/me"></label>
            <label class="wide">身份 B 自定义 Header（一行一个 Name: value）
              <textarea id="j-b-headers" rows="2" placeholder="X-Api-Key: ..."></textarea>
            </label>
            <label class="wide">身份 B 采集入口（一般留空）
              <textarea id="j-b-start" rows="2"></textarea>
            </label>
            <label class="wide">垂直越权路径（一行一个；留空按常见管理路径推断）
              <textarea id="j-authz-vertical" rows="2" placeholder="/admin/audit&#10;/admin/users"></textarea>
            </label>
            <label>最大越权请求数 <input id="j-authz-max" type="number" value="200"></label>
            <label>相似度阈值 <input id="j-authz-sim" type="number" step="0.01" value="0.90"></label>
          </div>
          <p class="secret-note">cookie/header 只写入本地 Fernet 加密库；页面、日志、审计、报告均脱敏显示。</p>
        </div>
      </div>
      <div id="job-errors" class="errors"></div>
      <button class="act" id="job-submit">提交并执行</button>
      <p class="muted">提交后写入 targets/authorized，并以子进程执行 recon；同一时间只执行一个任务。</p>
    </div>
    <div class="panel"><h2>任务队列</h2><div id="job-area">${empty("暂无任务")}</div></div>
    <div class="panel"><h2>任务日志（尾部）</h2><pre class="evidence" id="job-log">选择任务查看日志</pre></div>`;
}

async function renderNewJob() {
  document.getElementById("view-sub").textContent = "提交资产 → 校验 → 排队 → 子进程执行";
  document.getElementById("view").innerHTML = newJobHTML();
  document.getElementById("job-submit").addEventListener("click", submitJob);
  const authzToggle = document.getElementById("j-authz-enable");
  const authzFields = document.getElementById("j-authz-fields");
  authzToggle.addEventListener("change", () => {
    authzFields.hidden = !authzToggle.checked;
  });
  await loadJobs(true);
  startJobPolling();
}

function lineValues(id) {
  const el = document.getElementById(id);
  return el ? el.value.split(/\r?\n/).map(x => x.trim()).filter(Boolean) : [];
}

async function submitJob() {
  const errBox = document.getElementById("job-errors");
  errBox.innerHTML = "";
  const authzEnabled = document.getElementById("j-authz-enable").checked;
  const authz = { enabled: authzEnabled };
  if (authzEnabled) {
    authz.identities = [
      {
        name: document.getElementById("j-a-name").value.trim() || "A",
        role: document.getElementById("j-a-role").value,
        cookie: document.getElementById("j-a-cookie").value.trim(),
        headers: document.getElementById("j-a-headers").value,
        start_urls: lineValues("j-a-start"),
        session_check_url: document.getElementById("j-a-check").value.trim()
      },
      {
        name: document.getElementById("j-b-name").value.trim() || "B",
        role: document.getElementById("j-b-role").value,
        cookie: document.getElementById("j-b-cookie").value.trim(),
        headers: document.getElementById("j-b-headers").value,
        start_urls: lineValues("j-b-start"),
        session_check_url: document.getElementById("j-b-check").value.trim()
      }
    ];
    authz.vertical_paths = lineValues("j-authz-vertical");
    authz.max_requests = Number(document.getElementById("j-authz-max").value) || 200;
    authz.similarity_threshold = Number(document.getElementById("j-authz-sim").value) || 0.90;
  }
  const payload = {
    vendor: document.getElementById("j-vendor").value.trim(),
    program_url: document.getElementById("j-program").value.trim(),
    scope: document.getElementById("j-scope").value,
    include_subdomains: document.getElementById("j-subdomains").checked,
    include_third_party: document.getElementById("j-thirdparty").checked,
    restrictions_raw: document.getElementById("j-restrictions").value.trim(),
    tier: document.getElementById("j-tier").value,
    authorized: document.getElementById("j-confirm").checked,
    authz
  };
  try {
    const res = await postJSON("/api/jobs", payload);
    errBox.innerHTML = `<div class="okmsg">已提交：${esc(res.job.id)}（${esc(JOB_STATUS[res.job.status] || res.job.status)}）</div>`;
    document.getElementById("j-scope").value = "";
    document.getElementById("j-confirm").checked = false;
    if (authzEnabled) {
      document.getElementById("j-a-cookie").value = "";
      document.getElementById("j-a-headers").value = "";
      document.getElementById("j-b-cookie").value = "";
      document.getElementById("j-b-headers").value = "";
    }
    await loadJobs(true);
  } catch (e) {
    const errs = (e.payload && e.payload.errors) || [e.message];
    errBox.innerHTML = errs.map(x => `<div class="errmsg">${esc(x)}</div>`).join("");
  }
}

async function loadJobs(initial) {
  let data;
  try {
    data = await api("/api/jobs");
  } catch (e) {
    document.getElementById("job-area").innerHTML = empty("任务队列读取失败：" + e.message);
    return;
  }
  const items = data.items || [];
  let finished = false;
  items.forEach(j => {
    const old = S.jobStatuses[j.id];
    if (old && old !== j.status && ["done", "failed", "canceled"].includes(j.status)) {
      finished = true;
    }
    S.jobStatuses[j.id] = j.status;
  });
  renderJobArea(items);
  if (initial && items.length && !S.jobLogId) {
    S.jobLogId = items[0].id;
  }
  if (S.jobLogId) await loadJobLog(S.jobLogId);
  if (finished) {
    await loadRuns();
    if (S.view === "overview") await renderOverview();
    else if (S.view === "findings") await renderFindings();
    else if (S.view === "authz") await renderAuthz();
    const note = document.getElementById("job-refresh-note");
    if (note) note.textContent = "任务结束，总览/命中/越权数据已刷新";
  }
}

function renderJobArea(items) {
  const box = document.getElementById("job-area");
  if (!items.length) { box.innerHTML = empty("暂无任务"); return; }
  box.innerHTML = `<table><thead><tr><th>状态</th><th>厂商</th><th>档位</th>
    <th class="num">队列位</th><th>阶段</th><th>开始</th><th>结束</th><th>操作</th></tr></thead><tbody>
    ${items.map(j => `<tr data-action="job-log" data-job-id="${esc(j.id)}" style="cursor:pointer">
      <td>${badge(JOB_STATUS[j.status] || j.status,
                   j.status === "done" ? "S" : (j.status === "failed" ? "high" : ""))}
        <div class="muted mono">${esc(j.id)}</div></td>
      <td>${esc(j.vendor)}<div class="muted">${j.kind === "triage" ? "体检" : "侦察"}</div></td>
      <td>${esc(j.tier)}</td>
      <td class="num">${j.status === "running" ? "运行中" : (j.queue_position || "-")}</td>
      <td>${esc(j.stage || "-")}</td>
      <td class="mono">${esc(j.started_at || "-")}</td>
      <td class="mono">${esc(j.ended_at || "-")}</td>
      <td>${["queued", "running"].includes(j.status)
        ? `<button class="act" data-action="job-cancel" data-job-id="${esc(j.id)}">取消</button>` : "-"}</td>
    </tr>`).join("")}</tbody></table>
    <div id="job-refresh-note" class="muted" style="margin-top:8px"></div>`;
}

async function loadJobLog(id) {
  const el = document.getElementById("job-log");
  if (!el) return;
  try {
    const d = await api(`/api/jobs/${encodeURIComponent(id)}?tail=250`);
    const lines = d.log_tail || [];
    el.textContent = lines.length ? lines.join("\n") : "（暂无日志）";
    el.scrollTop = el.scrollHeight;
  } catch (e) {
    el.textContent = "日志读取失败：" + e.message;
  }
}

async function cancelJob(id) {
  try {
    await postJSON(`/api/jobs/${encodeURIComponent(id)}/cancel`, {});
    await loadJobs(false);
  } catch (e) {
    alert("取消失败：" + e.message);
  }
}

function startJobPolling() {
  stopJobPolling();
  S.jobTimer = setInterval(() => {
    if (S.view !== "newjob") { stopJobPolling(); return; }
    loadJobs(false).catch(() => {});
  }, 2000);
}
function stopJobPolling() {
  if (S.jobTimer) { clearInterval(S.jobTimer); S.jobTimer = null; }
}

/* ---------------------------------------------------------------- 调度 */
async function show(view, keepPage) {
  S.view = view;
  stopJobPolling();
  stopTriagePolling();
  if (!keepPage) S.page = 1;
  document.querySelectorAll("#nav button").forEach(b =>
    b.classList.toggle("active", b.dataset.view === view));
  document.getElementById("view-title").textContent = TITLES[view] || view;
  document.getElementById("run-picker-wrap").hidden = !NEED_RUN.has(view) || !S.runs.length;
  const el = document.getElementById("view");
  el.innerHTML = `<div class="empty">加载中…</div>`;
  try {
    if (view === "overview") await renderOverview();
    else if (view === "newjob") await renderNewJob();
    else if (view === "triage") await renderTriage();
    else if (view === "targets") await renderTargets();
    else if (view === "runs") await renderRuns();
    else if (view === "assets") await renderAssets();
    else if (view === "findings") await renderFindings();
    else if (view === "authz") await renderAuthz();
    else if (view === "evolution") await renderEvolution();
    else if (view === "audit") await renderAudit();
  } catch (e) {
    el.innerHTML = empty(`加载失败：${e.message}（数据缺失时请确认 --data-dir）`);
  }
}

function bind() {
  document.getElementById("nav").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-view]");
    if (b) show(b.dataset.view);
  });
  document.getElementById("run-picker").addEventListener("change", (e) => {
    S.runId = e.target.value; S.page = 1;
    show(S.view);
  });
  document.getElementById("view").addEventListener("click", async (e) => {
    const t = e.target.closest("[data-action]");
    if (!t) return;
    const act = t.dataset.action;
    if (act === "page") {
      S.page = Math.max(1, S.page + Number(t.dataset.dir || 0));
      show(S.view, true);
    } else if (act === "select-run") {
      S.runId = t.dataset.id; S.page = 1; show("runs");
    } else if (act === "job-log") {
      S.jobLogId = t.dataset.jobId;
      await loadJobLog(S.jobLogId);
    } else if (act === "job-cancel") {
      await cancelJob(t.dataset.jobId);
    } else if (act === "report") {
      const tid = t.dataset.template;
      try {
        const r = await api(`/api/reports?id=${encodeURIComponent(S.runId)}`);
        const hit = (r.items || []).find(x => x.name.includes(tid));
        if (hit) {
          window.open(`/api/report?id=${encodeURIComponent(S.runId)}&file=${encodeURIComponent(hit.name)}`, "_blank");
        } else {
          alert("未找到对应证据包文件（可能未达到价值线）");
        }
      } catch (err) { alert("报告读取失败：" + err.message); }
    }
  });
}

(async function init() {
  bind();
  try {
    const s = await api("/api/session");
    S.token = s.token || "";
  } catch (e) { /* token 获取失败时提交会被后端拒绝 */ }
  try { await loadRuns(); } catch (e) { /* 空状态由各视图兜底 */ }
  show("overview");
})();
