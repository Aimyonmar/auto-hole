# 12 · 本地只读桌面控制台

> 从“浏览器面板”升级为 **pywebview + WebView2 桌面应用**：无地址栏、无浏览器 UI、不自动启动浏览器。

## 1. 定位与安全边界

- 桌面窗口内嵌系统 WebView2，前端仍通过本机回环 HTTP 取数；
- 只绑定 `127.0.0.1`（`0.0.0.0` 直接拒绝），端口随机（也可用 `--port` 指定，占用时顺延）；
- 只有 GET；POST/PUT/DELETE/PATCH 一律 405；
- 不提供任何扫描、提交、修改目标的操作；
- 不访问外网、不引 CDN/在线字体图标；静态资源随包分发；
- 关闭窗口即停止 HTTP 服务、清理锁文件并退出进程。

## 2. 启动

### 2.1 桌面版（默认）

双击：

`dist\AutoHoleDashboard\AutoHoleDashboard.exe`

- 只出现一个应用窗口，标题「AutoHole 控制台」，默认 1280×800，可最大化；
- 后台随机端口，前端自动指向实际监听地址；不启动任何浏览器；
- 首次运行在 exe 同级创建 `workspace/`、`targets/authorized/`、`outputs/recon-demo/`、`logs/`；
- 启动日志：`dist/AutoHoleDashboard/logs/startup.log`（记录 pid、锁、绑定端口、窗口、退出）；
- 二次双击：检测到已有实例时前置已有窗口；找不到窗口时弹提示“已在运行”，不会重复起服务；
- WebView2 Runtime 缺失时降级为 tkinter 提示窗口（可手动点“用浏览器打开”，不会自动起浏览器）。

### 2.2 保留的服务模式（开发/排查）

```powershell
# 只起服务，不开窗口（默认 8080，可被占用顺延）
.venv-recon\Scripts\python.exe dashboard_server.py --server-only --port 8080

# 服务自检（启动→两次回环请求→退出，全程无窗口/无浏览器）
.venv-recon\Scripts\python.exe dashboard_server.py --selftest

# 窗口自检（开窗口 2 秒后自动关闭）
.venv-recon\Scripts\python.exe dashboard_server.py --selftest-window
```

浏览器只在 `--server-only` 模式下由使用者手动访问，不属于桌面版启动流程。

前端入口：`dashboard/static/index.html`（打包后位于 `_internal/dashboard/static/index.html`）。

### 2.3 重建

```powershell
.venv-recon\Scripts\python.exe -m pip install pyinstaller pywebview
.venv-recon\Scripts\pyinstaller.exe dashboard.spec --noconfirm --clean
```

- `dashboard.spec`：one-dir、`console=False`（不弹控制台窗口），收集 `webview / clr_loader / pythonnet` 与静态资源；
- 打包前确认 `targets/authorized/` 为空；不会把目标清单、凭据、数据库打进去。

### 2.4 实测（2026-11-02，打包版）

| 项 | 结果 |
|---|---|
| 目录体积 | 40.9 MB（pywebview/WebView2 依赖增加） |
| 启动到窗口出现 | 约 1.1 s（3 次实测 1.098–1.130 s） |
| 窗口数 / 进程数 | 1 个窗口、1 个 `AutoHoleDashboard` 进程 |
| 子进程 | 仅 `msedgewebview2.exe`（WebView2 内核）；无新 `msedge.exe` 浏览器进程 |
| 数据 | 1 次运行、3 条命中、1 条资产正常显示 |
| 二次启动 | 约 0.3 s 内检测到已有实例并退出，首个实例保持运行 |
| 关闭窗口 | 进程退出、端口关闭、`dashboard.lock` 清理 |
| 端口顺延 | 18087 被占用 → 自动使用 18088 |
| 服务自检 | HTTP 200，空数据 `runs=0` 正常 |

## 3. 页面与数据来源

| 页面 | 内容 | 数据来源 |
|---|---|---|
| 总览 | 运行次数、资产、命中、等级分布、误报率、平均耗时、最近运行 | `summary.json` + `findings.jsonl` + `feedback.jsonl`，缺产物时回落 SQLite |
| 目标清单 | 可挖/blocked、授权状态、资产数、上次运行/命中、blocked 原因 | `targets/authorized/*.yaml` + 运行产物 |
| 运行详情 | 阶段耗时占比、探测请求（实测）/扫描请求（估算）、配额、限速/熔断、警告 | `summary.json` / `metrics.json` / `audit.jsonl` |
| 资产 | 主机、端口、状态码、标题、指纹与置信度、来源 | `assets.jsonl`，缺失时回落 SQLite |
| 命中 | 等级、评分、tags、证据截断、报告下载 | `findings.jsonl`，缺失时回落 SQLite |
| 进化历史 | 候选类型/状态/正负样本结果、版本快照与回滚 | `evolution/candidates/*.validation.json` + `versions/index.json` |
| 审计流水 | 时间、事件、主机、URL、状态、耗时、当时速率 | run 时间窗内的 `audit.jsonl` |

## 4. 接口

`GET /api/overview`、`/api/targets`、`/api/runs`、`/api/run?id=`、`/api/assets?id=&page=&size=`、
`/api/findings?id=&page=&size=&severity=`、`/api/finding?id=&template=&host=&matched=`、
`/api/reports?id=`、`/api/report?id=&file=`、`/api/evolution`、`/api/audit?id=&page=&size=`、`/api/meta`。

任务相关：
`GET /api/session`（下发本地 token）、`GET /api/jobs`、`GET /api/jobs/<id>?tail=`、
`POST /api/jobs`（JSON 表单）、`POST /api/jobs/<id>/cancel`。
写接口必须带 `X-AutoHole-Token`；若带 `Origin`，只接受同端口回环来源（防 CSRF）。

分页参数服务端处理，`size` 上限 200；空数据返回空数组/空状态，不抛 500。

## 5. 面板内提交任务（新建任务）

### 5.1 表单字段与校验

| 字段 | 说明 | 拒绝规则 |
|---|---|---|
| 厂商名 | 报告/档案文件名 | 为空拒绝 |
| 补天项目链接或编号 | 授权依据 | 为空拒绝 |
| 资产范围（多行） | 一行一个；IP 自动归入 ips | 规范化后为空拒绝；含 `*` 拒绝；非法域名拒绝 |
| 含子域 / 含第三方托管 | 范围开关 | 含第三方托管直接拒绝 |
| 平台禁止项（原文） | 原文照抄 | 为空拒绝；按分句判断，含“禁止/不得 + 自动化/扫描/脚本”的分句 → 拒绝 |
| 档位 | light / standard | 其他值拒绝 |
| 授权确认勾选 | 必须勾选 | 未勾选拒绝 |

校验直接复用 `modules.recon.intake.parse_payload`（与 CLI `intake` 同一套规则），
通过后写入 `targets/authorized/<厂商slug>.yaml`（`registration_status=approved`，
`source.file=<dashboard-form>`），与命令行路径完全一致。

**只读越权检测（可选）**：额外字段为身份 A/B 的名称、角色（high/low/user）、Cookie、
自定义 Header、会话校验 URL、采集入口、垂直路径、最大请求数、相似度阈值。
启用时必须至少 2 个身份且每个身份有 cookie 或 header；单账号直接 400 拒绝。
cookie/header 只写入 `workspace/authz/vault.enc`（Fernet），
`targets/authz/<slug>.yaml` 仅保留身份名称/角色/入口/credential_id，不含 secret。

### 5.2 队列与执行

- **SQLite `workspace/jobs.db`**（选它而不是 JSON：状态更新需要原子性、HTTP 线程与工作线程并发读写，JSON 易损坏）。
- 同一时间只执行一个任务；其余排队并显示 `queue_position`。
- 状态：`queued / running / done / failed / canceled`；记录开始/结束时间、阶段、退出码、错误。
- 执行方式：子进程调用同一 exe 的 `--run-cli batch`（开发态为 `dashboard_server.py --run-cli`），
  继承 `batch` 的授权校验、限速、配额、熔断；不绕过任何既有约束。
- 越权任务：目标档案含 `authz_accounts` 时，`all` 阶段先做身份会话预检（失效则任务失败），
  recon 结束后自动执行只读越权检测；结果写 `<target>/authz.jsonl|authz-summary.json|authz-report.md`。
- 体检任务：`kind=triage` 时执行 `main.py triage -t <ledger>`，不经过 batch/nuclei；
  请求上限默认 60（可 1~200），结果写 `<target>/triage.md|triage.json`。
- 取消：排队任务直接置 canceled；运行中任务用 `taskkill /T /F /PID` 终止整棵进程树。
- 超时：默认 1800s，超时终止进程树并标记 failed。
- 异常：非零退出码、启动失败、批量中目标失败（日志出现“失败（已隔离）”）都会标记 failed，队列继续。
- 日志：`logs/jobs/<job_id>.log`，页面轮询 `/api/jobs/<id>` 显示尾部；结束后自动刷新总览/命中数据。
- 审计：`logs/dashboard-audit.jsonl` 记录 `job_submitted / job_started / job_done|failed|canceled / timeout`。

### 5.3 安全

- 服务仍只绑回环地址；写接口要求本地 token（页面启动时经 `GET /api/session` 获取）；
- `Origin` 存在时必须与当前服务端口同源（127.0.0.1/localhost），跨源一律 403；
- 没有“跳过授权校验”的开关；表单与 CLI 共用 `parse_payload`/`batch`/`recon` 同一套检查；
- 越权凭据：Fernet 加密库 + 本地密钥（Unix 0600 / Windows icacls 限当前用户）；
  页面、日志、审计、summary、report 均脱敏，不提供“查看凭据”入口；
- 打包产物不含凭据：打包态的 `config.yaml` 由程序生成，`hunter/llm` 的 key 为空。

### 5.4 打包版端到端实测（2026-11-02）

- 环境：本地靶场 `127.0.0.1:18090`；打包 `AutoHoleDashboard.exe --server-only`；档位 standard；
  演练配置使用 3 条演示模板 + 2 条演示指纹。
- 面板 UI 实际提交：任务 `queued → running → done`，耗时 22–28s；产出 3 条命中
  （1 high / 2 medium）、2 份证据包与 `report.md`；总览/命中页自动刷新。
- 串行：第二个任务 `queue_position=2`，未并发执行；排队取消后状态 `canceled`。
- 取消：运行中任务取消后状态 `canceled`，子进程 PID 在数秒内消失，仅保留面板主进程。
- 拒绝矩阵（均 400 且逐项提示）：缺授权依据、范围为空、`*.example.com`、automation=no、
  tier=deep、未勾选授权确认。
- CSRF：无 token / 跨源 Origin 均为 403。
- 单元测试补充：非零退出码 → failed、失败任务不阻塞后续队列、超时（2s）→ failed 且进程被终止。
- 构建产物 245.3 MB（加入越权模块后 255.6 MB），含 14465 个 nuclei 模板文件；`--selftest`、`--selftest-window` 均通过。

### 5.5 目标体检页

「目标体检」页可提交 triage 任务（厂商/授权依据/范围/禁止项/请求上限/授权确认），
结果区按 `docs/recon/14-triage.md` 的七块展示，支持导出 `triage.md` / `triage.json`。
体检任务在运行列表中标记为「体检」，不产生 findings/证据包/扫描请求。

本地三档实测（请求 13/60）：老旧 CMS → 建议深挖（16 分）；云 WAF 现代站 → 不建议（-10）；
纯静态站 → 不建议（-4）；审计仅 `triage-probe` / `triage-exposure`，零扫描。

打包面板实测：任务「打包体检演练」完成，请求 13/60，结论「建议深挖」16 分，
技术栈包含 Nginx 1.18.0 / WordPress 5.8.2，6 类暴露面；审计 1 条 probe + 12 条 exposure，
无 `scan`/`finding` 事件；`triage.md` / `triage.json` 可导出。

越权检测打包版实测（同一轮、面板 UI 实际填写并提交）：

- 任务「打包越权演练」：recon 3 条命中（1 high / 2 medium）+ 越权疑似 2 条
  （1 水平 `/orders/1001`，1 垂直 `/admin/audit`）。
- 越权计数：水平测试/垂直测试 7，公共页抑制 3，正常/负样本 2，请求 25/60，未触发预算耗尽。
- A/B 证据并排展示；响应已脱敏（`admin_token`、`email`、`debug_cookie` 均为 `[REDACTED]`）。
- 凭据仅存在于 `workspace/authz/vault.enc`；`vault.key` ACL 仅当前用户；
  ledger/metadata/audit/report/summary 中无 `sid=A`/`sid=B` 明文。
- 打包产物 255.6 MB（含 cryptography 与 14465 模板）；`--selftest` 通过。

## 6. 已知限制

- **扫描请求数是估算值**（`URL × 15`，与 legacy 预算口径一致），UI 明确标注“估算”；
- 限速/熔断计数来自审计（`throttled` / `budget_stop` / `error`），未记录的事件显示 0；
- 审计按“运行结束时间 − 耗时 − 30s”切时间窗，边界处可能多/少几条；
- 无产物时回落 SQLite，但 SQLite 没有 `runs` 表，运行列表仍只能来自产物；
- 需要系统安装 **Microsoft Edge WebView2 Runtime**（Win10/11 通常自带）；缺失时进入 tkinter 降级窗口；
- 控制台已隐藏，启动异常请看 `logs/startup.log`；杀软可能对 PyInstaller 产物误报，可加白名单；
- 全量 nuclei 模板（1.4 万条）扫描一个目标可能耗时较长，任务默认超时 1800s；
  演示/小规模可替换为精简模板目录；
- 任务子进程与桌面进程共用 exe，关闭面板会终止正在跑的任务（状态 canceled）；
- 任务队列为单机串行，不支持多目标并发执行（与授权/配额口径一致）；
- 面板档位只开放 light/standard；`batch` 会在本批次内打开当前档位的扫描（不改全局默认），
  因此面板 standard 任务默认会跑 nuclei；单跑 `recon` 且未显式 `--stage scan` 时仍遵循 profile 默认。
- 体检模式不产生扫描请求、findings 或证据包；体检结论是研判推断，不是漏洞结论。
