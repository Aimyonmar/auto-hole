# 03 · 设计与实现说明

> 位置：新增代码全部在 `modules/recon/`，通过 `main.py` 的 `recon` 子命令与 `adapters` 适配层接入；
> `core/` 既有接口、`config.yaml` 格式、SQLite 表结构保持兼容（仅两处必要修改，见 §8）。

---

## 1. 总体结构

```
targets/*.yaml  ──►  [宪法第1条：authorization + 范围校验]
                         │
                         ▼
        ┌──────────── modules/recon/runner.py ────────────┐
        │  collect        probe(+fingerprint)      scan   │
        │   │                  │                    │     │
        │   ▼                  ▼                    ▼     │
        │ sources 插件      Prober(线程池)      core.scanner
        │ (seed/subfinder/   + 令牌桶/熔断       (profile 覆盖参数)
        │  hunter)           + 审计                        │
        └──────────────┬──────────────────────┬────────────┘
                       ▼                      ▼
        assets.jsonl / findings.jsonl    legacy SQLite(镜像)
        summary.json / report.md         audit.jsonl
```

设计原则：
1. **被动优先**：`seed → subfinder（被动枚举）→ hunter（查库）`，最后才主动 HTTP 探测。
2. **单次请求多维提取**：一次 GET 同时产出状态码、Server、标题、正文指纹（不做多趟请求）。
3. **所有外部请求先过三道闸**：范围校验 → 配额登记 → 令牌桶取令牌。任一步失败都不发请求。
4. **有界**：并发/速率/主机数/请求数/正文大小全部有上限，且代码级不可越过。

---

## 2. 文件清单

| 文件 | 职责 |
|---|---|
| `modules/recon/__init__.py` | 包说明与版本 |
| `modules/recon/schema.py` | `Asset` / `Finding` 统一 schema、归一化、去重合并、nuclei 行判定 |
| `modules/recon/ratelimit.py` | 令牌桶、熔断器、自适应限速器、持久化配额账本、参数越界校验 |
| `modules/recon/audit.py` | 逐请求 JSONL 审计与统计汇总 |
| `modules/recon/state.py` | 分阶段 checkpoint（断点续跑） |
| `modules/recon/config.py` | `config/recon.yaml` 加载、分级 profile、路径与边界校验 |
| `modules/recon/fingerprint.py` | 指纹规则解析、索引、匹配引擎（短路 + 前置过滤 + 负向规则） |
| `modules/recon/fingerprints/builtin.yaml` | 内置指纹库（39 条规则 / 39 个产品） |
| `modules/recon/probe.py` | HTTP 探测（线程池 + 限速 + 审计 + 指纹内联） |
| `modules/recon/sources/base.py` | 数据源基类与上下文 |
| `modules/recon/sources/__init__.py` | 注册表、插件自动发现、批量构建 |
| `modules/recon/sources/seed.py` | 目标声明资产（零网络） |
| `modules/recon/sources/subfinder.py` | 复用 `core.subdomain`，补来源标注与 dnsx 存活过滤 |
| `modules/recon/sources/hunter.py` | 复用 `core.hunter`（免费账号游客模式不变） |
| `modules/recon/sources/import_list.py` | 外部资产清单导入（FOFA/Quake/鹰图导出 → 本地 txt/CSV） |
| `modules/recon/value.py` | 价值评分（危害 × 类型 × 规模 × 证据 × 重复风险） |
| `modules/recon/targeting.py` | 按产品分组 + 定向模板目录 + 配额预检 |
| `modules/recon/inventory.py` | 跨目标产品盘点（通用1.0 ≥100 达标统计） |
| `modules/recon/evidence.py` | 提交级证据包（补天格式 + 检查清单） |
| `modules/recon/adapters.py` | 写 legacy DB、调用 legacy scanner、汇总 JSON/Markdown |
| `modules/recon/runner.py` | 阶段编排、断点、上限保护、汇总 |
| `modules/recon/cli.py` | `recon` 子命令实现 |
| `config/recon.yaml` | 独立配置（不覆盖 `config.yaml`） |
| `requirements-recon.txt` | 独立环境依赖 |
| `tests/recon/` | 47 个单测 + 1 个本地 mock 站点脚本 |
| `docs/recon/01~04` | 调研、差距、设计、验证 |

---

## 3. 数据模型（标准 schema v1）

`Asset` 关键字段（JSONL 每行一条，`"schema": "recon.asset/v1"`）：

```json
{
  "schema": "recon.asset/v1",
  "host": "a.example.com", "port": 8443, "scheme": "https", "url": "https://a.example.com:8443",
  "status": 200, "title": "致远OA V8.1 登录", "server": "nginx/1.20",
  "tech": ["PHP"], "products": [{"product": "致远OA", "rule_id": "seeyon-oa", "confidence": 0.95, "matched": ["title~致远"]}],
  "sources": ["seed", "subfinder", "hunter"],
  "tags": [], "first_seen": "...", "last_seen": "...",
  "evidence": {"url": "...", "status": 200, "elapsed_ms": 42.1, "body_sha256": "…", "body_len": 3120},
  "meta": {"probe": "http", "attempts": 1}
}
```

要点：
- **身份** = `host|port`；`port=0` 表示“端口未知，按策略探测常用端口”（序列化再读回不会被 URL 默认端口覆盖）。
- **多源合并**：`sources` 取并集；`tech` 取并集；同名产品取最高置信度；空字段不覆盖已有值。
- **证据**只存摘要（URL/状态/耗时/正文长度与哈希），不存正文，避免敏感内容落盘。

`Finding` 从 nuclei 行归一化而来，`key = template_id|host|matched_at_hash`；
判定函数 `is_nuclei_finding()` 只排除 `stats/error/trace/progress`，要求存在 `template-id`（修复 G1）。

---

## 4. 指纹引擎

### 4.1 规则格式（YAML）

```yaml
- id: seeyon-oa
  product: 致远OA
  confidence: 0.95
  logic: any            # any | all
  min_matched: 1        # any 下证据不足则降权
  tags: [oa, seeyon]
  template_dirs: ["http/cves", "http/exposures"]
  match:
    - {type: title, contains: "致远"}
    - {type: body, contains: "seeyon"}
    - {type: header, name: "Server", contains: "seeyon"}
  negative:
    - {type: body, contains: "某某误报特征"}
```

条件类型：`header`（需 `name`）、`title`、`body`、`url`、`status`（`200` / `200-299` / `2xx` / `200,301`）、`favicon`（sha256）。
每条条件支持 `contains` / `regex` / `value`（精确）/ `sha256`。

### 4.2 匹配算法（三层优化）

1. **负向规则优先**：任一 `negative` 条件成立即否决（对应 Wappalyzer `excludes`）。
2. **成本分级短路**：
   `status/favicon(0) → url(1) → title(2) → header(3) → body contains(4) → regex(5/6)`；
   `all` 逻辑遇 false 立即退出（贵条件不再执行）。
3. **字面量前置过滤**：把所有正文 `contains` 规则的字面量合成**一条**正则（`|` 交替、长串优先、忽略大小写）。
   若整条正则不命中，则“正文里没有任何指纹字面量”**可证**，于是跳过全部正文子串判定——
   一次扫描替代 N 次全文搜索。命中时再回落到逐字面量 `in` 判断（保证语义不因重叠字面量出错）。

### 4.3 误报抑制

| 手段 | 说明 |
|---|---|
| `negative` | 直接否决冲突规则（如 `Server: openresty` 时否决 Nginx） |
| `min_matched` + `weak_match_penalty` | `any` 逻辑下命中条件数不足时置信度 ×0.7 |
| `min_confidence` | 最终低于阈值（默认 0.6）直接丢弃 |
| `matched` 回填 | 每条产品都带“命中了哪些条件”，便于人工复核 |
| 无臆造数据 | 内置库不含未验证的 favicon hash；规则只用稳定页面特征 |

---

## 5. 限速与熔断

### 5.1 三个独立上限

| 参数 | 含义 | 代码级上限 |
|---|---|---|
| `concurrency` | 同时在飞请求数（线程池大小） | 64（`ABSOLUTE_MAX_CONCURRENCY`） |
| `requests_per_second` | 令牌桶速率 | 200（`ABSOLUTE_MAX_RPS`） |
| `daily_request_limit` | 单目标单日请求数（持久化） | 应用层 100000 |

`validate_limits()` 对 `concurrency<=0`、`>64`、`rps<=0`、`>200` 直接抛 `RateConfigError`，
**不存在“传 0 = 不限制”的语义**。

### 5.2 自适应状态机

```
        成功(每 20 次)
   ┌───────────────────► 速率 +10%（上限=基线）
   │
[运行] ── 失败/5xx ──► 速率 -50%（下限=min_rps）
   │
   └── 连续失败 8 次 ──► [熔断 open] ──冷却 60s──► [half-open] ──成功──► [closed]
```

- 429/503 走 `record_throttle()`：立即降速，不计入熔断失败数。
- 熔断打开时 `acquire()` 抛 `RuntimeError`，探测阶段捕获后整体停止（不再打击目标）。
- 退避 `backoff_sleep(attempt)`：`min(backoff_max, base * 2^attempt)` + 轻抖动，有上限。

### 5.3 配额账本

`recon_budget(target, day, source, count)` 表，跨进程累计；
与 legacy `request_counter` 表并存（互不干扰，recon 与 nuclei 各自记账）。

每次请求顺序：**范围校验 → `ledger.charge(1)` → `limiter.acquire()` → 发请求**。
这样“被配额拒绝”的请求不会消耗令牌，也不会污染速率统计。

---

## 6. 断点续跑

状态文件：`workspace/recon/<target>/state.json`

```json
{
  "version": 1, "target": "…", "profile": "light",
  "stages": {
    "collect": {"status": "done", "processed": [], "counters": {"done:seed": true, "count:seed": 1}},
    "probe":   {"status": "done", "processed": ["127.0.0.1|0", "127.0.0.1|18081", "127.0.0.1|18082"]}
  }
}
```

- 数据源完成记 `done:<source>`；主机探测完成记“原始 key + 实际 host|port”（避免二次探测）。
- 原子写入（`tmp → os.replace`），崩溃不会留下半截 JSON。
- 目标名不匹配时自动重置，防止串状态。
- `--fresh` 显式清空。

---

## 7. 分级策略（profiles）

| 维度 | light | standard（默认） | deep |
|---|---|---|---|
| 并发 | 3 | 8 | 16 |
| 速率 (rps) | 5 | 20 | 50 |
| 端口 | 80,443 | 9 个常见 Web 端口 | 11 个（含 8001/8081） |
| 主机上限 | 300 | 2000 | 8000 |
| favicon | 关 | 关 | 开（额外 1 请求/主机） |
| 重试 | 1 | 1 | 2 |
| 连带扫描 | 否 | 否 | 是 |

首次对新目标建议 `light`；`standard` 对齐项目既有约定（首跑并发 8）；
扫描参数（severity/tags/url 上限）由 profile 覆盖 `core.scanner` 的 `ScanConfig`，
`tags_exclude` 永远会并上 `dos/fuzz`（强制项不可被 profile 覆盖掉）。

---

## 8. 与既有系统的接入（兼容性）

改动集中在“挂载点 + 两处必要修正”：

1. **`main.py`（挂载点）**：新增 `recon` 子命令（`--profile/--stage/--fresh/--recon-config`），
   旧命令参数与分发路径完全不变。
2. **`core/config.py`（口径调整）**：把“并发 ≤20 / 日请求 ≤5000”从**硬编码红线**改成
   “温和档 + 按授权范围可配置”：
   - 默认 8 / 5000；
   - 超过 20 / 5000 必须填 `scan.authorization_ref`（授权依据），否则拒绝启动；
   - 代码级绝对上限 64 / 100000 不可突破（保证有界）；
   - 新增 `ScanConfig.authorization_ref` 字段（有默认值，旧 `config.yaml` 无需改动即可加载）。
3. **`core/scanner.py`（缺陷修复）**：修正命中行 `type` 过滤逻辑（G1）。

接口层面的兼容做法：
- 新 CLI 是**新增子命令** `recon`，旧命令 `collect/scan/judge/report/run` 参数与行为不变；
- recon 的产物（`assets.jsonl`）通过 `upsert_assets()` 镜像进 legacy `assets` 表，
  `tech` 字段仍写“字符串列表 JSON”，`cmd_scan`/`cmd_judge`/`cmd_report` 无需改动即可消费；
- recon 的分级扫描直接调用 `core.scanner.scan_urls()`（只是把 `ScanConfig` 换成 profile 覆盖后的副本），
  不复制 POC 执行逻辑；
- 新配置独立为 `config/recon.yaml`，缺失时使用内置默认（不影响旧部署）。

---

## 9. 合规实现点（对应任务硬约束）

| 约束 | 落地 |
|---|---|
| 只对显式声明目标请求 | `load_target()` 强制 `authorization`；`Prober.in_scope` 每次请求前校验 `check_host_in_scope`；越界写 `scope_reject` 审计并丢弃 |
| 禁止 DoS 类行为 | 并发 ≤64、rps ≤200、指数退避、连续失败熔断、主机数上限、正文读取上限、无“无上限模式” |
| 只读取证 | 探测仅 `GET`；不写文件、不带 payload、不上传；扫描复用 nuclei 的 `strict_readonly` 过滤与 `dos/fuzz` 排除 |
| 请求留痕 | 每请求一条 JSONL：目标、时间、来源、URL、状态、耗时、当时速率、结果类型；指纹/漏洞命中另记 |
| 已禁用目标不恢复 | 帆软目标 `domains/ips/hunter_query` 全空 → `load_target` 直接拒绝；recon 也要求显式 `-t`，不会自动遍历 `targets/` |
| Hunter 游客模式 | `sources/hunter.py` 复用 `core.hunter`，降级逻辑原样保留 |
| 默认参数合规 | 默认 `standard` = 并发 8 / 20 rps / 5000 日请求；首跑建议 `light` |
| 开发期不碰真实目标 | 单测与 CLI 验证全部使用 `127.0.0.1` mock 服务 |

---

## 10. 环境隔离

- 独立虚拟环境：`.venv-recon/`（已加入 `.gitignore`）。
- 独立依赖：`requirements-recon.txt`（pyyaml / requests / rich / pytest）。
- 运行时可选用任一环境（依赖与主项目一致），独立环境用于隔离开发与测试。
- 所有运行数据仍在项目内：`workspace/recon/`。

---

## 11. 变现导向的价值链路

采集能力只解决“有没有资产”，能不能赚钱取决于“先提交哪个”。为此新增四段：

### 11.1 价值评分（`value.py`）

```
分值 = 危害基础分(critical 55/high 40/medium 25/low 10/info 3)
     + 漏洞类型加分(取最高一项：RCE +20 / 上传 +18 / 未授权 +16 / SQLi +15 / 反序列化 +15 …)
     + 通用产品加分(+10，产品可复用)
     + 资产规模加分(10–99 +4；100–999 +16；≥1000 封顶 20)
     - 证据缺失(无 curl -8；无回显 -5)
     - 重复风险(已提交 -12；同模板多命中 -6；老 CVE -6)
```

- 等级：S≥75 / A≥60 / B≥45 / C≥40 / D<40
- 评估结果写回 `findings.jsonl` 的 `value` 字段（分数/等级/建议/依据/粗估区间）
- 评分依据逐条可读，便于人工判断是否推翻
- 仅用于排序与取舍，**不等于平台定价**

### 11.2 按产品分组定向扫描（`targeting.py`）

- 资产按“置信度最高的产品”归组；每组只传该产品的模板目录（`-t http/cves` 等）
- 未识别产品默认跳过（`scan_unidentified=false`），避免把配额烧在无关模板上
- `scan_grouped=true` 时，“已识别但无模板目录”的组件（纯 Nginx/Apache 等）也跳过，
  不拿全量模板去打通用组件
- 组内 URL 上限、组数上限、日配额预检（不足则截断/跳过组），不会一次性打爆配额
- 扫描仍复用 `core.scanner.scan_urls`，只多传 `extra_templates` 与批次 `label`

### 11.3 跨目标产品盘点（`inventory.py`）

- 只读 `workspace/recon/*/assets.jsonl`，不发请求
- `instances` = 存活资产的去重 host 数（多端口只算 1 台）
- 输出 `inventory.json` + `inventory.md`：已达门槛 / 接近门槛 / 全部产品
- 用于通用1.0 的“同产品 ≥100 实例”影响力证明底稿

### 11.4 证据包（`evidence.py`）

- 只对价值分 ≥ `min_score_for_evidence`（默认 40）的命中生成
- 内容：补天标题规范、价值评级与依据、复现命令、请求/响应摘录（截断 400 字 + 脱敏 Bearer）、
  影响说明、实例数证明、修复建议、人工检查清单、只读声明
- 输出到 `workspace/recon/<target>/evidence/`，不提交任何平台

### 11.5 外部清单补量（`sources/import_list.py`）

- 文件：`workspace/import/<目标名>.txt`
- 行格式：`host` / `host:port` / `URL` / `IP,端口,URL,标题`（自动识别），`#` 注释忽略
- 导入的 host 仍需过授权范围校验；仅在“产品型目标（有 hunter_query）”下视为已声明的范围
- 用途：把 FOFA/Quake/鹰图导出直接接入，快速把产品实例补到 100 台

> 完整作业流程与“先打什么”的判断见 [05-value-playbook.md](05-value-playbook.md)。

## 12. 使用方式

```powershell
# 首次对新目标：轻量档（并发 3 / 5 rps）
.venv-recon\Scripts\python.exe main.py recon -t targets\ikuai.yaml --profile light

# 常规采集（默认 standard：collect + probe，含指纹）
.venv-recon\Scripts\python.exe main.py recon -t targets\ikuai.yaml

# 只跑某一阶段 / 看进度
.venv-recon\Scripts\python.exe main.py recon -t targets\ikuai.yaml --stage probe
.venv-recon\Scripts\python.exe main.py recon -t targets\ikuai.yaml --stage status

# 深度档（含分级扫描，仅限已确认授权范围）
.venv-recon\Scripts\python.exe main.py recon -t targets\ikuai.yaml --profile deep

# 丢弃断点重来
.venv-recon\Scripts\python.exe main.py recon -t targets\ikuai.yaml --fresh
```

