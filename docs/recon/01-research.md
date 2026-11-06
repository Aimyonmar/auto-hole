# 01 · 业界工具调研与可迁移设计点

> 目标：从成熟工具里提炼**可迁移的设计点**（而不是抄功能），用于指导 auto-hole 的采集/扫描能力升级。
>
> **资料说明**：本文基于各项目公开仓库 README、官方文档与既有实现认知整理。本次整理环境未能逐条联网复核原文，
> 涉及具体字段名/默认值的条目已标注“（不确定）”，实际以对应项目最新版本文档为准。
> 版本差异普遍存在（尤其 ProjectDiscovery 系列 CLI 参数随版本调整），本文只保证“设计意图”层面的准确性。

---

## A. 子域名 / 资产收集：subfinder、amass、OneForAll、assetfinder

### A1. 数据源插件化

| 工具 | 做法 | 可迁移点 |
|---|---|---|
| subfinder | 每个数据源一个实现，统一接口（约等于 `Name() / IsDefault() / Run(ctx, domain, callback)`），在 runner 里聚合成源列表；`-all` 使用全部源，也可指定单个源 | 源 = 独立类 + 注册表；启用/禁用由配置决定；单一源失败不影响其它源 |
| amass | `sources/` 包内每个源实现 DataSource 接口（`Name / AddDomain / Run / Output`），按 passive/active 分类 | 源声明“被动/主动”属性，调度时可按档位只跑被动源 |
| OneForAll | Python 模块化，`modules/` 下每个源一个模块，`--all` 或 `-s` 指定 | 插件发现（按目录扫描模块）比硬编码列表更易扩展 |
| assetfinder | 只做少量被动源，输出极简 | 先跑“零成本被动源”，再决定是否投入主动探测 |

**关键设计意图**：插件的价值不是“源多”，而是**失败隔离 + 可开关 + 可排序**。一个源的配额耗尽/接口变更不应拖垮整条链路。

### A2. 结果归一化与去重

- subfinder/amass 都会把不同源返回的原始结构收敛成“子域名字符串 + 来源”的最小集合，去重在输出前完成（不是交给下游）。
- amass 用图数据库持久化资产与关系（域名→IP→端口），天然带去重与增量（(不确定) 具体存储后端支持 SQLite/Postgres）。
- OneForAll 结果落 CSV，按字段列归一化，便于二次处理。
- assetfinder 不做存活校验，把“是否存活”留给下游 httpx —— **职责单一、可组合**。

**可迁移点**：
1. 统一 schema 放在**写入任何存储之前**（先归一化再落库）。
2. 去重 key 要选“稳定身份”：域名用 `host`，Web 资产用 `host:port`。
3. 同一资产被多个源命中时**合并保留来源列表**，而不是覆盖成最后一个源。

### A3. 存活校验与“被动优先”

- subfinder 本身不做 DNS 解析，靠 `dnsx`/`httpx` 下游过滤；amass 有主动 DNS 解析与被动模式区分。
- 业界共识：**先被动（查第三方数据）→ 再 DNS 解析 → 最后 HTTP 探测**，逐层收敛，避免对目标造成无谓请求。

**可迁移点**：分阶段收敛（collect → resolve → probe），每阶段可单独续跑；被动源永远先执行。

### A4. 配置化

- subfinder 用 `provider-config.yaml` 存各家 API key，源开关与 key 解耦。
- amass 用 `config.ini` 的 `[data_sources]` 段控制每个源启用与凭据。

**可迁移点**：**凭据集中在一个文件、源开关在另一个维度（配置项/CLI）**，便于“有 key 才启用”。

---

## B. 存活探测与指纹：httpx、EHole、ObserverWard、finger

### B1. httpx（ProjectDiscovery）

- 输入是主机/URL 列表，输出 `-json`（每行一个 JSON），字段含 `input/host/port/scheme/status_code/title/tech/webserver/cdn/hash` 等。
- 技术栈识别内置 wappalyzergo（Wappalyzer 规则集的 Go 实现），`-td` 开关（(不确定) 新版本默认开启）。
- `-favicon` 输出 favicon 的 mmh3 哈希；`-hash` 输出响应体哈希；两者都用于“同源资产聚类”。
- 限速：`-rl`（每秒请求数）+ `-c`（并发）+ `-retries` + `-timeout`；`-no-fallback` 控制 https→http 回退。
- **单次请求多字段提取**：一次抓取同时产出状态码/标题/头/技术栈，不做多次往返。

**可迁移点**：
1. 一次请求完成“存活 + 标题 + 头 + 正文 + 指纹”，减少请求总量（对合规限速场景收益最大）。
2. 统一 `jsonl` 输出，字段稳定，便于落库与 diff。
3. `-no-fallback` 思路：https 失败才回退 http，且只对 TLS 端口回退，避免请求翻倍。

### B2. EHole（棱洞）

- 指纹库为 JSON 规则集，单条规则大致包含 `cms`（产品名）、`method`（keyword/regular）、`location`（body/header/url 等）、`keyword`（匹配内容）。（不确定：字段名随版本可能为 `name/type/...`）
- 支持 favicon hash（mmh3）匹配，配合“关键词 + 路径”组合降低误报。
- 定位是“批量指纹识别”，强调规则可手工维护。

**可迁移点**：**规则与引擎分离**，规则用 YAML/JSON 维护，引擎只负责求值；规则必须支持“条件组合”，否则单关键词误报率不可接受。

### B3. ObserverWard

- 指纹规则直接采用 **Wappalyzer 规则体系**（社区维护、覆盖面广），工具本身负责批量请求与匹配。
- Wappalyzer 规则的核心结构：`implies`（命中后隐含其它技术）、`excludes`（命中则排除其它技术）、按 `headers/body/meta/script/url` 分组的正则。
- 支持从测绘平台（fofa/hunter 等）直接导入目标批量识别。

**可迁移点**：
1. **排除规则（excludes / negative）是误报控制的核心手段**，比提高阈值更有效（例如 `Server: openresty` 时不应同时报 `Nginx`）。
2. `implies` 可用于“命中一个特征推断出生态”（如 `X-Powered-By: PHP` → 推断 PHP），但推断项必须标低置信度，避免污染资产清单。

### B4. finger（第三方指纹工具）

- 公开资料较少（(不确定) 具体实现细节），通用做法是“规则文件 + 批量请求 + 关键词/正则匹配”，部分版本支持 favicon 与 favicon hash。
- 常见优化：按 `path` 或 `header` 先做便宜的预筛选，再对候选执行正文正则。

**可迁移点**：**按成本分级求值**（便宜条件先判、贵条件后判，能短路就短路），这是纯软件层面最有效的提速方式。

### B5. 性能与误报的共同结论

- 逐条规则全量遍历正文正则在规则数上百时会明显变慢；成熟工具的共同做法是：
  1. 条件按类型分组（header/title/body/favicon/path）；
  2. 便宜的字符串/头匹配优先；
  3. 正文匹配尽量用“字面量预筛 + 少量正则”，而不是每条规则一个正则跑全文。
- 误报控制：多条件 AND、排除规则、置信度阈值、命中依据可回溯（报告里写清“命中了哪条规则”）。

---

## C. 端口与服务：naabu、masscan、nmap

| 工具 | 速率模型 | 超时/重试 | 备注 |
|---|---|---|---|
| naabu | `-rate`（每秒包数）+ `-c`（内部 worker 并发），两者独立 | `-retries`、`-timeout`（毫秒级），`-verify` 用 connect 再确认一次开放 | SYN/CONNECT 两种模式；可把结果交给 nmap 做服务识别 |
| masscan | `--rate`（默认约 100 pps），自有异步 TCP/IP 栈 | `--retries`、`--wait` | 分片通常由调度层完成（ZMap 有 `--shards`，masscan 本身以速率控制为主）(不确定: masscan 是否有原生分片参数) |
| nmap | `-T0~5` 模板 + `--min-rate/--max-rate` | `--min-rtt-timeout/--max-rtt-timeout`、`--max-retries`，按 RTT 自适应重传 | 服务识别（`-sV`）与脚本（`-sC`）阶段独立限速 |

**可迁移点**：
1. **速率与并发是两个独立旋钮**（每秒请求数 ≠ 同时在飞请求数），两者都要有界。
2. 失败要触发**退避**（指数 + 上限），而不是固定 sleep。
3. 对端明显限流（429/503）时应**主动降速**，并在成功若干次后缓慢回升（自适应）。
4. 端口扫描本质是“高噪声”能力，本项目**不做独立端口扫描引擎**（见 02 差距清单），只用 HTTP 端口列表覆盖常见 Web 端口。

---

## D. URL / 路径与参数：katana、gau、waybackurls、ffuf

| 工具 | 核心机制 | 可迁移点 |
|---|---|---|
| katana | 深度优先/广度优先爬取，`-d` 深度（默认约 3）、`-jc` 解析 JS 提取端点、`-fs` 正则限定 scope、`-rl` 限速、`-jsonl` 输出 | 爬取要**同时限深度与限 scope**，否则会爬出授权范围 |
| gau | 聚合 Wayback / Common Crawl / OTX / URLScan 等多源历史 URL，去重后输出 | 被动 URL 源优先；多源结果先去重再交给下游 |
| waybackurls | 只查 Wayback CDX，可按子域展开 | 单源、低成本，适合作为“补充”而非主力 |
| ffuf | 字典 + FUZZ 占位；`-mc/-fc` 状态码、`-ms/-fs` 大小、`-mw/-fw` 词数过滤；`-ac` 自动校准基线以压制“全 200”误报 | **自动校准**：先请求若干随机路径得到基线响应特征，再据此过滤，避免误报刷屏 |

**可迁移点**：
1. 爬取/爆破必须限制深度、范围、总请求数（三项都要有上限）。
2. 去重要在“URL 归一化之后”（去参数顺序、去 fragment、统一大小写）再做。
3. 敏感路径字典要分级（通用/产品专属），且默认只跑低噪声档。

**本项目取舍**：URL 发现（爬虫/历史 URL/目录爆破）属高噪声主动行为，**本次未实现**，只在设计上预留接口（见 03/04）。

---

## E. 漏洞验证：nuclei

### E1. 模板结构

- 单个 YAML 模板包含 `id`、`info`（`name/severity/tags/classification` 等）、请求块（`http`/`requests`，可多请求）、`matchers`、`extractors`。
- `matchers` 支持 `type: status / word / regex / size / binary / dsl`，`part: body/header/all`，`condition: and/or`。
- 多条件 AND（状态码 + 关键词）是**抑制误报的标准做法**；单关键词匹配极易误报。

### E2. 分级调度

- `-severity`、`-tags`/`-etags` 做模板筛选；`workflows` 允许模板之间编排（先指纹识别再定向打 CVE）。
- `-rl`（每秒请求）、`-c`（并发模板数）、`-bs`（bulk size，单模板并发目标数）、`-headless` 单独并发，是**四层独立限速**。
- `-mhe`（max host errors）可跳过持续失败的 host，避免在死目标上浪费配额。

### E3. 结果标准化

- `-jsonl` 每行一条命中，关键字段稳定：`template-id`、`info.name`、`info.severity`、`host`、`matched-at`、`curl-command`、`extracted-results`。
- **注意**：命中行的 `type` 通常为 `http`/`dns`/`ssl`/`tcp` 等，**不能按 `type` 白名单过滤**（本项目旧实现正因此丢命中，见 02）。

### E4. 恢复与断点

- `-resume` 基于本地 resume 文件续跑（(不确定) 具体文件名/格式随版本变化），核心是“记录已完成的模板×目标组合”。

**可迁移点**：
1. 模板化 POC + 严重度/标签分级过滤。
2. 至少两层限速（速率 + 并发），并按 host 做失败熔断。
3. 结果字段固定 JSONL，落库前归一化。
4. “命中行过滤”要按“是否存在 template-id + 排除 stats/error”判断，而不是按 type 白名单。

---

## F. 工程共性（跨工具）

| 设计点 | 典型实现 | 本项目落地 |
|---|---|---|
| 令牌桶限速 | naabu/nuclei 的 rate + 并发双旋钮 | `AdaptiveLimiter`（令牌桶 + 自适应降速 + 熔断） |
| 断点续跑 | nuclei `-resume`、amass 图库状态 | `RunState`（分阶段 processed 集合 + 原子写入） |
| 并发模型 | 固定 worker 池，禁止无界 goroutine/线程 | `ThreadPoolExecutor(max_workers=并发上限)` |
| 统一结果 schema | httpx/nuclei 的 jsonl 字段稳定 | `Asset`/`Finding` 数据类 + `recon.asset/v1` |
| 被动优先 | subfinder/amass 先查第三方库 | 源按 `passive → declared` 顺序执行；主动探测单独阶段 |
| 失败隔离 | 单源失败不影响全局 | 源异常只记录 warning，继续下一个源 |
| 审计留痕 | （业界多为日志文件） | 逐请求 JSONL 审计（本次按合规要求强化） |
| 报告输出 | 工具多为原始列表，交给下游 | 汇总 JSON + Markdown 资产清单（产品维度） |

---

## G. 可迁移设计点汇总（本项目采用了哪些）

| # | 设计点 | 来源 | 是否采用 | 落地位置 |
|---|---|---|---|---|
| 1 | 数据源插件化 + 注册表 + 失败隔离 | subfinder/amass/OneForAll | ✅ | `modules/recon/sources/` |
| 2 | 统一 Asset/Finding schema + 来源合并 | subfinder/httpx/nuclei | ✅ | `modules/recon/schema.py` |
| 3 | 去重 key = host:port，写入前合并 | httpx/naabu | ✅ | `schema.dedupe()` |
| 4 | 被动优先 + 分阶段收敛 | amass/subfinder | ✅ | `collect → probe → scan` |
| 5 | 单次请求多维提取 | httpx | ✅ | `probe.py`（一次 GET 出状态/标题/头/正文/指纹） |
| 6 | 规则与引擎分离、规则可维护 | EHole/ObserverWard | ✅ | `fingerprints/builtin.yaml` + `fingerprint.py` |
| 7 | 排除规则抑制误报 | Wappalyzer/ObserverWard | ✅ | 规则 `negative` + `min_confidence` |
| 8 | 成本分级 + 短路求值 | finger/EHole | ✅ | `Condition.cost` + `_eval_rule` |
| 9 | 字面量前置过滤（多模式单次扫描） | httpx/wappalyzergo 思路 | ✅ | `FingerprintEngine._prefilter` |
| 10 | 速率 + 并发双旋钮、均有界 | naabu/nuclei | ✅ | `AdaptiveLimiter` + `validate_limits` |
| 11 | 指数退避 + 自适应降速 + 熔断 | nmap/naabu | ✅ | `ratelimit.py` |
| 12 | 断点续跑 | nuclei `-resume`/amass | ✅ | `state.py` |
| 13 | 结果标准化 JSONL | httpx/nuclei | ✅ | `assets.jsonl` / `findings.jsonl` |
| 14 | 自动校准抑制误报 | ffuf `-ac` | ❌（本次不做爆破） | 设计预留 |
| 15 | 爬虫/历史 URL/目录字典 | katana/gau/waybackurls/ffuf | ❌ | 见 02 优先级 |
| 16 | 独立端口扫描引擎 | naabu/masscan | ❌ | 沿用 HTTP 端口列表 |
| 17 | 模板化 POC | nuclei | ⭕ 复用现有 nuclei | `adapters.run_scan` 分级覆盖参数 |
| 18 | 爬取深度/scope 限制 | katana | ❌（未来如做爬虫必须实现） | — |
