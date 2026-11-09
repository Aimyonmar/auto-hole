# 02 · 现状梳理与差距清单

> 对象：`auto-hole`（Python，SQLite 落库，外部二进制 nuclei/subfinder/httpx/dnsx）。
> 梳理范围：采集（资产收集）、存活探测、指纹、扫描（nuclei）、限速、去重、断点、报告。

---

## 一、现状梳理（按维度）

| 维度 | 现有实现 | 位置 |
|---|---|---|
| 入口 | `doctor / collect / scan / judge / report / run` 六个子命令 | [main.py](../../main.py#L121-L160) |
| 资产收集 | 硬编码两路：Hunter API + `subfinder → dnsx → httpx` | [pipeline.py](../../core/pipeline.py#L25-L78) |
| 数据源 | 只支持 hunter / subfinder；无插件机制，新增源必须改 pipeline | [hunter.py](../../core/hunter.py#L42-L80)、[subdomain.py](../../core/subdomain.py#L53-L84) |
| 结果结构 | 每个源各拼一个 dict（字段名靠约定），`source` 是单字符串 | [pipeline.py](../../core/pipeline.py#L43-L47) |
| 去重 | 只在 SQLite 唯一索引 `(target, host, port)` 层去重；同资产多源命中时后写覆盖前写 | [db.py](../../core/db.py#L11-L26) |
| 存活探测 | 调 `httpx -json`，取 title/tech/status/webserver | [subdomain.py](../../core/subdomain.py#L93-L160) |
| 指纹 | 37 个国产产品的“别名关键词表”，对 `tech` 字符串和标题做 `in` 匹配，无规则、无置信度、无排除项 | [fingerprint.py](../../core/fingerprint.py#L18-L83) |
| 端口 | 无端口扫描；仅 httpx `-ports` 覆盖 9 个常见 Web 端口 | [subdomain.py](../../core/subdomain.py#L114-L115) |
| URL/路径发现 | 无爬虫、无历史 URL、无目录字典 | 不存在 |
| 漏洞验证 | nuclei：severity + tags + 写入类 POC 关键词过滤 + 指纹定向目录 | [scanner.py](../../core/scanner.py#L24-L50) |
| 命中去重 | `(template_id, host)` 唯一索引（跨目标也拦） | [db.py](../../core/db.py#L115-L120) |
| 限速 | 单目标“日请求计数”SQLite 熔断；无每秒速率、无退避、无熔断恢复；计数点在“资产登记”而非真实请求 | [constitution.py](../../core/constitution.py#L118-L154) |
| 并发 | 由 nuclei/httpx 的 `-rate-limit`/`-concurrency` 参数承载；父进程本身无并发控制 | [subdomain.py](../../core/subdomain.py#L48-L51) |
| 断点续跑 | 无 | 不存在 |
| 结果落库 | SQLite `assets`/`findings`；报告为 Markdown | [db.py](../../core/db.py#L11-L48)、[report.py](../../core/report.py#L70) |
| 审计 | 无请求级日志 | 不存在 |
| 测试 | 2 个脚本式测试（宪法负向 15 项 + 本地冒烟） | [tests/](../../tests) |

---

## 二、差距清单

编号规则：`G` = gap，`✅` 本次已改，`⏸` 本次未改（有原因）。

### G1（❗高危，✅）nuclei 命中行被错误过滤，真实命中可能全丢

- **现状**：`scan_urls` 用 `j.get("type") not in (None, "", "finding")` 判定命中行。
- **问题**：nuclei `-jsonl` 的命中行 `type` 实际为 `http` / `dns` / `ssl` / `tcp` 等，该条件会把**所有真实 HTTP 命中**过滤掉；本地冒烟测试因“预期 0 命中”而一直没暴露。
- **改法**：改为“排除 `stats/error/trace/progress` + 必须存在 `template-id`”。
- **收益**：极高（直接决定有没有结果）。**成本**：极小。

### G2（❗高，✅）没有统一结果 schema，多源结果无法合并

- **现状**：各源直接产出字段不一的 dict；`source` 单值；重复资产互相覆盖。
- **业界**：subfinder/httpx/nuclei 都先归一化再输出（`-json/-jsonl` 稳定字段）。
- **改法**：新增 `Asset`/`Finding` 数据类 + `sources[]` 合并 + `host|port` 去重 key。
- **收益**：高（后续所有能力的基座）。**成本**：小。

### G3（❗高，✅）指纹能力弱：只有“别名关键词”，没有规则/置信度/误报抑制

- **现状**：`PRODUCT_ALIASES` 逐条 `in` 匹配 tech 与标题；无法看响应头/正文；无 `Server: openresty` 时仍会同时报 Nginx 这类冲突。
- **业界**：EHole JSON 规则 + ObserverWard/Wappalyzer 的 `excludes` + 置信度 + 多条件 AND。
- **改法**：YAML 规则库（header/title/body/url/status/favicon 条件，`any/all`、`negative`、`confidence`）+
  引擎（成本分级短路 + 字面量前置过滤 + 弱命中降权 + `min_confidence` 过滤）。
- **收益**：高（资产质量直接决定后续 POC 定向）。**成本**：中。

### G4（高，✅）无每秒级限速、无退避、无熔断恢复

- **现状**：只有“日请求计数上限”，达到即抛异常；没有 rate/并发双旋钮，也没有 429/5xx 的降速。
- **业界**：naabu/nuclei 的 `-rate` + `-c`；nmap 的 RTT 自适应；对端限流时主动降速。
- **改法**：`TokenBucket` + `AdaptiveLimiter`（降速/回升/熔断）+ 持久化 `BudgetLedger`。
- **收益**：高（合规底线 + 稳定性）。**成本**：中。

### G5（高，✅）没有断点续跑，中断即重跑

- **现状**：无状态文件；`nuclei` 超时（2h）后只能重新开始。
- **业界**：nuclei `-resume`、amass 图库状态。
- **改法**：分阶段 `RunState`（`processed` 集合 + 原子写入 + 目标隔离）。
- **收益**：高（长任务可用性）。**成本**：小。

### G6（中高，✅）无请求级审计

- **现状**：只有控制台输出与 SQLite 计数。
- **合规要求**：目标、时间、速率、命中证据必须可审计。
- **改法**：`audit.jsonl` 逐请求一条（含 `elapsed_ms`/`rps`/`outcome`），指纹命中与漏洞命中另记事件。
- **收益**：中高（合规刚需）。**成本**：小。

### G7（中，✅）扫描策略只有全局一套

- **现状**：severity/tags/并发全在一个 `scan` 段；无“轻量/标准/深度”档位。
- **业界**：nuclei 通过 severity/tags/workflows 分级；httpx/naabu 通过 rate/ports 分级。
- **改法**：`config/recon.yaml` 的 `profiles.light/standard/deep`，扫描阶段复用 `core.scanner` 并覆盖参数。
- **收益**：中（首次跑更安全、深度跑更彻底）。**成本**：小。

### G8（中，✅）数据源不可扩展

- **现状**：新增数据源要改 `pipeline.py` 与 `subdomain.py`。
- **业界**：subfinder/amass/OneForAll 均为插件式。
- **改法**：`Source` 基类 + `@register` + 目录自动发现 + 可选外部插件目录 + 可用性降级。
- **收益**：中（长期可维护性）。**成本**：小。

### G9（中，✅）无“运行时实际速率”记录

- **现状**：无法回答“这次到底发了多少请求、峰值多少”。
- **改法**：`AdaptiveLimiter.snapshot()` + `summary.json` 的 `limits.runtime` + `report.md`。
- **收益**：中。**成本**：极小。

### G10（中，⏸）无 URL/路径发现（katana/gau/waybackurls/ffuf）

- **原因**：爬虫与目录爆破是**高噪声主动行为**，在公益 SRC 场景性价比低且合规风险高；
  且需要额外的 scope 限制（爬取深度、域名 scope）才能保证不越界。
- **建议**：作为下一阶段独立能力，必须内置“深度 ≤2、仅同域、总请求上限、默认关闭”。
- **收益**：中（对特定目标有效）。**成本**：大。

### G11（中低，⏸）无独立端口扫描（naabu/masscan）

- **原因**：SYN 扫描噪声大、易触发防护；当前 httpx 端口列表已覆盖绝大多数 Web 入口。
- **建议**：若做，仅允许 connect 模式、单目标端口数上限、默认关闭，并纳入同一 `BudgetLedger`。

### G12（低，⏸）指纹库无 favicon hash 数据

- **现状**：引擎已支持 `favicon` 条件与计算（sha256），但内置库没有真实 hash 条目（不臆造数据）。
- **说明**：EHole 用的是 mmh3 hash；本项目用 sha256（无需额外依赖），两者**不互通**，需单独维护。
- **建议**：后续可按需采集授权目标的 favicon 计算 sha256 并入库。

### G13（低，⏸）无 `implies`（技术推断链）

- **现状**：命中 PHP 不会推断“PHP 生态”。
- **原因**：推断项易污染资产清单，且对补天提交帮助有限；当前只输出“有证据的指纹”。
- **建议**：如引入，推断项必须 `confidence < 0.5` 且与“实测指纹”分开字段。

### G14（低，⏸）legacy 与 recon 两套路径并行

- **现状**：`recon` 与 `collect` 都可用，各自落库；recon 只镜像到 legacy `assets` 表。
- **原因**：保持向后兼容（既有 CLI/配置/表结构不变）是本次硬要求。
- **建议**：稳定后可将 `collect` 逐步切到 recon 管线（保留旧命令作为兼容入口）。

### G15（低，⏸）无 SQLite 之外的持久化/聚类

- **现状**：单文件 SQLite；无资产关系图、无跨目标聚类。
- **原因**：当前规模（单目标数千资产）足够；过度设计无收益。

---

## 三、性价比排序（收益 × 成本）

| 排名 | 差距 | 收益 | 成本 | 优先级 |
|---|---|---|---|---|
| 1 | G1 nuclei 命中被过滤 | 极高 | 极小 | P0（立即修） |
| 2 | G2 统一 schema + 去重合并 | 高 | 小 | P0 |
| 3 | G6 请求审计 | 中高（合规刚需） | 小 | P0 |
| 4 | G5 断点续跑 | 高 | 小 | P0 |
| 5 | G4 速率/退避/熔断 | 高 | 中 | P0 |
| 6 | G3 指纹规则引擎 | 高 | 中 | P1 |
| 7 | G8 数据源插件化 | 中 | 小 | P1 |
| 8 | G7 分级策略 | 中 | 小 | P1 |
| 9 | G9 实际速率记录 | 中 | 极小 | P1 |
| 10 | G10 URL 发现 | 中 | 大 | P2（未做） |
| 11 | G11 端口扫描 | 中低 | 中 | P2（未做） |
| 12 | G12 favicon 库 | 低 | 中 | P3（机制已就绪） |
| 13 | G13 implies | 低 | 小 | P3（未做） |
| 14 | G14 两套路径 | 低 | 中 | P3（兼容优先） |
| 15 | G15 图数据库 | 低 | 大 | P3（不做） |

**本次实现范围**：P0 全部 + P1 全部（G1–G9）。P2/P3 只做机制预留与文档说明。
