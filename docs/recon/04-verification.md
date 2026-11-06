# 04 · 验证与风险

> 验证原则：**开发阶段不对任何真实外部目标发起扫描**。全部验证使用 `127.0.0.1` mock 服务、
> 本地 SQLite、tmp 目录，零外部网络请求（Hunter/subfinder 相关用例只做“可用性判断”，不发请求）。

---

## 1. 环境

| 项 | 值 |
|---|---|
| Python | 3.14.7（`.venv-recon` 独立虚拟环境） |
| 依赖 | pyyaml 6.0.3 / requests 2.34.2 / rich 15.0.0 / pytest 9.2.0 |
| 外部二进制 | 未参与 recon 单测（`subfinder/httpx/nuclei` 仅 legacy 冒烟测试使用） |
| 网络 | 仅 127.0.0.1（mock 站点 / tmp SQLite） |

```powershell
.venv-recon\Scripts\python.exe -m pytest tests/recon -q
```

---

## 2. 单元测试结果

```
84 passed in 9.34s
```

覆盖矩阵：

| 测试文件 | 覆盖点 |
|---|---|
| `test_schema.py` | host/URL 归一化、`host|port` 去重、多源合并、产品取最高置信度、端口未知不被 URL 默认端口覆盖、nuclei 行归一化、标题提取 |
| `test_fingerprint.py` | `any/all` 逻辑、negative 否决误报、`min_matched` 降权、前置过滤开关等价性（防漏报）、regex/status/favicon 条件、非法规则报错、内置库加载与真实命中 |
| `test_fingerprint_bench.py` | 命中/未命中两条路径的性能与结果一致性 |
| `test_ratelimit.py` | 越界参数拒绝、令牌桶节流、速率切换、熔断开合、降速下限、退避上限、配额持久化与跨目标隔离 |
| `test_state.py` | 进度持久化、计数器、失败阶段、目标隔离重置 |
| `test_sources.py` | 注册表、seed 声明资产（CIDR 不展开）、subfinder/hunter 降级、外部插件目录加载 |
| `test_probe_mock.py` | 探测+指纹、审计字段、范围拒绝（不发请求）、断点续跑、配额熔断、favicon hash、JSONL 往返、legacy 表镜像 |
| `test_legacy_scan_parse.py` | **G1 回归**：`type=http` 的命中必须入库（不被旧过滤器丢掉）；`stats` 行必须跳过；`strict_readonly` 下写入类 POC 仍被过滤 |
| `test_value.py` | 严重度/漏洞类型/通用产品/实例规模加分、证据缺失与重复/老 CVE 扣分、等级与建议边界、按价值排序 |
| `test_targeting.py` | 按产品分组、模板目录映射、未识别产品开关、已处理过滤、组数/URL 上限 |
| `test_inventory.py` | 去重 host 计数口径（多端口算 1）、通用门槛与接近门槛、样例上限、报告渲染 |
| `test_evidence.py` | 补天标题规范、评级/依据、curl 与证据摘录、截断与 Bearer 脱敏、低分不生成 |
| `test_import_source.py` | host/host:port/URL/CSV 解析容错、注释忽略、重复去重、文件缺失降级 |
| `test_runner_scan.py` | 扫描编排（monkeypatch nuclei）：分组、定向模板、配额截断、配额耗尽停止、进度落 state |

关键负向用例（证明“约束真的生效”，而不是写在文档里）：

- 未声明 `authorization` 的目标 → `load_target` 抛 `ScopeViolation`；
- 范围外主机 → 探测阶段直接拒绝，`budget` 计数为 0，审计留 `scope_reject`；
- `concurrency=0 / 65 / rps=999` → `RateConfigError`；
- 连续失败达阈值 → `acquire()` 抛异常（熔断），不会继续打目标；
- 日配额用尽 → 探测中止（`ProbeAborted`），剩余主机不发请求；
- 并发/日请求超温和档且未填 `authorization_ref` → `ConstitutionViolation`。

---

## 3. 指纹匹配性能对比（实测）

命令：`.venv-recon\Scripts\python.exe -m pytest tests/recon/test_fingerprint_bench.py -s`

场景：80 条规则（每条 1 个正文特写字面量 + 1 个响应头特征），正文 192,000 字节，页面**不含任何指纹**（最常见的真实情况）。

| 实现 | 耗时 |
|---|---|
| 前置过滤 + 成本短路 | **1.21 ms** |
| 朴素逐条遍历（`match_naive`） | 12.43 ms |
| 加速比 | **10.3x** |

命中场景（正文尾部含目标字面量）两者耗时相近（7.42 ms / 6.59 ms，差异在噪声范围内），
但**结果完全一致**——前置过滤只做“可证明的剪枝”，不改变匹配语义（有专门用例守护）。

> 说明：这是 CPU 侧收益；真正的大头是“一次请求完成存活+标题+头+正文+指纹”，
> 相比旧实现（httpx 探活 → 再抓正文做指纹）可把对外请求量降到 1/2 以下。

---

## 4. CLI 端到端（本地回环）

两个 mock 站点（`tests/recon/mock_site.py`）：
- `127.0.0.1:18081` 致远OA 风格页面（`Server: nginx`，标题含“致远OA”，正文含 `seeyon`）
- `127.0.0.1:18082` OpenResty 页面（无产品指纹）

目标文件 `targets/_verify_local.yaml`（授权依据=本地回环验证，仅 `127.0.0.1`），
配置 `workspace/_verify_recon.yaml`（light：并发 2 / 5 rps / 端口 18081,18082）。

### 4.1 首次运行（`--stage all --fresh`）

```
[*] 档位：light  并发 2  速率 5 rps  端口 2 个
[*] 指纹库 39 条规则 / 39 个产品（前置过滤 启用）
[*] 数据源 seed（declared）
    seed 返回 1 条，累计去重 1 条（0.0s）
    资产 2（本次请求 2，实际 9.09 rps）
[✓] 完成（0.31s）  资产 2 存活 2 有指纹 2  命中 0
    - Nginx: 1 台（置信度 0.95）
    - OpenResty: 1 台（置信度 0.95）
    - 致远OA: 1 台（置信度 0.95）
```

对照预期：2 个端口 → 2 次请求；`Server: openresty` 页面**没有**误报 Nginx（negative 规则生效）。

### 4.2 断点续跑（同命令去掉 `--fresh`）

```
    [resume] 数据源 seed 已完成，跳过
[✓] 完成（0.06s）  资产 2 存活 2 有指纹 2  命中 0
    请求 0 次，实际 0.0 rps
```

**0 次请求**，资产清单保持不变——证明续跑不会重复打击目标。

### 4.3 状态查询（`--stage status`）

```
    all: done / collect: done / probe: done（已处理 3）
[*] 资产 2 条 / 命中 0 条
    - Nginx: 1 台
    - 致远OA: 1 台
    - OpenResty: 1 台
```

### 4.4 产物检查

- `workspace/recon/本地回环验证/assets.jsonl`：2 行，`schema=recon.asset/v1`，含 `products/evidence/sources`；
- `summary.json`：资产 2 / 存活 2 / 有指纹 2，`limits.runtime.requests=2`、`current_rps=5.0`、`circuit=closed`；
- `report.md`：产品分布表 + 数据源贡献 + 速率与审计；
- `audit.jsonl`：逐请求 `request` 事件（含 `host/url/status/elapsed_ms/rps/outcome`）+ `fingerprint_hit` 事件（含 `matched` 依据）；
- legacy `assets` 表：镜像 2 行，`tech` 为 `["Nginx","致远OA"]` / `["OpenResty"]`（字符串列表 JSON，旧 `scan/judge/report` 可直接消费）。

### 4.5 审计样例（真实产物，已脱敏）

```json
{"ts":"…","target":"本地回环验证","event":"request","stage":"probe","host":"127.0.0.1","url":"http://127.0.0.1:18081","status":200,"elapsed_ms":46.3,"attempt":0,"rps":5.0,"outcome":"ok","body_len":312,"title":"致远OA V8.1 SP2 登录"}
{"ts":"…","target":"本地回环验证","event":"fingerprint_hit","product":"致远OA","rule_id":"seeyon-oa","confidence":0.95,"matched":["title~致远"]}
```

### 4.6 价值链路（离线，零请求）

准备 3 条资产（致远OA×2、OpenResty×1）与 2 条命中（critical RCE、info 缺头），
执行 `recon --stage evidence` 与 `inventory --min-instances 2`，实测输出：

```
[*] 指纹库 55 条规则 / 55 个产品（前置过滤 启用）
    [+] 证据包 A69: 20261102-A69-致远OA_远程代码执行-CVE-2023-1234.md
    [skip] 价值 3.0 < 40.0：http-missing-header
[*] 命中价值：可提交 1 条，等级 {'S': 0, 'A': 1, 'B': 0, 'C': 0, 'D': 1}
    [A69.0] 致远OA 远程代码执行 @ https://a.example.com/seeyon/htmlofficeservlet（优先提交）
    [D3.0] Missing Security Header @ https://c.example.com/（不建议提交）
    请求 0 次
```

```
[*] 目标 1 个 / 产品 2 个 / 存活资产 3 条
    - 致远OA: 2 台 已达通用门槛
    - OpenResty: 1 台
```

要点：
- **A69 = critical 55 + RCE 20 - 老 CVE 6**（CVE-2023 ≤ 当前年-3），评分依据逐条写入证据包；
- info 级命中（3 分）**不生成证据包**，避免低价值材料占时间；
- 盘点按“去重 host”计数，多端口不会虚增实例数；
- 全流程**0 次外部请求**（evidence/inventory 只读本地文件）。

### 4.7 扫描编排（不启动 nuclei）

`test_runner_scan.py` 通过 monkeypatch 替换 `run_scan`，验证：
- 3 台资产（2 致远OA + 1 Jenkins）→ 2 个扫描组，标签分别为 `致远OA`/`Jenkins`；
- 致远OA 组自动带上 `http/cves` 等定向模板目录；
- 剩余配额 25 次时，2 URL 的组被截断为 1（估算 15 次/URL）；
- 配额耗尽时不再发起任何组，并写 warning；
- 处理过的 URL 不会重复入组；
- `scan_grouped=true` 时，“已识别但无模板目录”的组件（如纯 Nginx）**默认跳过**，不占配额
  （`test_targeting.py::test_require_template_dirs_skips_generic_component`）。

---

## 5. 既有功能回归

| 项目 | 结果 |
|---|---|
| `tests/test_constitution.py`（宪法负向） | **19 通过 / 0 失败**（含新增的“填授权依据可放宽”“绝对上限仍拒绝”“并发 0 拒绝”三条） |
| `tests/test_smoke_local.py`（httpx + nuclei 本地全链路） | 见 §5.1 |
| 旧 `config.yaml`（无 `authorization_ref` 字段） | 正常加载（并发 8 未超温和档） |
| `main.py collect/scan/judge/report/run` | 参数与代码路径未改动；`recon` 为新增子命令 |

### 5.1 legacy 冒烟测试

`tests/test_smoke_local.py` 是既有脚本（httpx 探活 + nuclei 全模板扫描本地服务）。
本次**未跑到结束**：它对单个 URL 加载 14,000+ 模板、`-rate-limit 8`，按设计需约 30 分钟以上，
不适合作为每次改动的回归手段（此前一次尝试即在 nuclei 阶段长时间挂起，已清理残留进程）。

替代验证：
1. **httpx 探活链路**——`core/subdomain.py` 本次未改动；recon 的 `test_probe_mock.py` 覆盖了同一套
   HTTP 探测语义（状态码/标题/Server/端口归一化）。
2. **nuclei 结果解析链路**——新增 `tests/recon/test_legacy_scan_parse.py`，用 monkeypatch 注入
   合成 JSONL，直接验证 `core.scanner.scan_urls()` 的解析、去重、只读过滤逻辑（即本次 G1 修复点）。
3. 若需完整跑一次，建议另起低峰时段执行，或临时缩小 `tools/nuclei-templates` 目录后再跑。

---

## 6. 未完成项与风险

### 6.1 未实现（有意取舍）

| 项 | 原因 | 若要做的最低要求 |
|---|---|---|
| URL/路径发现（爬虫、历史 URL、目录字典） | 高噪声主动行为，公益 SRC 收益/风险比低 | 深度 ≤2、仅同域 scope、总请求上限、默认关闭 |
| 独立端口扫描（SYN） | 噪声大、易触发防护；HTTP 端口列表已覆盖多数入口 | 仅 connect 模式、端口数上限、共享同一配额账本 |
| favicon hash 指纹数据 | 不臆造未验证 hash；且 EHole 用 mmh3，本项目用 sha256，不互通 | 对授权目标实测采集后再入库 |
| `implies` 技术推断 | 推断项易污染资产清单 | 单独字段 + 低置信度 |
| 两套采集路径合并 | 向后兼容优先（本次硬要求） | 稳定后再把 `collect` 切到 recon 管线 |

### 6.2 已知风险

1. **指纹召回率**：内置库 39 条规则覆盖常见国产 OA/中间件/CMS，但远少于 Wappalyzer 规模；
   对未收录产品会漏报（漏报比误报安全，后续按实战补规则即可）。
2. **正文只读前 256KB**：指纹位于页面尾部的产品可能漏检；可通过 `fingerprint.body_limit` 调整（会增加内存占用）。
3. **favicon 为 sha256**：与 EHole/Wappalyzer 的 mmh3 hash 不兼容，规则不能直接复用。
4. **GBK 等非 UTF-8 页面**：按响应头 `charset` 解码，缺失时按 UTF-8，可能出现乱码导致中文关键词漏匹配
   （ASCII 指纹不受影响）。
5. **配额账本按“单目标+单日”**：同一目标被多个并发进程同时跑时，写锁在 SQLite 层，极端并发下可能抛锁等待；
   当前设计是单机单任务，未做多进程协调。
6. **recon 与 legacy 两套限速同时记账**：recon 探测用 `recon_budget`，nuclei 扫描用 `request_counter`，
   两者各自算额度；总请求量需把两份账本相加来看（`summary.json` 与 legacy 计数均可查）。
7. **`scan` 阶段的请求量是“估算登记”**：沿用 legacy `scan_urls` 的 `URL × 15` 保守估算，
   与 nuclei 实际请求数可能有偏差（偏保守，不会放大）。
8. **未做真实目标验证**：所有验证均在回环环境，真实网络下的 TLS 异常、CDN/WAF 拦截、超时分布
   需要首跑 `light` 档观察后再调参。
9. **价值分只是启发式**：权重基于补天公开经验（危害/类型/规模/重复风险），不是平台定价公式；
   实际收录与定价还受行业、时间跨度、厂商策略影响，不能据此承诺收益。
10. **盘点规模是本机视角**：`inventory` 只统计已采集且存活的资产，不能代表平台测绘总量；
    通用1.0 提交时仍需用测绘平台截图补充证明。
11. **导入清单的范围**：`workspace/import/<目标名>.txt` 中的 host 仅在“产品型目标（有 hunter_query）”
    下被视作已声明范围；普通域名目标仍只接受 `domains/ips` 内的资产，越界会被 `scope_reject` 拦下。

### 6.3 合规提醒

- `recon` 只接受显式 `-t targets/xxx.yaml`，不会遍历 `targets/` 目录；帆软目标因 `domains/ips/hunter_query` 全空，
  `load_target` 会直接拒绝，**本次未恢复该目标配置**。
- 放宽并发/日请求必须填写 `scan.authorization_ref`；绝对上限 64 / 100000 仍由代码硬校验拦截。
- 所有报告仍为本地文件，工具不包含任何提交平台逻辑（宪法第6条）。
