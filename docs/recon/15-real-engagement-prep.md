# 真实实战前的准备（首跑配置 / 模板精简 / 停机 SOP）

结论先行：

- **首跑只开 light 档**：探测并发 3、5 rps，nuclei 并发/速率 3/3、bulk 25、单请求超时 8s、重试 1 次；端口只探 80/443；面板单目标本次日配额 500；体检独立预算 60。
- **模板必须按指纹裁剪**，不能直接上全量。实测：致远 OA 标签族 18 条，high+critical 且排除 intrusive 后选中 **7 条**；`weak_password=false` 时实际执行 5 条。通达 6 条、泛微 25 条、用友 21 条。单方向一轮控制在 **15–30 条**，最多不超过 50 条。
- **模板由代码强制裁剪**：指纹命中后只把筛选出的具体模板文件传给 nuclei，不再传全量目录；没有指纹时使用内置 30 条基准白名单，目录缺失/为空直接报错，不回退全量。
- **WAF 自动中止**：探测/发现/扫描任一阶段识别到拦截特征（含 429 和 Cloudflare challenge）就停止当前目标；状态与报告标记 `waf_stop`，审计写 `waf_hit` / `waf_stop`；阈值 `waf.stop_after` 默认 1。
- **UA 与档位已对齐**：nuclei 通过 `-header` 使用 `probe.user_agent`；开发态与打包态的 light 在 `max_hosts`、`scan_max_urls`、`scan_severity`、UA 上一致。
- **软 404 基线改为 3 次取样**：状态取众数、长度取中位数。
- nuclei 阶段的请求数仍只能按 **URL×15** 估算，无法从现有产物精确解析。

## 1. 首跑配置建议

### 1.1 建议值

| 参数 | 首跑建议 | 实际口径 / 理由 |
|---|---|---|
| 档位 | `light` | 面板只允许 light/standard，任务默认 light；triage 固定 light |
| 探测并发 | 3 | light profile；对真实目标先保守 |
| 探测速率 | 5 rps | light profile 的令牌桶速率 |
| nuclei 并发 | 3 | 代码把 `profile.concurrency` 同时传给 `-concurrency` |
| nuclei rate-limit | 3 | `build_nuclei_cmd` 用 `scan.concurrency` 作为 `-rate-limit`，不是 profile 的 5 rps |
| nuclei bulk-size | 25 | 代码固定值 |
| nuclei 超时 / 重试 | 8s / 1 | 代码固定值；子进程总超时 2h |
| 端口 | 80, 443 | light profile |
| 探测超时 / 重试 / 重定向 | 8s / 1 / 5 | light profile 与 probe 默认值 |
| 单目标本次日配额 | 500 | 面板 batch manifest 固定 `daily_limit: 500`；主配置的 5000 只是上限 |
| 扫描 URL 上限 | 通常 ≤33 | 500 配额 ÷ 15/URL；其他 legacy 请求会进一步减少可用 URL 数 |
| 严重度 | `high,critical` | 开发态与打包态 light 均已统一为 high,critical |
| 弱口令 | `weak_password: false` | 首跑不发 default-login 登录尝试，避免锁定/告警；代码会加 `-exclude-tags default-login` |
| UA | `auto-hole-recon/1.0 (authorized security testing)` | 探测与 nuclei 共用该 UA；nuclei 通过 `-header` 注入 |
| 取证模式 | `strict_readonly` | 宪法第 2 条默认；不写目标 |
| 体检预算 | 60 | triage 独立预算，硬顶 200 |
| 越权预算 | 200 | 仅在有账号元数据时执行，GET-only |

不建议首跑使用 standard（8 并发 / 20 rps）；更不要用 deep。deep 在配置和 CLI 中存在，但面板不可选。

### 1.2 light 档与面板档位一致性核对

| 项目 | 开发态 `config/recon.yaml` | 打包态自动生成 `config/recon.yaml` | 首跑采用 |
|---|---|---|---|
| 面板可选档位 | light / standard | light / standard | light |
| light 并发 | 3 | 3 | 3 |
| light 速率 | 5 | 5 | 5 |
| light 探测超时 / 重试 | 8 / 1 | 8 / 1 | 8 / 1 |
| light 端口 | 80,443 | 80,443 | 80,443 |
| light `max_hosts` | 300 | 300 | 300 |
| light `crawl_max_urls` | 30 | 30（内置默认） | 30 |
| light `path_scan_max_paths` | 20 | 20（内置默认） | 20 |
| light `scan_max_urls` | 100 | 100 | 受 500 配额约束，通常 ≤33 |
| light `scan_severity` | high,critical | high,critical | high,critical |
| probe UA | 带 `(authorized security testing)` | 带 `(authorized security testing)` | 使用该值 |
| limits `min_rps` / `backoff_max` | 2 / 8 | 1 / 4 | 2 / 8 |

结论：**面板档位只有 light/standard，默认任务也是 light**；开发态与打包态 light 的四个关键值已统一为更保守的一方。`deep` 仍只存在于配置与 CLI，面板不可选。

另有两处易混淆：

- 主配置 `config.yaml` 的 `scan.concurrency: 8`、`daily_request_limit: 5000` 是上限；实际执行时 light profile 会把并发覆盖为 3，单目标日配额由 batch manifest 覆盖为 500。
- `config/recon.yaml` 的顶层 `profile: standard` 是 CLI 默认；面板任务显式传 `--profile light`，triage 也固定 light。

## 2. 模板精简方案

### 2.1 从指纹到模板子集

映射方法：

1. 在体检报告的 `tech` 里取产品名，对应 `modules/recon/fingerprints/builtin.yaml` 的 `product`。
2. 取该规则最具体的标签（如 `seeyon`），不要用 `oa`、`java`、`server` 这类泛标签。
3. 用 nuclei 的“只列模板、不扫描”模式统计和导出：`-tl` 配合 `-tags`、`-severity`、`-exclude-tags`。
4. 单产品只保留 high/critical，并排除 `intrusive/dos/fuzz`；文件上传、写入类模板首跑一律不发。
5. 每轮 15–30 条，最多 50 条；超过就按“版本命中优先、RCE/未授权优先”再砍。

实际命令示例（只列模板，不执行扫描）：

```powershell
tools\nuclei.exe -templates tools\nuclei-templates `
  -tags seeyon,seeyon-oa,zhiyuan -severity high,critical `
  -exclude-tags intrusive,dos,fuzz -tl -disable-update-check -silent
```

### 2.2 本地模板目录实测结果

模板总量 14103 个 YAML，其中 `http/` 11675 个；全部模板中 high+critical 为 5025 个。

| 指纹产品 | 建议标签 | 模板总数 | high+critical | 排除 intrusive 后 |
|---|---|---:|---:|---:|
| 致远 OA | `seeyon,seeyon-oa,zhiyuan` | 18 | 11 | **7** |
| 通达 OA | `tongda` | 15 | 11 | **6** |
| 泛微 OA | `weaver,ecology` | 39 | 36 | **25** |
| 用友 | `yonyou,chanjet` | 37 | 30 | **21** |
| 若依 | `ruoyi` | 2 | 1 | 1（另一条为 headless，当前扫描未开 headless） |
| 禅道 | `zentao,easycorp` | 2 | 1 | 1 |

上表是“选中模板数”；首跑若 `weak_password=false`，命令行还会用 `-exclude-tags default-login` 再过滤，实际执行数会更少（实测致远 OA 为 5 条）。

示例（致远 OA，排除 intrusive 后实际保留）：

- `http/misconfiguration/seeyon-unauth.yaml`
- `http/vulnerabilities/seeyon/seeyon-oa-fastjson-rce.yaml`
- `http/vulnerabilities/seeyon/seeyon-oa-setextno-sqli.yaml`
- `http/vulnerabilities/other/seeyon-oa-log4j-rce.yaml`
- `http/cnvd/2020/CNVD-2020-62422.yaml`

按关键词粗筛全量 OA 产品（致远/通达/蓝凌/用友/若依/禅道/泛微）共有 109 条 http 模板；high+critical 且非 intrusive 为 64 条，与上面的按标签结果基本一致。每轮只取其中一个产品方向即可控制在几十条以内。

### 2.3 接进当前工具的实际行为

修复后的 `scan_urls` / `build_nuclei_cmd` 行为：

1. 指纹命中产品后，`FingerprintEngine.tags_for()` 取该产品最具体的标签（如 `seeyon`，不会用 `oa/java/server` 泛标签）。
2. 代码直接读取本地模板 YAML 的 `tags`/`severity` 建立索引（只扫 `http/`），按产品标签和严重度筛选；不启动 `nuclei -tl` 子进程，打包环境下也不需要等待 nuclei 遍历全量库。
3. 实际扫描命令只包含这些文件的多个 `-t`，**完全不再传 `-templates`**；模板数量从全量 14103 降到 5–30 条级别。
4. 命令行同时带 `-tags`（产品标签 ∪ `scan.tags_include`）和 `-exclude-tags`（配置排除 ∪ `intrusive,dos,fuzz`）；`weak_password=false` 时额外排除 `default-login`。
5. 没有指纹时，按 `paths.nuclei_templates_base` 读取内置 30 条基准白名单；目录缺失或为空直接抛 `TemplatePolicyError`，不会回退全量。
6. nuclei 的 UA 通过 `-header "User-Agent: ..."` 注入，默认取 `recon.probe.user_agent`。

因此首跑**不需要再复制子集目录或改 `paths.nuclei_templates`**；选中哪个产品由指纹标签决定，子集目录由代码自动生成文件列表。

### 2.4 体检没有指纹时

- light/standard 的 `scan_unidentified: false`：未识别产品不进入扫描分组，直接给出“未回退全量模板”的警告。
- deep 的 `scan_unidentified: true`：使用 `tools/nuclei-templates-engage/base/` 下的 **30 条** high/critical、非 intrusive 模板（配置/源码暴露、面板/接口暴露、目录/调试页等），不会扫描 14103 条全量。
- 基准目录缺失或为空：直接报错，要求补模板或改 `paths.nuclei_templates_base`。

首跑仍建议：没有指纹就**不扫**，把结论停在人工复核；确需继续时再用这 30 条基准白名单。

## 3. WAF 与噪声识别

### 3.1 代码已有的识别能力

triage 会把响应头/正文前 2048 字符与下列标记匹配，命中后写入报告 `waf` 字段，并在结论里扣 4 分、建议 light：

- Cloudflare：`cloudflare|cf-ray|cf-cache-status`
- Akamai：`akamai|akamai-ghost`
- Imperva：`imperva|incapsula|visid_incap`
- Sucuri：`sucuri`
- AWS WAF：`awswaf|aws.?waf|x-amzn-waf`
- 阿里云盾：`aliyun|yundun|阿里云盾`
- 腾讯云 WAF：`tencent|腾讯云waf|waf.tencent`
- 安全狗：`safedog|安全狗`
- 云锁：`yunsuo|云锁`
- 长亭/雷池：`chaitin|长亭|雷池`
- 360 WAF：`360waf|360网站卫士|360安全`
- ModSecurity：`modsecurity|mod_security`

代码现在会**自动中止**：`WafGuard` 在探测/发现/扫描金丝雀任一阶段识别到拦截后，立即停止当前目标；状态/报告标记 `waf_stop`，审计写 `waf_hit` 与 `waf_stop`（URL、HTTP 状态、命中特征、命中次数、阈值）。默认 `waf.stop_after: 1`（首次即停），可配置为累计 N 次（1–10）。

### 3.2 实战补充特征

以下特征与代码标记一起看，以实际响应为准：

| 类型 | 常见响应码 | 可核对特征 |
|---|---|---|
| Cloudflare | 403 / 429 / 503 | `Server: cloudflare`、`CF-RAY`、页面含 `Attention Required` / `Ray ID` / `cf-error-details` |
| 阿里云盾 | 403 / 405 / 503 | 页面含 `aliyun` / `yundun` / `阿里云盾`，或跳转 `errors.aliyun.com` |
| 长亭雷池 | 403 | 页面/响应头含 `chaitin` / `长亭` / `雷池` / `SafeLine` |
| 腾讯云 WAF | 403 / 429 | 响应含 `tencent` / `waf.tencent`，或跳转腾讯云拦截页 |
| 安全狗 / 云锁 | 403 | 页面含 `safedog` / `安全狗` 或 `yunsuo` / `云锁` |
| Imperva | 403 | `visid_incap` cookie、`X-Iinfo`、`incapsula` |
| Akamai | 403 | `Server: AkamaiGHost`、`X-Akamai-*` |
| AWS WAF | 403 | `x-amzn-waf`、`awswaf` |
| ModSecurity | 403 / 406 | 页面含 `ModSecurity` / `Not Acceptable` |

通用拦截页特征：短正文、统一 403、含 “Access Denied / Request blocked / Web Application Firewall / 请稍后再试 / 人机验证 / captcha / JavaScript challenge”，或所有路径（包括随机 404 路径）都返回同一拦截页。

### 3.3 降级与中止

- WAF 命中：代码自动停止当前目标，无需人工判断；体检阶段同样会提前结束并写入 `waf` 证据。
- 扫描阶段由于 nuclei 内部响应不可见，代码在每组前后用同一 URL 做一次 GET 金丝雀；金丝雀命中即停止后续组。
- 出现 429：代码按 WAF 信号自动停止；人工冷却至少 15 分钟，不自动重试。
- 403 连续 5 次，或最近 20 次请求中 403 占比 ≥20%：人工立即停止（代码不会按 403 比例自动停）。
- 超时率 ≥20%（最近 20 次）或 P95 > 8s：先把并发/速率降到 1/1；再发 10 个请求仍不恢复就停止。
- 5xx ≥10%，或连续 3 个 5xx：人工立即停止。
- 工具内置熔断是“连续失败 8 次 → 冷却 60 秒”，属于保护而非合规中止；不能拿它替代人工停机。

## 4. 404 基线校准在真实目标的落地

代码当前实现（`modules/recon/discovery.py`）：

- 每个路径探测的 base 取 **3 条**随机路径：`/__auto_hole_probe_<epoch 毫秒>_0/1/2`；
- 基线状态取 3 条的**众数**，基线长度取同状态样本的**中位数**；
- 判定“明显不同”的条件：
  - 状态 200/201，且状态与基线不同，或正文长度 > 基线长度 × 1.15；
  - 状态 401/403/500，且状态与基线不同。
- 不使用标题相似度、正文 hash 或重定向目标比较。

triage 的暴露面探测没有软 404 基线：只跳过 404/410 和 ≥500，其他状态会记录。因此体检报告里的 200 暴露面必须人工复核。

真实目标建议：

- 代码每次已自动取 3 条随机路径；如果目标对随机路径有缓存、JS challenge 或按 UA 返回不同内容，建议再用同一 UA/会话手工补测 2–3 条确认。
- 全部样本返回 200 且正文长度差异在 ±15% 内、标题基本相同 → 判为软 404，后续 200 不作为暴露面。
- 样本中状态不同、长度差异 >15%、标题不同、或跳转到不同 Location → 才认为“明显不同”，可记录。
- 代码里的 15% 是唯一量化阈值；人工校准高于 15% 时，以人工结果为准，并在报告中注明。

## 5. 扫描请求数精确计数

| 阶段 | 能否精确 | 现有口径 |
|---|---|---|
| 探测 / 爬取 / 路径扫描 | 可以 | 审计 `workspace/recon/audit.jsonl` 的 `event=request`；summary 的 `probe.requests`；预算账本的 `used/breakdown` |
| 体检 | 可以 | 报告 `basics.request_budget.used/limit`（默认 60） |
| 只读越权 | 可以 | 越权 summary 的 `requests/max_requests`（默认 200） |
| nuclei 扫描 | **不能精确** | 运行前按 `URL × 15` 预扣日配额；summary 只有 `requests_estimated = urls_scanned × 15` |

nuclei 的 JSONL 只包含命中结果，不记录每个请求；`-stats` 的输出被 `subprocess` 捕获后没有解析或落盘。因此：

- 报告里只能写“估算请求数”，不能写“实际请求数”。
- 需要更准的数字时，只有两种低成本方式：
  1. 用同一命令手工复跑一次并读取 `-stats` 的最终 Requests 计数（会真实发请求，必须重新授权并计入配额）；
  2. 由授权方提供目标侧访问日志，按 UA/时间窗统计。
- 当前不建议把 `-stats` 输出当作自动依据，因为它没有进入数据库或报告。

## 6. 首跑 SOP

### 6.1 流程

1. **授权与范围**：目标必须已有授权档案、范围非空、预检通过；`automation_allowed=no` 直接拒绝。
2. **体检**：`main.py triage -t <target> --profile light --max-requests 60 --fresh`，或面板「目标体检」。
   - 上限 60 请求、50 主机、每主机最多 12 条暴露面路径；零 nuclei。
   - 预算用尽、无存活、WAF 命中、全 403：体检结束即停。
3. **人工读报告**：只选 1–2 个方向（带版本产品 / 可访问暴露面 / 明确风险方向）。
   - 没有指纹：默认不进入扫描；确需继续时由代码使用 2.4 的 30 条内置白名单。
4. **定向小批量**：按第 2 节，由指纹标签自动筛出具体模板文件；无需改 `paths.nuclei_templates`，也不需要手工复制子集目录。用面板 light 档或 `batch --profile light`。
   - 每轮 15–30 条模板、1–2 个 URL、单目标日配额 500。
   - 监控每 20 个请求的状态码、超时、响应体特征；WAF 由代码自动中止。
5. **无论结果如何先停**：不追加第二轮、不扩大 URL、不做利用验证；出报告和证据包后再决定是否申请下一轮授权。

### 6.2 立即中止清单

下表阈值是首跑 SOP 的人工规则，不是代码内置熔断；代码内置的只有“连续失败 8 次 → 冷却 60 秒”。

| 触发条件 | 阈值 | 动作 |
|---|---|---|
| 429 | 任意一次 | 代码按 WAF 信号自动停止；人工冷却 ≥15 分钟 |
| 403 骤增 | 连续 5 次，或最近 20 次 ≥20% | 人工立即停止 |
| WAF 标记/拦截页 | 任意一次 | 代码自动停止并记录响应头与页面特征 |
| 超时率 | 最近 20 次 ≥20% 或 P95 > 8s | 先降到 1 并发/1 rps；10 次仍不恢复则停 |
| 5xx | ≥10% 或连续 3 次 | 立即停止 |
| 日配额 | 已用 ≥80%（500 中的 400） | 停止，不再发请求 |
| 体检预算 | 60 次用尽 | 停止，按部分数据出报告 |
| 范围越界 | 任意跳转到范围外主机/域名 | 立即停止并记录 |
| 命中 critical | 任意 critical finding | 停止，不验证利用，交人工 |
| nuclei 子进程 | 超过 2h | 停止并保留部分结果 |
| 人工不确定 | 任何异常 | 停止，先问授权方 |

### 6.3 每轮固定输出

- 体检报告：`triage.md` / `triage.json`
- 扫描 summary：组数、URL 数、估算请求数、命中数、warnings
- 审计：`workspace/recon/audit.jsonl`
- 证据包：仅对人工确认的方向生成，不自动提交

## 7. 当前做不到 / 已知缺口

1. **nuclei 请求数无法精确统计**：只有 URL×15 估算；`-stats` 未落盘，也不能自动回填。
2. **扫描阶段的 WAF 识别是金丝雀**：nuclei 内部响应不可见，代码在每组前后用同 URL 做 GET 检查；如果 WAF 只在扫描中途触发，最多在组结束后停止，不能中断正在运行的 nuclei 子进程。
3. **软 404 基线只在 discovery 生效**：triage 暴露面仍只按 404/410/≥500 跳过，没有软 404 校准。
4. **面板不暴露 deep 档**：配置与 CLI 支持，但面板只有 light/standard；deep 仅供 CLI 显式使用。

以上 1–4 属于仍存在的限制；模板定向、tags/exclude、UA、WAF 自动中止、light 档对齐已在本版修复。

## 8. 本机验证记录（2026-11-02）

| 验证项 | 结果 |
|---|---|
| 功能测试 | **187 passed**（既有 176 + 新增 11） |
| 宪法检查 | **19 通过 / 0 失败** |
| 标签筛选（测试替身） | 两个指纹场景分别 8 / 15 条模板，均断言 <50 且远小于全量 14103 |
| 标签筛选（真实索引） | 本地索引 11675 个 http 模板（首次建索引约 20s）；致远 OA 选中 7 条，Jenkins 7 条；基础白名单 30 条 |
| 命令行断言 | 无 `-templates`；`-t` 数量等于选中文件数；`-exclude-tags` 含 `intrusive,dos,fuzz`；`-header` 带 UA |
| 无指纹 | 使用 base 30 条；base 缺失抛 `TemplatePolicyError`，不回退全量 |
| WAF 阈值 | mock Cloudflare 403：`stop_after=2` 时第 1 次不触发、第 2 次触发 |
| WAF 阶段停止 | mock 站点：probe 阶段命中后 `probe.requests=1`，discovery/scan 未调用，状态 `waf_stop`，审计有 `waf_stop`，report 含 “WAF 中止” |
| WAF 扫描金丝雀 | 扫描前金丝雀命中 → `run_scan` 未调用，warnings 含 WAF |
| 软 404 | 全 200 的软 404 站点：3 条取样后所有路径都不标记 interesting |
| 打包 | `dist` 255.73 MB；`--selftest` exit 0、http=200；内置白名单 30 条 |
| 打包态模板子集 | `AutoHoleDashboard.exe --run-cli recon --stage scan`：输出 `模板策略：targeted，5 个模板`，排除 `dos,fuzz,intrusive,default-login`，无全量模板；仅访问 127.0.0.1 mock |
