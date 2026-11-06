# 只读越权检测（IDOR / 水平 + 垂直）

## 1. 能力边界

本模块只做**授权范围内的 GET 重放对比**：

- 水平越权（IDOR）：用身份 A 的会话采集资源 URL/对象标识，再用身份 B 重放，比较 B 是否拿到与 A 相同的数据。
- 垂直越权：用高权限身份采集管理接口，再用低权限身份重放，判断是否被 403/401/404 正确拒绝，或返回敏感内容。
- **不实现写操作**：代码中不存在 POST/PUT/PATCH/DELETE 调用，也没有“允许写方法”的配置开关。
- 不做竞态、金额篡改、文件上传、GraphQL mutation、WebSocket 等测试；命中只作为“疑似越权”证据，需人工复核。

## 2. 执行流程

```
账号元数据（无 secret） + 加密 vault
        │
        ├─ 身份预检：每个身份 1 次轻量 GET；失效/登录页/缺标记 → 任务失败
        ├─ 候选采集：A 的采集入口页面 + 现有 discovered/assets + JS 端点
        │   筛数字 ID / UUID / slug / base64 / hash（路径段或查询参数）
        ├─ 水平：A 基线 GET → B 重放 GET → 状态/长度/相似度/匿名基线
        ├─ 垂直：高权基线 → 低权重放（配置路径 + 高权页面管理链接 + 常见管理路径）
        └─ 去重 → authz.jsonl / authz-summary.json / authz-report.md
```

所有请求都走 `Prober.request`：范围校验 → 日配额/熔断 → 共享令牌桶 → 审计。
越权检测另有独立预算（默认每目标 200 次逻辑请求），超限即停，不继续重放。
越权阶段开始时重置 recon 的“连续失败”计数（避免端口探测失败把重放熔断），
但仍使用同一令牌桶、日配额与审计；authz 自身连续失败会重新打开熔断。

## 3. 配置格式

### 3.1 全局默认（config/recon.yaml）

```yaml
authz:
  enabled: true
  auto_run: true
  max_requests: 200
  similarity_threshold: 0.90
  public_similarity: 0.92
  max_candidates: 100
  max_vertical_paths: 30
  max_collect_pages: 10
  response_truncate: 400
  accounts_dir: "targets/authz"
  vault_path: "workspace/authz/vault.enc"
  key_path: "workspace/authz/vault.key"
  vertical_paths: []
```

### 3.2 明文账号导入（仅 CLI 一次性输入）

```yaml
identities:
  - name: A
    role: high                 # high / low / user
    cookie: "sid=A"
    headers:
      X-Api-Key: "REPLACE_ME"
    start_urls:
      - "http://127.0.0.1:18091/orders"
    session_check_url: "http://127.0.0.1:18091/api/me"
    expect_status: [200]
    expect_body_contains: ""   # 可选：响应必须包含该标记才算会话有效
  - name: B
    role: low
    cookie: "sid=B"
    session_check_url: "http://127.0.0.1:18091/api/me"
vertical:
  paths: ["/admin/audit", "/admin/users"]
  base_url: "http://127.0.0.1:18091/orders"
settings:
  max_requests: 200
  similarity_threshold: 0.90
```

```bash
python main.py authz -t targets/authorized/xxx.yaml --accounts accounts.yaml
python main.py authz -t targets/authorized/xxx.yaml --accounts accounts.yaml --prepare-only
python main.py recon -t targets/authorized/xxx.yaml --stage authz
```

导入后生成：

- `targets/authz/<slug>.yaml`：身份名称/角色/采集入口/会话校验 URL/credential_id，**无 cookie/header**。
- `workspace/authz/vault.enc`：Fernet 加密的 `credential_id -> {cookie, headers}`。
- `workspace/authz/vault.key`：Fernet 密钥；Unix 0600，Windows 用 `icacls` 去掉继承并只授权当前用户。

面板提交会直接写上述元数据与加密库，不会落盘明文凭据。批量 `all` 阶段发现元数据时自动执行（`authz.auto_run=true`）。

## 4. 候选与对象标识

候选来源：

- 身份 A（high/owner）的 `start_urls` 页面及其同源链接、inline JS 端点、最多 2 个同源 `.js` 文件端点；
- 现有 `discovered.jsonl`、`assets.jsonl` 中的 URL；
- 垂直路径：账号元数据里的 `vertical.paths`、高权页面中的管理链接、常见管理路径。

对象标识识别：

| 类型 | 规则 |
|---|---|
| 数字 ID | 路径段 3–12 位数字；查询参数为 `id/user_id/order_id/...` 时允许 1–12 位 |
| UUID | `8-4-4-4-12` 十六进制 |
| hash | 16/32/40/64 位十六进制 |
| base64 | 12 位以上，URL-safe 字符，含数字/`-`/`_`/`=` |
| slug | 含数字或 `-`/`_` 的路径段 |

排除：静态扩展名、`login/logout/signin/register/error/404/500/favicon`、非对象查询参数（`page/size/sort/q/...`）。

## 5. 判定逻辑与阈值

### 5.1 相似度

- JSON：顶层字段名 Jaccard（60%）+ 公共字段值的 token Jaccard（40%）。
- HTML/文本：去掉 script/style/标签后，token Jaccard 与 3-gram shingle Jaccard 加权；短文本（<20 token）只取 token Jaccard。
- 同时计算响应长度比 `min/max`，低于 0.5 视为内容明显不同。

### 5.2 判定表

| 条件 | 结果 |
|---|---|
| A 非 2xx / A 是登录页或统一错误页 | skip（无有效基线） |
| B 返回 401/403/404 | normal（正确拒绝） |
| B 返回 3xx（登录/跳转） | normal |
| B 返回 5xx | error |
| B 2xx 且相似度 < `similarity_threshold` | normal（内容不同） |
| B 2xx 且相似度 ≥ 阈值，但匿名访问与 A 相似度 ≥ `public_similarity` | suppressed_public（公共页） |
| B 2xx 且相似度 ≥ 阈值，匿名不可达/内容不同 | suspect（疑似越权） |

垂直越权使用同一判定表，只是基线身份为 high、重放身份为 low。

### 5.3 误报抑制

- 登录页、登录跳转、统一错误页（状态码 + 正文标记）。
- 公共页匿名基线：只有“疑似”候选才发 1 次匿名请求，避免浪费预算；匿名内容与 A 达到 `public_similarity` 即抑制。
- 静态资源、登录/注册/错误路径排除。
- 同一 canonical URL 多次命中只保留 `evidence_score` 最高的一条（证据更完整、相似度更高、敏感字段更多）。
- 控制样本（B 403/404）不生成证据，只计入 `normal`。

## 6. 凭据保护

- 凭据只在 `SecretVault.get()` 后存在于内存；`Identity` 的 `repr`、`public()`、日志、审计、summary、报告均不包含 cookie/header。
- 证据中的 A/B 响应先替换已知 secret，再按 JSON 敏感键（token/password/email/cookie/session/...）和通用 header/token 规则脱敏，最后截断 400 字符。
- 审计记录只写身份名称、URL（敏感查询参数脱敏）、状态码、耗时、长度、outcome；不写请求头。
- vault 与 key 文件权限受限；vault 被拷贝但 key 不同/丢失时只报“解密失败”，不输出明文。
- 面板只显示身份名称/角色与脱敏后的响应，不提供“查看凭据”入口。

## 7. 靶场验证（本地，仅 127.0.0.1）

靶场 `outputs/authz-demo/lab_server.py`：

| 样本 | 行为 | 期望 |
|---|---|---|
| `/orders/1001` | A/B 都能读同一订单（真 IDOR） | 检出水平越权 |
| `/orders/1002` | A 200，B 403 | 不误报 |
| `/public/notice/123` | A/B/匿名都返回相同公共公告 | 公共页抑制 |
| `/admin/audit` | high A 与 low B 都返回审计数据（真垂直越权） | 检出垂直越权 |
| `/admin/users` | A 200，B 403 | 不误报 |

实测（standard/light 配置、60 次预算）：

- 候选 3；水平测试 3；垂直测试 2
- 真阳性 **2**（1 水平 IDOR + 1 垂直）
- 真阴性 **3**（2 个 403 控制组 + 1 个公共页抑制）
- 误报 **0**
- 请求 16 / 上限 60；无预算耗尽
- 证据：`authz.jsonl` / `authz-report.md`，A/B 响应并排、已脱敏
- 单账号：`prepare_accounts` 直接拒绝（“至少需要 2 个身份”），不会执行
- 会话失效：身份 B 返回 401 时，预检抛出 `身份 B 会话失效`，不进入重放

## 8. 面板使用

1. 「新建任务」页填写目标与授权信息，勾选「启用 IDOR / 水平 + 垂直越权检测」。
2. 填身份 A/B 的 Cookie 或自定义 Header、会话校验 URL；A 填采集入口（如 `/orders`）。
3. 填垂直路径（可留空，自动推断常见管理路径）。
4. 提交后任务串行执行：recon → 越权检测；日志尾部显示「越权预检/越权检测」阶段。
5. 打开「越权检测」结果页：
   - 卡片：疑似/公共页抑制/负样本/请求预算；
   - 表格：类型、URL、A/B 状态、相似度、判定依据；
   - 展开「对比 A/B 响应（脱敏）」可并排查看两份响应。
6. 凭据不显示；需要修改账号时重新提交任务（会重新加密覆盖同目标凭据）。

## 9. 已知限制（抓不到什么）

- **写方法越权不测**：POST/PUT/PATCH/DELETE 的对象越权、创建/修改/删除、金额篡改、竞态、上传、GraphQL mutation、WebSocket 消息全部不覆盖。
- **没有盲枚举**：只测已链接/已发现/配置中的 URL；未在页面上暴露、需要遍历 ID 的资源抓不到。默认不做 ID 爆破。
- **共享登录页误报**：如果 A/B 都是登录用户，且页面内容对所有用户相同（如公共仪表盘），匿名基线是 401，可能被判疑似；需要人工复核或增加同租户控制身份。
- **动态内容**：时间戳、CSRF token、随机广告等会拉低相似度，可能漏报；阈值可调低但会增加误报。
- **所有权假设**：水平检测以 A/high 为资源所有者；A 无法访问的 URL 直接跳过，不反推 B 的所有权。
- **会话预检依赖配置**：若 `session_check_url` 是公开首页，过期会话可能仍返回 200；建议填受保护接口并配置 `expect_body_contains`。
- **只读不等于无副作用**：少数系统的 GET 也会改变状态，本模块无法识别；授权范围与人工确认仍是前提。
- **本地密钥威胁模型**：vault 加密保护静态文件，但当前系统用户/管理员仍可在进程内解密；没有 HSM/远程密钥。
- **预算是逻辑请求数**：重试/重定向会产生更多实际 HTTP 请求；全局日配额与熔断仍然生效。
- **相似度是启发式**：命中需要人工复核；不同模板/字段的语义差异可能被 token 相似度掩盖。
- **同一对象多端点**：按 canonical URL 去重；`/orders/1001` 与 `/api/orders/1001` 会分别检测，可能重复报告。
