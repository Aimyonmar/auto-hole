# 07 · 进化回路：指标 → 候选 → 靶场回归 → 人工入库 → 版本回滚

> 核心原则：**自动产出候选，绝不自动改生产规则**；候选先过本地靶场正/负样本回归，
> 人工 `approve` 后才入库，且每次变更都有快照，可回滚。

## 1. 复盘指标（`metrics.json` / `metrics-history.jsonl`）

| 指标 | 口径 |
|---|---|
| `hits` | 本轮命中条数（去重后） |
| `false_positives` | 人工标记为误报的命中数（来自 `feedback.jsonl`） |
| `precision` | `(hits - fp) / hits`，粗略准确率 |
| `covered_assets` | 存活资产数 |
| `http_requests_probe` | 探测阶段实测请求数（审计计数） |
| `http_requests_scan_estimated` | 扫描阶段保守估算（扫描 URL × 15，沿用 legacy 预算口径） |
| `cost_per_hit_requests` | `(probe + scan_est) / hits`，单洞请求成本 |
| `stage_timing_s` | collect/probe/discover/scan/评分证据/总耗时 |
| `value_grades` | S/A/B/C/D 分布 |

> 扫描请求数不是逐条实测（nuclei 内部请求未逐条落审计），因此明确标注 `_estimated`。

## 2. 候选生成

### 2.1 检测模板候选（从已确认命中）

- 输入：价值分 ≥ `min_score_to_submit`、且未被标记误报的命中；
- 从证据里取：`method + path`（请求行/`matched-at`）、状态码、响应中**稳定片段**（优先 `extracted`，
  否则取响应正文中最长的非停用词 token）；
- 输出 nuclei YAML（与现有模板同格式）：`id=ah-cand-<hash>`，`matchers = status AND word`；
- 无稳定片段则跳过（不生成弱模板）。

### 2.2 指纹规则候选（从人工误报）

- 输入：`feedback.jsonl` 中带 `product + marker_type + marker_value` 的误报；
- 复用生产库里该产品的规则，追加一条 `negative` 条件（如 `body contains "repositoryformatversion"`）；
- 找不到既有规则则不生成（不臆造弱特征）。

### 2.3 人工审核门

- 所有候选写入 `workspace/recon/evolution/candidates/<timestamp>/`：
  - `templates/*.yaml`、`fingerprints/*.yaml`
  - `<id>.validation.json`（每个候选的验证结果）
  - `REVIEW.md`（待审清单：状态/来源/依据/验证 JSON）
- `approve` 前会检查 `status=passed`，否则拒绝入库。

## 3. 靶场回归（正/负样本）

| 候选类型 | 正样本 | 负样本 | 通过条件 |
|---|---|---|---|
| 模板 | 靶场正例 URL | 干净靶场 URL（不同端口、不同响应） | 正样本命中 **且** 负样本 0 命中 |
| 指纹规则 | 含该产品的页面 | 不含该产品的干净页面 | 正样本仍识别出产品 **且** 负样本不识别 |

实现：模板用 nuclei 对候选目录跑两次（正/负），解析 JSONL；
指纹规则用 requests 抓两页后交给 `FingerprintEngine` 求值。
验证只访问传入的回环地址。

## 4. 版本化与回滚

- `approve`：先快照当前规则库 → `versions/v<N>.yaml` → 追加候选 → 写 `versions/index.json`
  （版本号、动作、候选 ID、产品、备注、当时的 metrics）
- `rollback --version N`：用快照覆盖规则库，并追加一条 `action=rollback` 记录
- `evolve list`：查看历史版本与效果指标

> 仅管理指纹规则库；模板候选 `approve` 后放到 `evolution/approved_templates/`，
> 扫描是否使用由配置决定（避免自动引入未经审核的检测逻辑）。

## 5. 实测（本地靶场）

- 两条候选（1 模板 + 1 指纹规则）均 **passed**：
  - 模板：正样本命中 `/download?...`，负样本 0 命中；
  - 指纹：正样本仍识别 Nginx，负样本不识别。
- `approve` 后版本 v1 入库，`rollback v1` 后规则库恢复原状（`ah-fp-*` 规则消失）。

## 6. 限制

- 候选模板的“稳定片段”是启发式，可能选到动态内容；**必须人工看 REVIEW 再决定**；
- 指纹负条件依赖人工提供 marker，自动推断无法可靠区分“误报特征”与“正常特征”；
- 负样本只有一个干净靶场，不能覆盖所有误报形态；
- 指标中的扫描请求数是估算值，不是平台级精确计数。
