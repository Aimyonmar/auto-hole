# 08 · 批量编排、去重降噪与结构化报告

## 1. 批量编排（`batch`）

清单格式（`batch.yaml`）：

```yaml
targets:
  - file: targets/a.yaml      # 必须是带 authorization 的目标文件
    priority: 1
    daily_limit: 3000         # 单目标日请求上限（可选）
    scan: true                # 本批次是否连带扫描（默认 true）
  - file: targets/b.yaml
    priority: 2
```

调度规则：
- `load_target` 对每一项强制校验授权依据（清单外/无授权一律拒绝）；
- 按 `priority` 升序；`daily_limit` 覆盖该目标的探测/扫描配额；
- **双层配额**：单目标配额由 runner 账本执行；全局配额在调度前查询
  `recon_budget + request_counter` 当日合计，达到 `--global-daily-limit` 就不再启动新目标；
- **失败隔离**：单目标异常只记录，不中断批次；连续失败 2 次标记熔断并跳过；
- **断点续跑**：`batch-state.json` 记录已完成目标，重跑自动跳过（`--fresh` 重置）；
- **并行**：默认 1；`--max-parallel` 最多 3，并行时单目标速率按“全局 rps / 并行数”缩放；
  默认串行是为了避免 SQLite 写锁与总速率叠加。

产物：`batch-summary.json` + `batch-report.md`（目标/资产/命中/请求/耗时/状态）。

## 2. 去重与降噪（`history`）

### 2.1 历史命中库

SQLite 表 `hit_history`，key = `hash(host + 路径 + 漏洞类型)`：

- 同一漏洞重复跑：`status=reported/ignored` 的命中直接压制为 D，不再生成证据/报告；
- 同 host 同路径但不同模板、属同一漏洞类型：也视为重复（避免拆洞）；
- 新命中写库为 `new`；提交后可 `main.py history --key K --status reported`。

### 2.2 公开披露比对

`modules/recon/data/known_disclosures.yaml` 维护模板/产品清单；另外自动认为
“CVE 年份 ≤ 当前年-3”为老 Nday。命中后价值分封顶 25、默认不出证据包。

### 2.3 置信度校准与误报回收

- `feedback.jsonl` 记录人工误报（`evolve mark` 写入，含模板/主机/原因/标记）；
- `calibrate()` 按模板统计 `hits / fp / fp_rate`，当 `fp ≥ 3 且 fp_rate ≥ 50%` 时进入
  `suppressed_templates`，后续命中直接压制；
- 误报同时进入进化回路：可生成“加 negative 条件”的指纹候选（见 07）。

## 3. 结构化报告（`export`）

单条报告字段（`recon.report/v1`）：

```json
{
  "title": "[厂商][产品]存在[漏洞]漏洞",
  "severity": "critical|high|...", "risk_level": "严重|高危|...",
  "product": "...", "vendor": "...", "authorization": "...",
  "impact_scope": {"host": "...", "matched_at": "...", "product_instances": 120, "impact": "..."},
  "steps": ["..."],
  "reproduction": {"curl": "...", "request_excerpt": "...", "response_excerpt": "..."},
  "evidence": {"matched_at": "...", "matcher": "...", "extracted": [...], "request": "...", "response": "..."},
  "fix_advice": "...",
  "value": {"score": 52, "grade": "B", "advice": "...", "reasons": [...]},
  "history_status": "new|reported|ignored"
}
```

- `md` / `json` 两种格式，均附 `index.md` / `index.json` 批量清单；
- `--min-score` 只导出达到价值线的条目；
- 请求/响应统一截断 400 字符并脱敏 `Bearer`；
- 报告只落本地，提交仍为人工（宪法第6条）。

## 4. 与旧流程的关系

- `collect/scan/judge/report/run` 完全保留；新流程产物落在 `workspace/recon/`；
- `recon` 的资产仍镜像进 legacy `assets` 表，旧报告/判定可直接消费；
- `export` 是“从已有命中重新出结构化材料”，不发起请求。
