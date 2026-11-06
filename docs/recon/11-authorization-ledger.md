# 11 · 授权档案：导入、清单、选择与预检串联

> 目标：把“核对授权”从用户搬到程序。用户只需导入补天项目页（本地文件/粘贴），
> 程序解析成授权档案，列出可挖目标，选择后自动预检；预检不过，一个请求都不发。

## 1. 导入格式要求

- 支持 **本地 HTML** 或 **纯文本粘贴**（`main.py import <file>` 或 `--text`）；
- **不访问补天站点**，不登录、不带 cookie；未来如加直连，必须显式开关、默认关闭、单次低速（本次不实现）；
- 解析保守：识别不到的字段不猜，直接失败并列出缺失项。

### 1.1 字段映射（正则/行标签）

| 目标字段 | 识别依据（示例） |
|---|---|
| `vendor` | `厂商名称：` / `企业名称：` / `<title>` 兜底 |
| `program_url` | `https://www.butian.net/Company/<id>` 或 `Loo/submit?cid=<id>` |
| `program_id` | `项目编号：` 或从链接中提取数字 |
| `registration_status` | `报名状态：已通过/审核中/未通过/未报名` |
| `scope.domains` | `资产范围` 标题后的列表（`<li>` / 行） |
| `restrictions.raw` | `平台禁止项` / `限制条件` 标题后的文本 |
| `automation_allowed` | 原文含“禁止…自动化/扫描/脚本”→ `no`；“允许…”→ `yes`；否则 `unstated` |

### 1.2 解析失败示例

缺厂商 → `未识别字段：vendor`，**不生成档案**；
缺资产范围 → `未识别字段：scope.domains`，不生成；
状态标签存在但值未知 → 状态记为 `unknown`，档案生成但后续 blocked。

## 2. 档案格式与回溯

写入 `targets/authorized/<厂商slug>.yaml`，除接入模板字段外新增：

```yaml
registration_status: approved
program_id: "12345"
source:
  file: "本地导出路径或 <paste>"
  imported_at: "2026-11-02T..."
  digest: "<原文 sha256 前16位>"
  excerpt: "<前200字摘要>"
```

用于回溯“这份授权是从哪来的、原文有没有被改过”。已存在同名档案默认拒绝覆盖，`--force` 才覆盖。

## 3. blocked 规则

只有同时满足以下条件才进入可执行列表：

1. `registration_status = approved`；
2. 规范化后资产范围非空；
3. 预检通过（授权依据非空、无禁止自动化、无第三方、档位合法等）。

其余标为 **blocked** 并给出原因：状态未通过/未知、范围空、禁止自动化、第三方、字段非法。

## 4. 目标清单与选择

```text
$ main.py targets

可执行目标：
序号 | 厂商 | 报名状态 | 资产数 | 上次运行 | 上次命中
1 | 某某科技有限公司 | approved | 2 | 2026-11-02T04:20 | 3

Blocked（不可执行）：
厂商 | 报名状态 | 资产数 | 原因
某待审厂商 | pending | 1 | 报名状态=pending（需 approved）
```

选择方式：
- 序号：`main.py recon -t 1`
- 厂商名/子串：`main.py recon -t 某某科技`
- 档案路径：`main.py recon -t targets/authorized/xxx.yaml`
- 批量：清单里写 `target: 1` 或 `target: 厂商名`

被 blocked 的目标被选择时，直接拒绝并打印 blocked 原因，不进入预检之后的任何动作。

## 5. 选择后的预检串联

1. 解析选择 → 规范化为可执行目标文件（写入 `workspace/recon/<target>/target.from-ledger.yaml`）；
2. 自动预检：范围规范化/去重、资产数、档位参数、预估请求上限、熔断阈值、授权依据是否读入；
3. 预检失败 → 直接终止（零请求）；
4. 预检通过 → 输出“待确认摘要”（一行一条），等待确认：
   - 交互终端：`确认执行？[y/N]`
   - 非交互环境：必须加 `--yes`，否则拒绝执行。

## 6. 安全边界

- `import` / `targets` / `resolve` / 预检全程不发起网络请求（有单测断言）；
- 只有确认后进入的 `recon/batch` 才会对档案内资产发请求；
- 档案范围外的资产仍会被运行时 `scope_reject` 拦截。
