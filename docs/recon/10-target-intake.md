# 10 · 目标接入模板与预检

> 目的：用户只填必要信息，其余由程序校验；**预检不通过就不允许发任何请求**。

## 1. 字段逐项说明

| 字段 | 必填 | 为什么需要 | 填错会怎样 |
|---|---|---|---|
| `vendor` | 是 | 报告标题、档案文件名、厂商归属 | 为空 → 直接拒绝（`vendor: 厂商名不能为空`） |
| `program_url` | 是 | 补天项目页/编号，是授权链路的锚点 | 为空 → 拒绝；填非补天链接会通过格式校验但需人工确认 |
| `authorization_ref` | 是 | 真正的授权依据（项目页、报名通过记录、书面编号） | 空/纯空格 → 拒绝；只写“已授权”会被视为无效依据 |
| `scope.domains` | 是 | 待测域名清单 | 为空/全部非法 → 拒绝；通配符 `*` 单项被拒绝并列出 |
| `scope.ips` | 否 | 直接声明的 IP/CIDR（不展开） | 非法 IP → 该条被拒绝，不影响其它条目 |
| `scope.include_subdomains` | 否 | 是否纳入子域 | 填 `false` 时子域不会进入清单（预检会明确提示） |
| `scope.include_third_party` | 否 | 是否纳入第三方资产 | 填 `true` → 直接拒绝（第三方不在厂商授权范围） |
| `restrictions.raw` | 是 | 平台禁止项原文，审计留痕 | 为空 → 拒绝 |
| `restrictions.automation_allowed` | 是 | 自动化是否被允许 | `no` → 拒绝；`unstated` → 允许但提示人工确认；非法值 → 拒绝 |
| `tier` | 否 | 档位（light/standard/deep） | 非法 → 拒绝；缺省按 light |
| `test_accounts` | 否 | 测试账号，仅本地保存 | 不参与扫描，不会外发 |

## 2. 拒绝规则（硬性）

1. 必填缺失（vendor / program_url / authorization_ref / restrictions.raw / automation_allowed）。
2. `authorization_ref` 为空或纯空格。
3. `tier` 不属于 `light|standard|deep`。
4. `automation_allowed=no`（平台/厂商禁止自动化）。
5. `automation_allowed` 取值非法（只允许 yes/unstated/no）。
6. `scope.include_third_party=true`。
7. 域名条目含 `*`、空项、非法字符、或规范化后为空。
8. 规范化后没有任何有效域名/IP（范围为空）。

被拒绝的**条目**会单独列出（不影响其它合法条目）；命中第 1–6/8 条则整体失败。

## 3. 域名规范化

- 去空格、去协议（`http(s)://`）、去路径/查询、转小写；
- 去重；IP/CIDR 自动归入 `scope.ips`（CIDR 不展开）；
- 通配符一律拒绝（不做“模糊范围”）。

## 4. dry-run 输出示例

```text
[通过] 目标预检：某某科技有限公司
  文件：targets/xxx.yaml
  厂商：某某科技有限公司；项目：https://www.butian.net/Company/12345
  授权依据：项目页已报名通过
  档位：light；自动化声明：unstated
  范围：
    - a.example.com（不含子域）
  待测资产数：1（域名 1 / IP 0）
  提示：include_subdomains=false：子域不会进入清单（仅主域本身）
  被拒绝条目：
    - [scope.domains] '*.example.com'：通配符范围不允许（禁止 * 形式的模糊范围）
  计划（dry-run，未发送任何请求）：
    - 并发 3 / 速率 5.0 rps / 日配额 5000
    - 端口 2 个；扫描 关闭
    - 预估请求上限：探测 4 + 发现 128 + 扫描 0 = 132（受日配额约束）
    - 熔断：连续失败 8 次 / 冷却 60s
    - 授权依据已读入：是
[dry-run] 已输出计划，未发送任何请求、未写入文件
```

## 5. 命令

```powershell
# 预检（不写文件、不发请求）
main.py intake targets\xxx.yaml --dry-run
# 预检通过后生成可执行目标
main.py intake targets\xxx.yaml --emit targets\xxx.exec.yaml
```

## 6. 填空版（可直接复制）

```yaml
name: ""
vendor: ""
program_url: ""
authorization_ref: ""
scope:
  domains:
    - ""
  ips: []
  include_subdomains: false
  include_third_party: false
  note: ""
restrictions:
  raw: ""
  automation_allowed: "unstated"
tier: "light"
test_accounts: []
```
