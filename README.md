# auto-hole

> ## ⚠ ONLY FOR AUTHORIZED TESTING — 仅限获得书面授权的测试环境使用
>
> 使用本工具即表示你确认：**已取得目标所有者的明确书面授权**，且你的测试行为完全落在该授权范围内。
> 对未授权系统进行扫描、探测或验证，可能触犯《中华人民共和国刑法》第 285 条、第 286 条及《网络安全法》。
> **本仓库不附带任何授权，也不构成任何形式的授权。** 使用前请务必阅读 [法律与合规注意事项](#法律与合规注意事项)。

个人自动化漏洞挖掘工具 —— 面向补天平台（公益SRC + 通用1.0 Nday）的资产收集、指纹识别、POC 扫描、AI 误报筛查、补天格式报告生成一体化流水线。

> **宪法约束优先**：本项目一切行为受 [CONSTITUTION.md](CONSTITUTION.md) 约束（遵守法律、授权范围、禁止破坏性验证、速率红线、数据保密、防封号规则、环境隔离），宪法条款已代码化硬校验，违反即拦截。

## 快速开始（本机 Windows）

```powershell
# 1. Python 虚拟环境（宪法第7条：全部装进项目 .venv，零系统污染）
powershell -ExecutionPolicy Bypass -File setup_env.ps1

# 2. 工具链下载（nuclei/subfinder/httpx/dnsx + 14000+ 模板，全落 tools/ 目录）
powershell -ExecutionPolicy Bypass -File tools\setup_tools.ps1

# 3. 填写配置
copy config.example.yaml config.yaml   # 首次 doctor 会自动生成
# 编辑 config.yaml：hunter.api_key（鹰图）+ llm.api_key（GLM）

# 4. 自检
.venv\Scripts\python.exe main.py doctor
```

## 使用

```powershell
# 定义授权目标（宪法第1条：authorization 必填，否则拒绝执行）
# 参照 targets/example.yaml 创建 targets/myvendor.yaml

.venv\Scripts\python.exe main.py collect -t targets\myvendor.yaml   # 资产收集
.venv\Scripts\python.exe main.py scan    -t targets\myvendor.yaml   # nuclei POC 扫描
.venv\Scripts\python.exe main.py judge   -t targets\myvendor.yaml   # AI 误报筛查+价值预估
.venv\Scripts\python.exe main.py report  -t targets\myvendor.yaml   # 生成补天格式报告
.venv\Scripts\python.exe main.py run     -t targets\myvendor.yaml   # 一键全流程
```

### 增强采集（recon，可选）

插件化数据源 + 规则化指纹 + 自适应限速 + 断点续跑 + **价值评分/证据包**，默认温和档（并发 8 / 20 rps）。

```powershell
# 独立环境（隔离依赖，不污染主 .venv）
python -m venv .venv-recon
.venv-recon\Scripts\python.exe -m pip install -r requirements-recon.txt

.venv-recon\Scripts\python.exe main.py recon -t targets\myvendor.yaml --profile light   # 首次：轻量档
.venv-recon\Scripts\python.exe main.py recon -t targets\myvendor.yaml                  # 采集+探测+发现+指纹
.venv-recon\Scripts\python.exe main.py recon -t targets\myvendor.yaml --stage discover # URL/路径/参数发现
.venv-recon\Scripts\python.exe main.py recon -t targets\myvendor.yaml --stage scan     # 按产品分组定向扫描
.venv-recon\Scripts\python.exe main.py recon -t targets\myvendor.yaml --stage evidence # 只给高价值命中出证据包
.venv-recon\Scripts\python.exe main.py recon -t targets\myvendor.yaml --stage status   # 看进度/清单
.venv-recon\Scripts\python.exe main.py recon -t targets\myvendor.yaml --profile deep    # 深度档（含分级扫描）

# 目标体检：只做侦察/研判，零 nuclei/模板扫描；默认每目标 60 次请求
.venv-recon\Scripts\python.exe main.py triage -t targets\authorized\xxx.yaml
.venv-recon\Scripts\python.exe main.py triage -t targets\authorized\xxx.yaml --max-requests 40
# 结果：<state>/<target>/triage.md + triage.json；面板「目标体检」页可提交并导出

# 只读越权检测（IDOR / 水平 + 垂直；代码只发 GET，不实现写方法）
# 账号明文 YAML 只用于导入，导入后 cookie/header 写入 Fernet 加密库
.venv-recon\Scripts\python.exe main.py authz -t targets\authorized\xxx.yaml --accounts accounts.yaml --prepare-only
.venv-recon\Scripts\python.exe main.py authz -t targets\authorized\xxx.yaml
.venv-recon\Scripts\python.exe main.py recon -t targets\authorized\xxx.yaml --stage authz
# 结果：<state>/<target>/authz.jsonl|authz-summary.json|authz-report.md
# 加密库：workspace/authz/vault.enc；密钥：workspace/authz/vault.key（Windows ACL 限当前用户）
# 面板：新建任务页勾选「只读越权检测」，填写 A/B 身份；结果页「越权检测」并排展示 A/B 响应

# 目标接入：模板预检（不发请求）
.venv-recon\Scripts\python.exe main.py intake targets\_template.yaml --dry-run
# 导入补天项目页（本地 HTML/文本）→ targets/authorized/<厂商>.yaml
.venv-recon\Scripts\python.exe main.py import project.html
# 可挖目标清单（序号/厂商选择；blocked 会给出原因）
.venv-recon\Scripts\python.exe main.py targets
# 选择 + 预检确认（非交互环境必须把 --yes 放在子命令前）
.venv-recon\Scripts\python.exe main.py --yes recon -t 1 --stage status
.venv-recon\Scripts\python.exe main.py --yes recon -t 1 --profile light

# 本地只读桌面控制台（pywebview + WebView2，不启动浏览器）
# 双击 dist\AutoHoleDashboard\AutoHoleDashboard.exe 即可（单窗口、随机回环端口）
# 新建任务页可直接提交资产：校验 → 写 targets/authorized → 串行队列 → 子进程执行 batch
# 目标体检页：只做侦察/研判，零 nuclei 扫描；默认请求 60，结果可导出 triage.md/json
# 表单拒绝：缺授权依据 / 范围为空 / 通配符 / 含第三方 / automation=no / 未勾选确认 / tier 非 light|standard
# 越权检测需 >=2 个身份；单账号拒绝；会话预检失败会直接失败，不进入重放
# 同一时间只跑一个任务，其余显示队列位置；排队与运行中均可取消（终止进程树）
# 写接口要求本地 token + 同源 Origin；无 token 或跨源 → 403
# 任务队列：workspace/jobs.db；任务日志：logs/jobs/<id>.log；审计：logs/dashboard-audit.jsonl
# 打包版首次启动自动生成 config.yaml / config/recon.yaml（不含任何凭据）
# 启动日志：dist\AutoHoleDashboard\logs\startup.log
# 二次启动会前置已有窗口，不会重复起服务
# 开发/排查：只起服务（不开窗口）
.venv-recon\Scripts\python.exe dashboard_server.py --server-only --port 8080
# 服务自检 / 窗口自检
.venv-recon\Scripts\python.exe dashboard_server.py --selftest
.venv-recon\Scripts\python.exe dashboard_server.py --selftest-window
# 重建（含 main/core/modules.recon + nuclei + 1.4 万条模板）：.venv-recon\Scripts\pyinstaller.exe dashboard.spec --noconfirm --clean
# 产物约 255 MB（含 cryptography 凭据加密）；打包态 recon 数据源使用静态导入，避免冻结后动态 import 丢模块

# 跨目标产品盘点：通用1.0 的“同产品公网实例 ≥100”达标统计（不发请求）
.venv-recon\Scripts\python.exe main.py inventory --min-instances 100
# 外部资产清单补量：workspace/import/<目标名>.txt（host / host:port / URL / CSV）
# 历史 URL 离线导入：workspace/import/<目标名>.urls.txt（gau/waybackurls 导出）

# 批量编排（授权清单、优先级、双层配额、失败隔离、断点续跑）
.venv-recon\Scripts\python.exe main.py batch -m batch.yaml --profile light
# 进化回路：误报标记 → 候选生成/靶场回归 → 人工入库/回滚
.venv-recon\Scripts\python.exe main.py evolve --action mark -t targets\x.yaml --template-id T --host H --product P --marker-type body --marker-value V
.venv-recon\Scripts\python.exe main.py evolve --action propose -t targets\x.yaml --lab-positive http://127.0.0.1:18090/ --lab-negative http://127.0.0.1:18091/
.venv-recon\Scripts\python.exe main.py evolve --action approve -t targets\x.yaml --candidate-dir DIR --candidate-id ID
.venv-recon\Scripts\python.exe main.py evolve --action rollback --version 1
# 结构化报告导出（单条 + 批量清单）
.venv-recon\Scripts\python.exe main.py export -t targets\x.yaml --format md --min-score 45
# 历史命中状态（去重生命周期）
.venv-recon\Scripts\python.exe main.py history --key KEY --status reported
```

产物在 `workspace/recon/<target>/`：`assets.jsonl`（标准 schema）、`findings.jsonl`（含价值分）、
`summary.json`、`report.md`、`evidence/`（提交级证据包）；逐请求审计在 `workspace/recon/audit.jsonl`。
跨目标盘点输出 `workspace/recon/inventory.md`。详细设计与调研见 [docs/recon/](docs/recon/)，
只读越权检测见 [13-authz-testing.md](docs/recon/13-authz-testing.md)，
目标体检见 [14-triage.md](docs/recon/14-triage.md)，
变现口径与价值模型见 [05-value-playbook.md](docs/recon/05-value-playbook.md)。

报告输出到 `reports/`，**人工审阅后手动提交补天**（宪法第6条：工具永不自动提交）。

## 架构

```
授权目标(targets/*.yaml) → [宪法守门] → Hunter资产+subfinder子域 → httpx存活指纹
  → 指纹归一化(对齐补天产品名) → nuclei扫描(tags/severity过滤+定向模板+去重)
  → GLM误报筛查+价值预估(补天评分口径) → 补天格式报告(本地)
```

| 模块 | 说明 |
|---|---|
| [core/constitution.py](core/constitution.py) | 宪法执行器：授权范围校验、单目标日熔断 |
| [core/hunter.py](core/hunter.py) | 鹰图 API：资产拉取、配额监控 |
| [core/subdomain.py](core/subdomain.py) | subfinder/dnsx/httpx 编排（隔离环境运行） |
| [core/fingerprint.py](core/fingerprint.py) | 国产产品指纹归一化（致远OA/通达OA/泛微等补天收录产品） |
| [core/scanner.py](core/scanner.py) | nuclei 编排：宪法第2/3条参数化（禁dos/fuzz、写入类POC过滤、并发≤20） |
| [core/ai.py](core/ai.py) | GLM：误报筛查、价值预估、去重辅助 |
| [core/report.py](core/report.py) | 补天报告：[厂商]+[产品]+存在[漏洞名]漏洞 格式 |
| [core/db.py](core/db.py) | SQLite：资产/发现/去重/提交标记 |

## 服务器部署（Linux）

```bash
bash setup_env.sh && bash tools/setup_tools.sh
cp config.example.yaml config.yaml   # 填 key
# 定时任务：systemd --user（见 deploy/autohole.timer，每天 02:00）
```

## 测试

```powershell
.venv\Scripts\python.exe tests\test_constitution.py   # 宪法负向测试（15项）
.venv\Scripts\python.exe tests\test_smoke_local.py    # 本地全链路冒烟（零外部请求）
```

## 法律与合规注意事项

> 本节不是法律意见，不构成对任何具体行为的合法性背书。如有疑问，请咨询执业律师。

### 1. 未授权扫描 / 入侵的法律风险

- **《中华人民共和国网络安全法》**：第二十七条禁止任何个人和组织从事非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络安全的活动；第六十三条规定，尚不构成犯罪的，由公安机关没收违法所得、处拘留并处罚款。第二十一条、第四十一条等对网络运营者的数据安全义务同样构成本工具使用者必须自行评估的边界。
- **《中华人民共和国刑法》第二百八十五条**（非法侵入计算机信息系统罪 / 非法获取计算机信息系统数据、非法控制计算机信息系统罪）：违反国家规定，侵入国家事务、国防建设、尖端科学技术领域的计算机信息系统，或侵入其他计算机信息系统、获取该计算机信息系统中存储、处理或者传输的数据，或对该计算机信息系统实施非法控制，情节严重的，处三年以下有期徒刑或者拘役，并处或者单处罚金；情节特别严重的，处三年以上七年以下有期徒刑，并处罚金。提供专门用于侵入、非法控制计算机信息系统的程序、工具，或者明知他人实施侵入、非法控制计算机信息系统的违法犯罪行为而为其提供程序、工具，情节严重的，同样依照该条处罚。
- **《中华人民共和国刑法》第二百八十六条**（破坏计算机信息系统罪）：对计算机信息系统功能进行删除、修改、增加、干扰，造成计算机信息系统不能正常运行，后果严重的，处五年以下有期徒刑或者拘役；后果特别严重的，处五年以上有期徒刑。故意制作、传播计算机病毒等破坏性程序，影响计算机系统正常运行，后果严重的，同样依照该条处罚。
- **《中华人民共和国治安管理处罚法》** 及《数据安全法》《个人信息保护法》也可能适用于未授权访问、数据读取与个人信息处理行为。
- 即使只做"只读"探测、只发一个请求、只读取 1 条数据，只要**没有授权**，仍可能被认定为"侵入"或"非法获取数据"。工具刻意实现的限速、只读取证、禁 dos/fuzz 等约束，**不能**把未授权行为变成合法行为。

### 2. 工具公开后被滥用的可能

- 本项目属于典型的**双用途（dual-use）**安全工具：同一套采集、指纹与模板调度能力既可用于授权测试，也可被用于未授权扫描。
- 作者**无法控制、也不认可**任何下游的未授权使用；公开代码不等于公开授权，也不构成对滥用行为的帮助或纵容。
- 仓库刻意**不包含**任何真实扫描目标、有效凭据、扫描产物与针对真实系统的漏洞证据，以降低被直接用于攻击的可能；但这不能消除工具本身被误用或改造的风险。
- 若你基于本项目二次开发，请自行承担合规责任，并保留同等的限制与免责声明。

### 3. SRC 平台规则与厂商授权范围

- 本项目面向补天（butian.net）等 SRC 平台的公开测试场景，但**平台的收录规则不等于无限制授权**：
  - 需按平台要求完成注册、实名、报名等流程，且仅对**该厂商页面明确列出的资产范围**有效；
  - 厂商可附加更严格的规则（例如"禁止使用高并发、自动化扫描等影响系统稳定性的扫描器和辅助测试脚本"）——**厂商规则优先**，与本工具能力冲突时必须以厂商规则为准，不得使用本工具；
  - 超出登记域名/IP 范围的资产、第三方托管资产、关联但未列入范围的系统，均**不在授权内**；
  - 违反平台规则会导致账号封禁与漏洞不予收录，违反法律则另需承担法律责任。
- 本工具的 `targets/_template.yaml` 中 `restrictions.automation_allowed` 支持 `no`，用于在厂商明确禁止自动化时直接拒绝执行。

### 4. "授权目标清单"不等于授权证明

- 仓库中的 `targets/example.yaml`、`targets/_template.yaml` 仅用于说明字段格式，其中的域名（如 `example.com`）为**保留示例域名**，不是可扫描目标。
- 真实厂商目标清单（域名、IP、CIDR）**不会**随仓库公开。即使某厂商被公开 SRC 平台"收录"，也只代表该平台受理该厂商的漏洞报告，**不代表**你有权对其发起自动化扫描。
- 你在本地 `targets/*.yaml` 中填写的 `authorization` 字段只是**自我声明**，工具无法验证其真实性。填写了链接不等于获得了授权；伪造、夸大或引用过期授权，法律后果由填写者自行承担。
- 因此：**清单 ≠ 授权，配置 ≠ 授权，平台收录 ≠ 授权。** 唯一有效的是目标所有者（或有权处分者）出具的、覆盖你具体测试行为的书面授权。

### 5. 免责声明与使用前提

- 本工具**仅限**在你已获得书面授权的环境中使用，包括自有系统、明确的授权测试环境、以及 SRC 平台规则允许且你已合规报名的范围。
- 使用者应自行确认：目标在授权范围内、测试方法被允许、速率与时段符合要求、数据处置符合约定。
- 作者与贡献者不对任何直接或间接损害、法律责任、账号处罚、数据泄露或第三方索赔承担责任；软件按"现状"提供，不附带任何明示或默示担保。
- 发现漏洞后，请按平台规则与法律法规处置：不公开传播、不向第三方披露、不超出必要范围读取数据。
- 若你不确定自己的行为是否合法，**请立即停止使用**。

## 许可协议

本项目采用 **GNU Affero General Public License v3.0（AGPL-3.0）** 发布，全文见 [LICENSE](LICENSE)。

- 允许自由使用、修改、分发，但**衍生作品必须以同一协议开源**，不得闭源商用；
- 第 13 条"远程网络交互"条款覆盖 SaaS / 托管服务场景：即使只通过网络提供服务而不分发软件，也必须向使用者提供对应源码；
- 不提供任何担保，作者不承担使用后果。

## 收益说明（现实预期）

- 公益SRC：KB 为主 + 部分现金；通用1.0：需公网独立IP ≥100，按危害/行业/时间跨度定价（参考案例：niushop 任意文件上传 ¥3,400）
- 工具价值 = 批量效率 × Nday 模板覆盖 × AI 误报过滤；**不保证收入**，竞争与厂商收录策略影响实际收益
