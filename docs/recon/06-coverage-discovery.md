# 06 · 覆盖扩展：URL / 路径 / 参数发现

> 目标：补上此前跳过的“发现面”能力，同时把主动行为做成可分级、可审计、默认最保守。

## 1. 设计取舍

| 决策 | 选择 | 原因 |
|---|---|---|
| 爬虫实现 | 自研轻量正则爬取（a/form/iframe/script + inline JS） | 不引入 bs4/playwright；可复现、可控、无外部依赖 |
| 并发 | 按“层”并行（同层 URL 一起请求） | 深度可控、天然去重，避免无限队列 |
| 同源限制 | 默认仅同 scheme+host，不含子域 | 防止爬出授权范围（宪法第1条） |
| 静态资源 | 扩展名黑名单（图片/字体/压缩包/音视频） | 省配额，JS 单独抓取用于端点提取 |
| 路径字典 | 内置 60 条高价值路径，按价值排序 | light 只取前 20 条；顺序即优先级 |
| 基线校准 | 先请求一个随机不存在路径，作为 404 基线 | 借鉴 ffuf `-ac`，降低“全 200”误报 |
| 历史 URL | 离线导入（`<import_dir>/<target>.urls.txt`） | 开发期不允许访问外部；gau/waybackurls 导出即可接入 |
| 在线 CDX | **未内置**，文档说明 | 外部请求不可控，且开发验证禁止访问真实资产 |

## 2. 分级参数

| 参数 | light | standard | deep |
|---|---|---|---|
| `discover_enabled` | 是 | 是 | 是 |
| `crawl_depth` | 1 | 2 | 3 |
| `crawl_max_urls` | 30 | 200 | 800 |
| `crawl_concurrency` | 2 | 4 | 8 |
| `path_scan_enabled` | 是 | 是 | 是 |
| `path_scan_max_paths` | 20 | 60 | 120 |
| `js_extract` | 是 | 是 | 是 |

全部请求经 `Prober.request()`：范围校验 → 配额登记 → 令牌桶 → 请求 → 审计，无旁路。

## 3. 产物

`workspace/recon/<target>/discovered.jsonl`（schema `recon.url/v1`）：

```json
{"url":"http://host/page","host":"host","source":"crawl","depth":1,
 "status":200,"length":312,"params":["id"],"interesting":false,"product":"致远OA"}
```

- `source`：`crawl | js | path_scan | history`
- `interesting`：路径探测中“与基线明显不同”的响应（优先送扫描）
- `params`：URL query + 表单 input 名，用于后续参数级测试

扫描阶段会把 `discovered` 的 URL 并入对应产品组（受 `scan_max_urls` 限制），
因此 nuclei 不只打首页，而是打“爬到的路径 + JS 端点 + 字典命中路径”。

## 4. 限制

- 不解析 JS 动态拼接的 URL（只做正则提取），会漏一部分前端路由；
- 不跟随跨域/子域（安全优先）；
- 历史 URL 只做离线导入，需人工把 gau/waybackurls 结果落到指定文件；
- 路径字典是通用集合，未按产品定制（可在 YAML 外自行扩展）。
