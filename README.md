# 证物封签审计 API（evidence-audit）

各工作站在离线状态下对证物封签事件逐条登记，事后回传。由于回传顺序与实际封签顺序无关，本服务把一次请求中的事件当作**无序集合**整体审计：核对链结构（恰好一个根、前驱存在、无环、每个前驱至多一个子事件）、摘要链接（`prevDigest` 等于前驱声明的 `digest`），并**逐条重算摘要**。仅当所有事件构成一条完整单链时，才返回根到尾的事件序列与尾摘要。

纯 Go 1.23 标准库实现（`net/http`），无任何第三方依赖。

## 运行

```bash
docker compose up --build        # 构建镜像并启动 api，监听 8080
# 或本地运行（需 Go 1.23+）：
go run ./cmd/api                 # ADDR 环境变量可改监听地址，默认 :8080
```

## 摘要定义

每条事件的摘要是对以下字节序列依次拼接后取 SHA-256，小写十六进制编码（64 字符）：

```
BE32(len(id)) || id(UTF-8) || prevDigest(32 字节原始字节) || BE32(len(payload)) || payload(UTF-8)
```

- `BE32` 为 4 字节大端长度前缀；
- 根事件的 `prevDigest` 为 32 字节全零（即 64 个字符 `0`）。

审计员可不经本服务独立复算，例如用 coreutils：

```bash
{ printf '\x00\x00\x00\x06ev-000'; head -c 32 /dev/zero; \
  printf '\x00\x00\x00\x16evidence seal record 0'; } | sha256sum
# 971a33f4fd333604d60a7d551290470d242f024378fa18dc0bdb6838f2b0a636
```

该黄金向量已固化在 `internal/audit/digest_test.go` 中。

## API

### `POST /audit`

请求体（`events` 含 1–2000 条、`id` 唯一；五个字段均必填；根事件 `parentId` 为 `""`）：

```json
{
  "events": [
    {"id": "ev-000", "parentId": "",       "payload": "evidence seal record 0", "prevDigest": "0000...0000", "digest": "971a...a636"},
    {"id": "ev-001", "parentId": "ev-000", "payload": "evidence seal record 1", "prevDigest": "971a...a636", "digest": "..."}
  ]
}
```

**审计通过**（HTTP 200）——返回根到尾的事件序列与尾摘要：

```json
{
  "valid": true,
  "eventCount": 3,
  "chain": ["ev-000", "ev-001", "ev-002"],
  "tailDigest": "9038a853fd7b124620d611709e268bf07d70fe99d7da703d85a66ebee8d6fae9"
}
```

**审计未通过**（HTTP 200）——所有异常按（错误码, 事件 id）排序返回，不返回 `chain`/`tailDigest`：

```json
{
  "valid": false,
  "eventCount": 4,
  "errors": [
    {"code": "FORK", "eventId": "ev-001",
     "message": "event \"ev-001\" has 2 children (ev-001-bis, ev-002); each predecessor may have at most one"}
  ]
}
```

**请求格式错误**（HTTP 422）——JSON 无法解析、字段缺失/类型错误、未知字段、事件数量越界、id 重复或为空、摘要不是 64 位小写十六进制等：

```json
{
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "request validation failed",
    "details": ["events[0].digest: must be 64 lowercase hexadecimal characters"]
  }
}
```

请求体超过 32 MiB 返回 413；`GET /audit` 返回 405；`GET /healthz` 返回 `{"status":"ok"}`。

### 错误码

| 错误码 | 含义 | 典型损坏场景 |
|---|---|---|
| `DIGEST_MISMATCH` | 声明摘要与按 id/prevDigest/payload 重算结果不符 | 正文被改动、摘要被改动 |
| `PREV_DIGEST_MISMATCH` | `prevDigest` 不等于前驱声明的 `digest`（根事件须为全零） | 父引用改向、链接摘要被改 |
| `MISSING_PARENT` | `parentId` 指向不存在的事件 | 父引用指向已删除/编造的事件 |
| `FORK` | 同一前驱出现多个子事件 | 分叉（同一封签被登记两次） |
| `CYCLE` | 事件处于父引用环上 | 引用互相指成环 |
| `NO_ROOT` / `MULTIPLE_ROOTS` | 根事件不是恰好一个 | 根丢失或出现多条链 |
| `DUPLICATE_ID` | id 重复（防御性检查；HTTP 层已按 422 拦截） | — |
| `INVALID_DIGEST_FORMAT` | 摘要字段非 64 位小写十六进制（防御性检查；HTTP 层已按 422 拦截） | — |

三类典型篡改可被明确区分：改正文 → 仅 `DIGEST_MISMATCH`；改父引用指向不存在事件 → 仅 `MISSING_PARENT`（指向已存在事件 → `FORK` + `PREV_DIGEST_MISMATCH`）；构造摘要自洽的分叉事件 → 仅 `FORK`。

## 设计要点

- **顺序无关**：审计只依赖事件集合本身。先按 id 建索引，再做结构检查（根计数、父引用解析、子事件计数、函数图环检测），最后逐条重算摘要；结果排序后输出，同一集合任意置乱得到逐字节一致的结论（有测试覆盖）。
- **为什么这些检查充分**：每个事件至多一个父引用；若恰好一个根、所有父引用存在、无环，则沿父引用必收敛于唯一的根，整体是一棵树；再要求每个前驱至多一个子事件，树退化为一条覆盖全部事件的链。
- **结构异常与摘要异常一并收集**，便于审计员一次看清全部问题，而不是只见到第一个错误。

## 测试

```bash
go test ./...        # 全部单元测试与 HTTP 测试
go test -race ./...
```

覆盖：25 个随机种子置乱有效链仍通过且顺序还原；分别篡改正文、声明摘要、父引用（悬空/改向）、制造分叉、环、缺根、多根、非零根 prevDigest、重复 id；同一损坏集合在 20 种置乱下结论逐字节一致且按（错误码, 事件 id）排序；摘要定义逐字节独立复算 + coreutils 黄金向量；HTTP 层 422/405/边界（1 条、2000 条、2001 条）。

## 辅助工具

`cmd/chaingen` 生成一条合法链，便于手工演练（生成后自行改动字段即可制造各类损坏）：

```bash
go run ./cmd/chaingen -n 3 > chain.json
curl -s -X POST --data @chain.json http://localhost:8080/audit
```

## 目录结构

```
cmd/api/            服务入口（优雅停机）
cmd/chaingen/       合法链生成工具
internal/audit/     顺序无关的审计引擎与摘要定义
internal/httpapi/   net/http 路由、请求校验（422）、响应编码
Dockerfile          多阶段构建（构建期跑 go vet + go test）
docker-compose.yml  api 服务（含健康检查）
```
