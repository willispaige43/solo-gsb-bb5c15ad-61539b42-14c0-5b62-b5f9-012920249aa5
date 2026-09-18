# CIDR 地址租约 API

基于 **Python + FastAPI + SQLite + 标准库 `ipaddress`** 的本地 CIDR 地址租约服务。
支持 IPv4 / IPv6 地址池、保留网段、事务化租约分配、续租/释放、过期自动回收、
租约跨池迁移、租约控制权交接（一次性领取码），空闲空间的最简 CIDR 集合查询，
以及哈希链式租约审计日志。

## 快速启动（单条命令）

```bash
docker compose up -d --build
```

服务监听 **8000 端口**，API 根地址：`http://localhost:8000`

- 交互式文档（Swagger UI）：<http://localhost:8000/docs>
- 健康检查：<http://localhost:8000/health>

数据持久化在 Docker volume `cidr-data`（容器内 `/data/cidr.db`）。

> 不使用 Docker 时：`pip install -r requirements.txt && uvicorn app.main:app --port 8000`
> （可用环境变量 `CIDR_DB_PATH` 指定 SQLite 文件路径，默认 `/data/cidr.db`）。

## 分配语义

- 申请指定前缀长度时，从地址池的**当前空闲空间**中选择**起始地址最小**的合法
  （按自身大小对齐的）CIDR 返回。
- 整个分配在单个 `BEGIN IMMEDIATE` 事务内完成：SQLite 写锁在计算前即获取，
  并发请求在数据库层串行化，**绝不会得到重叠网段**；空间不足返回 `409`。
- 租约返回唯一随机令牌（`secrets.token_urlsafe(32)`），用于续租与释放。
- 租约过期后其网段**自动回收**（惰性回收：在写事务或列表查询时标记），
  旧令牌的一切操作返回 **409 Conflict**；主动释放后旧令牌同样返回 409。
- 以下情况返回 **422 Unprocessable Entity**：
  非规范网段（带主机位，如 `10.0.0.5/24`）、地址族与池不一致（IPv4 池传 IPv6）、
  网段越出地址池边界、前缀长度不合法。
- 查询池详情返回活动租约、保留段，以及把所有空闲空间合并后的**最简 CIDR 集合**
  （相邻块合并、每段贪心取最大对齐块）。

## 租约原地缩扩容

`PUT /leases/{token}/resize`，请求体 `{"target_prefix_len": <int>}`：

- 仅**活动租约**可操作；已释放/过期租约返回 `409`，未知令牌返回 `404`。
- **缩容**（目标前缀更长）：保留原起始地址所在的**低地址子网**，其余空间
  立即回到池中可再分配。
- **扩容**（目标前缀更短）：取**唯一包住当前网段**的目标超网；仅当其仍位于
  原池内、且不与保留段或其他活动租约重叠时成功，否则返回 `409`。
- 目标前缀等于当前前缀时直接返回当前租约，**不**追加审计事件。
- 非法前缀（负数、超过地址族长度：IPv4 > 32、IPv6 > 128）返回 `422`。
- 成功后 **token 与到期时间不变**；过期清理、冲突检查、网段更新与追加
  `resize` 审计事件都在**同一个 `BEGIN IMMEDIATE` 事务**内完成，
  失败整体回滚、不留事件。

## 租约跨池迁移

`POST /leases/{token}/migrate`，请求体 `{"target_pool_id": <int>}`，把一个
活动租约从当前地址池**整体迁移**到另一个池：

- 仅**活动租约**可迁移；已释放/过期租约返回 `409`，未知令牌返回 `404`。
- 源池与目标池**必须不同**，且**地址族一致**（同为 IPv4 或同为 IPv6），
  否则返回 `422`；目标池不存在返回 `404`。
- 新网段取租约**当前前缀长度**在目标池空闲空间中**起始地址最小**的合法 CIDR；
  目标池无容纳空间返回 `409`。
- 迁移在**同一个 `BEGIN IMMEDIATE` 事务**内完成：过期清理、两池占用计算、
  租约行更新与追加 `migrate` 审计事件一并提交，**失败整体回滚，两池状态均
  不改变、不留事件**。
- 迁移成功后：租约 **`id`、`token`、`expires_at` 保持不变**，源网段**立即释放**
  回源池（可马上再分配），租约归属目标池、持有新网段。
- 成功时追加一条 `migrate` 审计事件：事件 `pool_id`/`cidr` 使用**目标池与目标
  网段**，`details` 记录 `source_pool_id`、`target_pool_id`、`before_cidr`、
  `after_cidr`。

## 租约控制权交接

两步即可把租约控制权移交给另一方，无需让对方知晓旧令牌（服务监听 **8000 端口**）：

1. **签发**：当前持有方调用 `POST /leases/{token}/handoffs`
   （可带 `{"ttl_seconds": <1~3600>}`，默认 300 秒），为**活动租约**签发一个
   随机 `claim_code`，响应返回该码及 `expires_at`。数据库只保存交接码的
   **SHA-256 摘要**，不明文落库；同一租约再次签发会使旧码立即失效（superseded）。
   非活动租约（已释放/已过期）返回 `409`，未知令牌返回 `404`。
2. **领取**：接收方在有效期内调用 `POST /lease-handoffs/{claim_code}/claim`，
   在**同一个 `BEGIN IMMEDIATE` 事务**内消费交接码、**轮换租约 token** 并返回租约
   （**CIDR 与到期时间不变**），同事务追加一条 `handoff` 审计事件。

- 领取成功后**旧 token 立即失效**，此后按未知令牌返回 `404`；新 token 仅随
  领取响应返回一次。
- 并发领取同一交接码：仅一个请求成功，其余返回 `409`；交接码**过期、已消费、
  已被新码替换**，或**租约已非活动**同样返回 `409`；从未签发的交接码返回 `404`。
- 签发与领取的失败均**不追加审计事件**；响应与审计日志都不包含交接码摘要。

## API 一览

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/pools` | 创建地址池 |
| GET | `/pools` | 列出所有地址池 |
| GET | `/pools/{id}` | 池详情：保留段、活动租约、合并后的空闲 CIDR |
| POST | `/pools/{id}/reservations` | 声明保留网段 |
| GET | `/pools/{id}/reservations` | 列出保留网段 |
| POST | `/pools/{id}/leases` | 按前缀长度申请租约（默认 TTL 3600 秒） |
| GET | `/leases?pool_id=` | 列出活动租约（可按池过滤） |
| GET | `/leases/{token}` | 查询单个租约 |
| POST | `/leases/{token}/renew` | 续租 |
| POST | `/leases/{token}/release` | 主动释放 |
| PUT | `/leases/{token}/resize` | 原地缩/扩容（仅活动租约） |
| POST | `/leases/{token}/migrate` | 跨池迁移（同族不同池，保留 id/token/到期时间） |
| POST | `/leases/{token}/handoffs` | 签发租约交接码（有效期 1~3600 秒，默认 300） |
| POST | `/lease-handoffs/{claim_code}/claim` | 凭交接码领取租约（轮换 token） |
| GET | `/audit/events` | 按 `seq` 升序列出租约审计事件 |
| GET | `/audit/verify` | 校验审计链，返回 `valid` 与首个 `invalid_seq` |

状态码：成功 `200/201`；找不到资源 `404`；语义冲突（重叠、空间不足、
令牌已失效）`409`；格式/边界/族不一致 `422`。

## 调用示例

```bash
# 1) 创建 IPv4 地址池
curl -s -X POST http://localhost:8000/pools \
  -H 'Content-Type: application/json' \
  -d '{"name":"office","cidr":"10.0.0.0/24"}'
# {"id":1,"name":"office","cidr":"10.0.0.0/24","version":4,"created_at":...}

# 2) 声明保留网段（网关、设备区）
curl -s -X POST http://localhost:8000/pools/1/reservations \
  -H 'Content-Type: application/json' \
  -d '{"cidr":"10.0.0.0/26","description":"gateways & infra"}'

# 3) 申请一个 /27（从最小可用地址开始：10.0.0.64/27）
curl -s -X POST http://localhost:8000/pools/1/leases \
  -H 'Content-Type: application/json' \
  -d '{"prefix_len":27,"ttl_seconds":3600}'
# {"id":1,...,"cidr":"10.0.0.64/27","token":"<TOKEN>","status":"active",...}

# 4) 查看池详情：保留段、活动租约、合并后的空闲空间
curl -s http://localhost:8000/pools/1
# {"pool":...,"reservations":[...],
#  "active_leases":[{"cidr":"10.0.0.64/27",...}],
#  "free_cidrs":["10.0.0.96/27","10.0.0.128/25"]}

# 5) 续租（过期时间 = 当前时间 + 新 TTL）
curl -s -X POST http://localhost:8000/leases/<TOKEN>/renew \
  -H 'Content-Type: application/json' -d '{"ttl_seconds":7200}'

# 6) 主动释放（网段立即回到空闲空间，旧令牌此后返回 409）
curl -s -X POST http://localhost:8000/leases/<TOKEN>/release

# 6b) 原地扩容 /27 → /26（唯一包住当前网段的超网；token 与到期时间不变）
curl -s -X PUT http://localhost:8000/leases/<TOKEN>/resize \
  -H 'Content-Type: application/json' -d '{"target_prefix_len":26}'

# 6c) 原地缩容 /27 → /29（保留低地址子网，其余空间回到池中）
curl -s -X PUT http://localhost:8000/leases/<TOKEN>/resize \
  -H 'Content-Type: application/json' -d '{"target_prefix_len":29}'

# 6d) 跨池迁移到池 2（同族不同池；id/token/到期时间不变，源网段立即释放）
curl -s -X POST http://localhost:8000/leases/<TOKEN>/migrate \
  -H 'Content-Type: application/json' -d '{"target_pool_id":2}'
# {"id":1,...,"pool_id":2,"cidr":"192.168.0.0/29",...,"token":"<TOKEN>",...}

# 6e) 交接第一步：持有方为活动租约签发交接码（有效期 600 秒）
curl -s -X POST http://localhost:8000/leases/<TOKEN>/handoffs \
  -H 'Content-Type: application/json' -d '{"ttl_seconds":600}'
# {"claim_code":"<CLAIM_CODE>","expires_at":...}

# 6f) 交接第二步：接收方凭交接码领取租约（token 轮换，CIDR/到期时间不变）
curl -s -X POST http://localhost:8000/lease-handoffs/<CLAIM_CODE>/claim
# {"id":1,...,"token":"<NEW_TOKEN>",...}  —— 旧 TOKEN 此后按未知令牌返回 404

# 7) 查看审计链：allocate → renew → release 各一条事件
curl -s http://localhost:8000/audit/events

# 8) 校验审计链完整性
curl -s http://localhost:8000/audit/verify
# {"valid":true,"invalid_seq":null}
```

IPv6 用法完全相同：

```bash
curl -s -X POST http://localhost:8000/pools \
  -H 'Content-Type: application/json' \
  -d '{"name":"v6","cidr":"2001:db8::/32"}'

curl -s -X POST http://localhost:8000/pools/2/leases \
  -H 'Content-Type: application/json' -d '{"prefix_len":64}'
# 首个分配为 2001:db8:1::/64（若 2001:db8::/48 已被保留）
```

## 租约审计链

租约**分配、续租、释放、过期回收、缩扩容、跨池迁移、控制权交接**成功时，会在
**同一个 `BEGIN IMMEDIATE` 事务**内向 `audit_events` 表追加一条事件；操作失败
（409/422/404 等）事务回滚，**不会留下任何事件**。

每条事件包含：

| 字段 | 说明 |
|---|---|
| `seq` | 从 1 开始连续递增的序号（写锁内分配，并发安全） |
| `action` | `allocate` / `renew` / `release` / `expire` / `resize` / `migrate` / `handoff` |
| `lease_id` / `pool_id` | 租约与地址池标识（`migrate` 事件为目标池） |
| `cidr` | 租约网段（`resize` 事件为变更后的网段；`migrate` 事件为目标网段） |
| `occurred_at` | 事件时间（Unix 秒） |
| `details` | 详情 JSON（如 `prefix_len`、`ttl_seconds`、`expires_at`；`resize` 事件记录 `before_cidr` / `after_cidr`；`migrate` 事件记录源/目标池 ID 与迁移前后 CIDR） |
| `prev_hash` | 上一条事件的 `hash`；首条为 64 个 `0` |
| `hash` | 本事件摘要 |

`hash` 计算方式：将 `prev_hash` 文本与**除 `prev_hash`、`hash` 外全部字段**的
规范 JSON（按键排序、紧凑分隔符、UTF-8）拼接后计算 **SHA-256**：

```
hash = SHA256( prev_hash || json_sorted_compact(seq, action, lease_id,
               pool_id, cidr, occurred_at, details) )
```

- `GET /audit/events` — 按 `seq` 升序返回全部事件。
- `GET /audit/verify` — 重放整条链（序号连续、`prev_hash` 链接、逐条重算哈希），
  返回 `{"valid": true, "invalid_seq": null}`；若被篡改，返回 `valid: false`
  及首个失效事件的 `invalid_seq`。

> 审计日志不包含租约令牌（token）、交接码及其摘要，避免凭据经只读接口泄露。

## 测试

```bash
pip install pytest httpx
pytest -q
```

测试覆盖：最小起始地址分配、空闲合并表示、保留段冲突、越界/族不一致/非规范拒绝、
空间耗尽 409、续租、释放、TTL 过期回收、旧令牌 409、IPv6，以及 12 线程并发申请
`/29` 池中 8 个 `/32`（恰好 8 个成功且互不重叠，其余 409）。
缩扩容覆盖：缩容保留低地址子网且 token/到期时间不变、扩容取唯一超网、
扩容与活动租约/保留段/池边界冲突 409、非法前缀 422、同前缀幂等不写事件、
非活动租约 409、IPv6 双向调整。
跨池迁移覆盖：起始地址最小选取、源网段立即释放可再分配、保留 id/token/
到期时间、同池 422、族不一致 422、目标池不存在 404、请求体校验 422、
目标无空间/前缀放不下 409 且两池状态不变、已释放/已过期租约 409、
失败不写事件、IPv6、迁移后续租仍归属目标池、`migrate` 审计事件与链完整性。
审计链覆盖：各类事件记录与哈希链接、失败操作不记录、过期回收事件、
空链有效，以及篡改事件内容 / 破坏 `prev_hash` 链接时 `verify` 能定位首个失效 `seq`。
交接覆盖：签发 TTL 边界（1~3600，默认 300）、重复签发使旧码失效、领取轮换 token
且 CIDR/到期时间不变、旧 token 按未知令牌 404、过期/已消费/被替换/租约非活动 409、
8 线程并发领取同一交接码仅 1 个成功、`handoff` 审计事件与链完整性、
响应与日志不含交接码摘要。
另已在 `uvicorn --workers 2` 多进程部署下验证 32 并发分配 `/24` 池中的 `/28`
（16 个成功、块唯一且不重叠）。

## 项目结构

```
app/
  main.py      # FastAPI 路由与异常渲染
  service.py   # 业务逻辑（全部写操作在 BEGIN IMMEDIATE 事务内）
  audit.py     # 审计链：事件追加、规范 JSON、SHA-256 哈希链、验链
  iputil.py    # ipaddress 封装：区间运算、最小起始分配、空闲合并
  db.py        # SQLite 连接、WAL、schema
  schemas.py   # Pydantic 模型
  errors.py    # ApiError（404/409/422）
tests/
  test_api.py
Dockerfile
docker-compose.yml
requirements.txt
```

## 设计说明

- 地址区间统一表示为半开整数区间 `[start, end)`，IPv4/IPv6 共用一套算法；
  为容纳 128 位 IPv6 整数，SQLite 中以 **TEXT（十进制）** 存储起止地址。
- 选择最小合法 CIDR 时不枚举子网：空闲区间按起始地址排序，取第一个宽度足够的
  区间并向上对齐到所请求块大小，时间复杂度仅与占用记录数相关。
- 过期判定为惰性：写操作在事务内把本池过期租约置为 `expired`；读接口若检测到
  过期记录才取一次写锁，避免只读查询长期加锁。
- 审计事件与状态变更同事务提交，`seq` 在写锁内按 `MAX(seq)+1` 分配，因此链上
  序号连续无空洞；验链为纯只读操作，不加写锁。
- 交接码（`claim_code`）仅在签发响应中明文出现一次，数据库只存其 SHA-256 摘要；
  领取在单个写事务内完成「校验 → 消费 → 轮换 token → 追加 `handoff` 事件」，
  与租约分配共用同一把 SQLite 写锁，并发领取天然串行化。
