# lab.test 主从权威 DNS（Python / FastAPI / SQLite）

网络管理员批量更新 `lab.test` 仪器地址的最小可用主从权威 DNS，支持**按请求源
IPv4 网段区分的 A 记录视图**：同名仪器接入两处隔离网时，不同网段的查询得到各自
网段的地址，其余查询仍得到公共地址。

- **主节点**（`dnslab/master_app.py`）：通过 HTTP API（Swagger UI 在 `/docs`）维护
  公共 A 记录全集和每个网段的**地址覆盖清单**（视图）；每次发布（单条增删改、整体
  批量替换、视图增删改）在**一个 SQLite 事务**内完成变更、SOA 序列号递增（从 1 开始
  每次 +1）、并落一份带 SHA-256 校验和的**不可变快照**——**网段规则与地址随区域一起
  换版**。
- **从节点**（`dnslab/slave_app.py`）：经 HTTP 从主节点拉取整份快照，校验通过且序列号
  严格更新后才生效；以 UDP 回答 `A` / `SOA` 查询，按查询源 IP 做**最长前缀匹配**选中
  视图；对域内不存在的名字回答 `NXDOMAIN`（authority 带本版 SOA），域外查询 `REFUSED`。

## 视图语义

- 每个视图 = 一个客户端 IPv4 网段（CIDR）+ 该网段的名字覆盖清单。
- 一次查询**至多选中一个视图**：包含查询源 IP 的网段中**前缀最长**者；重叠网段
  （如 `10.0.0.0/8` 与 `10.1.0.0/16`）因此自然分层。
- 选中视图中**被覆盖**的名字回答视图地址与 TTL；**未覆盖**的名字回退公共记录；
  **未匹配任何网段**的查询同样使用公共记录。
- 视图只覆盖、不屏蔽：公共记录对所有网段可见，除非被选中视图显式覆盖；视图中
  独有的名字只对该网段解析，其他网段得到 `NXDOMAIN`。
- **撤销**一处覆盖（删单条或删整个视图）后，该网段只回退到公共地址——选中视图
  由源网段唯一决定，绝不会取到另一处网段的地址。
- 视图只影响 `A` 应答；`SOA` 与否定应答（`NXDOMAIN`/`NODATA`）与视图无关，照常工作。

## 一致性保证

| 场景 | 行为 |
|---|---|
| 发布与拉取交错 | 快照是主节点单事务读出的不可变版本；从节点要么整体应用某版本，要么不应用 |
| 视图与记录同版 | 视图规则和公共记录在同一事务换版、同属一份快照；每条应答由同一个不可变 `ZoneData` 生成，规则、记录、SOA 序列号同属一版 |
| 并发同步 | 从节点同步串行化；应用前在锁内复查序列号，最终版本一定是见过的最大序列号 |
| 中途断流 / 数据被改 | 传输中断 → 拉取报错；SHA-256 校验失败（校验和覆盖视图规则）→ 拒绝；现役版本不受影响 |
| 迟到旧版 | 序列号 ≤ 现役版本的一律拒绝（`applied: false`），不会覆盖新版 |
| 发布失败 | 非法 CIDR/名字/地址在事务开始前被拒绝，序列号不变；主从都继续用上一成功版本 |
| 主节点失联 | 从节点继续用最后一次成功同步的版本应答（含视图）；`/sync` 报 502 但不影响应答 |
| 从节点重启 | 启动时从 SQLite 恢复最后成功版本（含视图规则），无需先同步即可应答 |
| 初次同步失败 | 没有任何版本时回答 `SERVFAIL`（不可用），绝不凭空应答 |

## 快照格式与兼容

- **v2**：`{zone, serial, soa, records, views, sha256}`，`views` 参与校验和。
- **v1（旧格式）**：`{zone, serial, soa, records, sha256}`。新从节点照常校验并应用，
  视图集按空处理（应用旧版快照会清除视图，与"该版本无视图"语义一致）。
- 主节点在**没有任何视图**时生成的快照不带 `views` 键，与 v1 逐字节兼容；一旦发布
  视图即切换为 v2。注意：**旧版从节点程序**无法应用含 `views` 的快照（校验和公式
  不同），升级时应先升级从节点。
- `/debug/snapshot/legacy`（仅测试用）把当前版本渲染成 v1 格式，用于验证旧格式
  快照仍可同步。

## 运行

### Docker Compose（推荐）

```bash
docker compose up --build
```

- 主节点 API / 文档： http://localhost:8000/docs
- 从节点 API / 文档： http://localhost:8001/docs
- 从节点 DNS： `dig @127.0.0.1 -p 5353 host1.lab.test A` ／ `dig @127.0.0.1 -p 5353 lab.test SOA`

从节点数据在命名卷 `slave-data` 中，`docker compose restart slave` 后仍用最后版本应答。
Compose 网络固定为 `172.30.99.0/24`，从宿主机发到映射 UDP 端口的查询到达从节点时
源地址是该网络网关（`172.30.99.1`），因此下面的视图演示可直接复现；如子网与现有
网络冲突，改 `docker-compose.yml` 里的子网并相应调整视图网段即可。

### 本地（无 Docker）

```bash
pip install -r requirements.txt
MASTER_DB=/tmp/master.db uvicorn dnslab.master_app:app --port 8000 &
SLAVE_DB=/tmp/slave.db MASTER_URL=http://127.0.0.1:8000 DNS_PORT=5353 \
  uvicorn dnslab.slave_app:app --port 8001 &
```

## 使用（均可在 `/docs` 中操作）

```bash
# 批量发布公共记录（一次事务、一个新序列号）
curl -X POST http://localhost:8000/records/bulk -H 'Content-Type: application/json' -d '{
  "records": [
    {"name": "host1.lab.test", "ip": "10.0.0.1"},
    {"name": "host2.lab.test", "ip": "10.0.0.2", "ttl": 60}
  ]}'

# 单条增改 / 删除公共记录
curl -X PUT  http://localhost:8000/records/host3.lab.test -H 'Content-Type: application/json' -d '{"ip": "10.0.0.3"}'
curl -X DELETE http://localhost:8000/records/host2.lab.test

# 发布一个网段的地址覆盖清单（整体替换该网段视图，一个新序列号）
curl -X PUT http://localhost:8000/views/172.30.99.0/24 -H 'Content-Type: application/json' -d '{
  "records": [{"name": "host1.lab.test", "ip": "192.168.99.1"}]}'

# 单条视图覆盖的增改 / 删除；查看全部视图
curl -X PUT    http://localhost:8000/views/172.30.99.0/24/records/host3.lab.test \
     -H 'Content-Type: application/json' -d '{"ip": "192.168.99.3", "ttl": 60}'
curl -X DELETE http://localhost:8000/views/172.30.99.0/24/records/host3.lab.test
curl -X DELETE http://localhost:8000/views/172.30.99.0/24   # 删除整个视图
curl http://localhost:8000/views

# 查看主节点现役序列号 / 完整快照（含视图）
curl http://localhost:8000/zone/serial
curl http://localhost:8000/zone/snapshot

# 从节点：发起同步、查看现役版本（含视图数）
curl -X POST http://localhost:8001/sync -H 'Content-Type: application/json' -d '{}'
curl http://localhost:8001/status
```

CIDR 直接写在 URL 路径里（`/docs` 会自动编码为 `%2F`，服务端两种形式都接受）；
主机位会被规范化（如 `172.30.99.7/24` 存为 `172.30.99.0/24`）。重叠网段允许并存，
应答时选最长前缀。`PUT /views/{cidr}` 传空 `records` 列表等价于清空该视图（仍换版）。

`POST /sync` 可选参数：`{"serial": N}` 拉取指定历史版本（主节点保留最近
`KEEP_VERSIONS=100` 版，主要用于测试迟到旧版）；`{"url": ...}` 覆盖快照来源。
设 `SYNC_INTERVAL=秒数` 可让从节点周期自动同步（默认 0，仅手动）。

## UDP 查询演示（Docker Compose）

```bash
docker compose up --build -d
# 公共记录 + 面向演示网段的视图（宿主机查询源 IP 落在 172.30.99.0/24）
curl -X POST http://localhost:8000/records/bulk -H 'Content-Type: application/json' -d \
  '{"records": [{"name": "host1.lab.test", "ip": "10.0.0.1"},
                {"name": "host2.lab.test", "ip": "10.0.0.2"}]}'
curl -X PUT http://localhost:8000/views/172.30.99.0/24 -H 'Content-Type: application/json' -d \
  '{"records": [{"name": "host1.lab.test", "ip": "192.168.99.1"}]}'
curl -X POST http://localhost:8001/sync -H 'Content-Type: application/json' -d '{}'

dig @127.0.0.1 -p 5353 host1.lab.test A   # -> 192.168.99.1   （命中视图）
dig @127.0.0.1 -p 5353 host2.lab.test A   # -> 10.0.0.2       （视图未覆盖，公共记录）
dig @127.0.0.1 -p 5353 lab.test SOA       # SOA 照常，序列号即本版版本号

# 撤销覆盖后只回退公共地址
curl -X DELETE http://localhost:8000/views/172.30.99.0/24/records/host1.lab.test
curl -X POST http://localhost:8001/sync -H 'Content-Type: application/json' -d '{}'
dig @127.0.0.1 -p 5353 host1.lab.test A   # -> 10.0.0.1       （回退公共地址）
```

## 自测

```bash
python tests/selftest.py    # 需要已安装 requirements.txt
```

脚本拉起真实主从进程，覆盖：初次同步失败报不可用、发布/同步/应答、批量更新原子切换、
迟到旧版拒绝、断流与校验和损坏、并发发布+同步交错（记录与视图混合发布；序列号单调、
DNS 层 SOA 单调、最终记录与视图逐条一致）、主节点失联、从节点重启、新从节点+主失联、
`/docs` 可用性与主恢复后的同步；视图专项：重叠网段最长前缀、视图未覆盖名字与未匹配
网段回退公共、视图独有名字、撤销覆盖只回退公共地址、删除整个视图、旧格式快照仍可
同步（且应用后视图清空）、非法视图发布被拒且不换版、故障与重启后视图持续可用。

## 目录

```
dnslab/dnsproto.py    最小 DNS 线格式编解码与应答逻辑（仅标准库），含视图选择
dnslab/master_app.py  主节点 FastAPI 应用（公共记录 + 视图发布）
dnslab/slave_app.py   从节点 FastAPI 应用 + UDP DNS 服务
tests/selftest.py     端到端自测
Dockerfile / docker-compose.yml
```

## 已知限制

- 仅 UDP、仅 `A`/`SOA`/`ANY` 查询；不支持 TCP、EDNS、IXFR/AXFR、DNSSEC、NOTIFY。
- **视图按 UDP 源 IP 选择，不支持 EDNS Client Subnet**：查询若经转发器/递归器到达，
  看到的是转发器地址。适用于各隔离网内客户端直连（或每网本地转发器）的场景。
- 视图只覆盖 `A` 记录；无按视图的 SOA/TTL 策略，也不能用视图屏蔽公共名字。
- 旧版（无视图功能的）从节点程序不能应用含 `views` 键的快照；无视图时主节点生成
  的快照与旧格式逐字节兼容。滚动升级请先升级从节点。
- 序列号比较用简单“严格大于”（本系统序列号从 1 单调 +1，未实现 RFC 1982 回绕比较）。
- 快照为全量传输，适合 lab 规模；超大区域需增量机制。
- 从节点应用快照时的 SQLite 写入在事件循环内完成，记录数极大时会短暂阻塞循环（lab 规模无感）。
- 主节点 `/debug/snapshot/truncated`、`/debug/snapshot/corrupt`、`/debug/snapshot/legacy`
  仅用于故障注入/兼容性测试，生产应移除。
