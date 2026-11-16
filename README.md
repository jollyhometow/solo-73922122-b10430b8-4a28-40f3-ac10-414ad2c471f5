# 科研数据归档与独立见证系统

研究数据归档员交付采样 CSV 后，需要凭**独立第三方回执**发现原件被替换或漏失。
本系统由两个互不信任的服务组成：

| 服务 | 职责 | 持久化 | 端口 |
|---|---|---|---|
| **归档端 archive**（网页） | 按批号上传 ≤ 2 MiB 原件、本地保存、固定公钥验签、目录登记、下载、核查 | 独立卷 `archive_data`（原件 + 目录 SQLite） | 8000 |
| **见证端 witness** | 独立重算 SHA-256/长度并持久化，签发 Ed25519 回执；同号同文复用、异文拒绝 | 独立卷 `witness_data`（回执 SQLite + 私钥） | 8001 |

见证端持有 Ed25519 **私钥**；归档端只持有配套**公钥**（`keys/witness_ed25519.pub.pem`），
因此归档端无法伪造回执，只能验证。

## 1. 快速启动（Docker Compose）

```bash
# 1) 生成 Ed25519 密钥（仓库已附带一套演示密钥，生产环境务必重新生成）
./scripts/generate-keys.sh

# 2) 构建并启动两个服务（各自独立持久卷）
docker compose up --build -d
docker compose ps          # 两个 healthcheck 均为 healthy

# 3) 浏览器访问
#    归档网页:        http://localhost:8000
#    独立核查页:      http://localhost:8000/verify
#    见证回执清单:    http://localhost:8001/receipts
```

停止与清理：

```bash
docker compose down            # 停止，保留两个持久卷
docker compose down -v         # 同时删除持久卷（清空全部数据）
```

## 2. 核心流程与需求对应

### 上传（`POST /api/batches/{batch_id}/files`，网页首页）
1. 归档端流式读取，超过 **2 MiB 立即 413 拒绝**，本地计算长度与 SHA-256；
2. 原件先以原子替换（`.part` → 目标名）写入本地卷，**绝不覆盖已存在原件**；
3. 转发给见证端；见证端**自己重新**哈希（不信任归档端自报摘要），
   持久化 `批号、文件名、长度、SHA-256` 并签发 Ed25519 回执；
4. 归档端用**固定公钥**验签并核对批号/文件名/长度/摘要全部一致；
5. 验签通过才写入本地目录（状态 `registered`）。
   **本地原件、目录登记、已验签回执三者齐备**才把批次报为 `complete` 并开放下载。

### 同号同文复用、异文拒绝
- 见证端对 `(batch_id, filename)` 建唯一约束：同键同摘要 → 返回 `reused=true`
  的既有回执；同键异摘要/异长度 → **409 content_conflict**，历史记录不可覆盖；
- 归档端对同键异文同样 409，且保留已见证原件不动。

### 断连 / 崩溃后的接续（不重复归档）
- 见证不可达：原件保留在本地，目录记为 `pending`（网页显示“待核”），
  API 返回 **202**；**不会当作“未受理”盲目重投**。
- 见证受理后断连，或本地登记前进程退出（演示用故障注入）：
  重启时归档端同时扫描 ① 目录中的 pending 行 ② 磁盘上无目录记录的“孤儿原件”，
  先向见证端 `GET /batches/{id}` **查明**：有回执则验签后补登（复用，不重传）；
  见证明确 404 才重传本地原件；见证不可达则继续 pending。
- 每个批号一把进程内锁，双窗口并发重试在服务端串行化；
  见证端唯一约束是第二道防线，任何情况下都不会产生重复归档。
- 失败清理只移除临时 `.part` 文件，已见证原件永不被覆盖或删除。

### 独立核查（网页 `/verify`，`GET /api/verify`）
以**见证端已签发清单**为准（不是只扫本地目录），对每个回执逐项：
1. 固定公钥**验签**；
2. 重算本地原件 SHA-256/长度，与回执比对 → 报告 `tampered_original`（篡改）
   或 `missing_original`（缺件）；
3. 检查本地目录是否登记 → 报告 `catalog_missing`（目录漏登）。

见证不可达时接口返回 **503 且 `passed=false`**，绝不报核查通过。

### 下载
仅 `registered` 文件可下载；下载前再次重算摘要并验签，损坏原件返回 409 拒绝。

## 3. 故障演示

### 3.1 断连/崩溃接续 + 原件损坏（脚本，需 compose 运行中）

```bash
./scripts/demo.sh
```

脚本自动完成：武装崩溃标记 → 上传（见证受理后归档容器退出）→
等待 Docker 重启策略拉起 → 启动自动接续、批次恢复 complete 且见证只有 1 条记录 →
篡改卷内原件 → 核查页报告 `tampered_original` 且下载被拒。

手动版（网页亦可）：

```bash
# 武装：下一次上传在“见证已受理、本地未登记”处退出
curl -X POST http://localhost:8000/api/admin/arm-crash
curl -X POST http://localhost:8000/api/batches/BATCH-DEMO/files \
     -F filename=readings.csv -F file=@demo-samples/readings.csv
# 连接被切断；docker compose ps 可见 archive 容器被 restart 自动拉起
# 重启后打开 http://localhost:8000/batches/BATCH-DEMO，状态自动恢复 complete

# 模拟见证不可达：停掉见证后上传，网页/接口显示“待核”
docker compose stop witness
curl -X POST http://localhost:8000/api/batches/BATCH-OFFLINE/files \
     -F filename=x.csv -F file=@demo-samples/readings.csv   # 202 pending
curl http://localhost:8000/api/verify                       # 503, passed=false
docker compose start witness
curl -X POST http://localhost:8000/api/reconcile            # 查明并接续
```

### 3.2 原件损坏演示

```bash
docker exec research-archive sh -c \
  "printf 'CORRUPTED' >> /data/originals/BATCH-DEMO/readings.csv"
# 打开 http://localhost:8000/verify 点“开始核查” → 篡改，红色告警
```

## 4. 本地自测（无需 Docker）

`scripts/self_test.py` 会在临时目录中拉起**真实的 uvicorn 双进程**
（临时目录充当两个独立卷），覆盖 39 项检查：

```bash
pip install -r requirements.txt
python3 scripts/self_test.py
```

覆盖点：健康检查、空清单不误报通过、正常上传与验签下载、幂等复用、异文 409、
>2 MiB 拒绝、同批双窗口并发不重复归档、异批并行各自归档一次（无全局锁）、
见证后崩溃→重启自动接续、见证卷重启后回执与签名完整保持、
见证不可达 pending 且不重投、核查发现篡改/缺件/目录漏登、
伪造回执（他方 Ed25519 私钥）被固定公钥拒绝、见证停服时核查 503 不通过。

> 注：CI 沙箱禁用 `kill(2)`，测试进程通过应用内 `POST /__selftest_shutdown`
> 优雅退出；该端点仅用于测试，生产可经反向代理屏蔽。

## 5. 目录结构

```
common/receipt.py          Ed25519 回执载荷、签名、验签（两端共享）
witness/                   独立见证服务（FastAPI + SQLite + 私钥）
archive/                   归档网页（FastAPI + SQLite + 固定公钥 + 原件存储）
  templates/               上传/批次/核查三个页面
keys/                      Ed25519 密钥对（演示用，生产请重新生成）
scripts/generate-keys.sh   密钥生成
scripts/self_test.py       31 项端到端自测
scripts/demo.sh            断连接续 + 原件损坏演示
docker-compose.yml         双服务 + 两个独立持久卷 + 健康检查 + 自动重启
Dockerfile                 单镜像双命令
```

## 6. 安全说明与边界

- 回执载荷为确定性 JSON（排序键、紧凑分隔），签名覆盖
  `version/batch_id/filename/length/sha256/issued_at`，并含公钥指纹防错钥；
- 演示密钥随仓库提供仅为开箱即用；真实部署应在受信环境运行
  `generate-keys.sh` 重新生成，私钥只挂载进见证端；
- 当前为单节点 SQLite、HTTP 明文，生产部署应置于 TLS 反向代理之后，
  并按需给见证/归档管理接口加鉴权。
