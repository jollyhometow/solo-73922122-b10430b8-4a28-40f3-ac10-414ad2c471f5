# 科研数据归档与独立见证系统

研究数据归档员交付采样 CSV 后，需要凭**独立第三方回执**发现原件被替换或漏失。
本系统由两个互不信任的服务组成：

| 服务 | 职责 | 持久化 | 端口 |
|---|---|---|---|
| **归档端 archive**（网页） | 按批号上传 ≤ 2 MiB 原件、本地保存、固定公钥锚点验签、目录登记、下载、核查、**换钥申请与证明链核验** | 独立卷 `archive_data`（原件 + 目录 SQLite + 已核验换钥链） | 8000 |
| **见证端 witness** | 独立重算 SHA-256/长度并持久化，签发 Ed25519 回执；同号同文复用、异文拒绝；**持有并轮换签名私钥、出具换钥证明链** | 独立卷 `witness_data`（回执 SQLite + 私钥目录 + 换钥链） | 8001 |

见证端持有 Ed25519 **私钥**；归档端只持有配套的**固定锚点公钥**
（`keys/witness_ed25519.pub.pem`），因此归档端无法伪造回执，只能验证。
轮换产生的新公钥**不会被直接信任**：归档端必须凭“旧钥签新钥”的换钥证明，
从固定锚点逐级验签推导后才纳入本地密钥环。

## 1. 快速启动（Docker Compose）

```bash
# 1) 生成 Ed25519 锚点密钥（仓库已附带一套演示密钥，生产环境务必重新生成）
./scripts/generate-keys.sh

# 2) 构建并启动两个服务（各自独立持久卷；keys 目录只读挂载）
docker compose up --build -d
docker compose ps          # 两个 healthcheck 均为 healthy

# 3) 浏览器访问
#    归档网页:        http://localhost:8000
#    独立核查页:      http://localhost:8000/verify
#    见证密钥轮换页:  http://localhost:8000/rotations
#    见证回执清单:    http://localhost:8001/receipts
#    见证换钥链:      http://localhost:8001/rotations
```

停止与清理：

```bash
docker compose down            # 停止，保留两个持久卷（含私钥与换钥链）
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

### 见证签名密钥轮换（网页 `/rotations`，`POST /api/rotations`）

例行更换见证签名密钥时，历史采样 CSV 仍可核查、新上传继续归档，全过程不中断服务。

**换钥证明链（可连续追溯至原固定公钥）**

- 每个见证私钥都存放在见证端**自己的持久卷** `witness_data/keys/<指纹>.pem`；
  镜像里的引导私钥只在首次启动时复制进卷，之后所有新钥都在卷内生成，永不离开见证容器。
- 一次轮换由见证端：① 生成新 Ed25519 密钥并原子落盘 → ② 用**旧私钥**签署一份
  换钥证明（含轮换单号、旧/新钥指纹、新钥 PEM、时间、签名）→ ③ 在**同一个 SQLite
  事务**里写入证明并把当前密钥指针切到新钥 → ④ 切换内存中的签名器 → ⑤ 才从卷中
  **粉碎删除旧私钥**（先随机覆写再 unlink）。
- 证明链首尾相接：第 N 份证明由第 N-1 把钥签署，第一份由固定锚点钥签署。

**归档端不直接信任见证端自报公钥**

- 归档端唯一信任的是随镜像固定的锚点公钥；它拉取整条换钥链后，从锚点开始逐跳验签，
  每份证明必须由链上前一把钥验证通过，其内嵌新钥才进入本地“密钥环（fingerprint→公钥）”。
- 验签失败或锚点指纹不匹配 → 该链不被安装，接口返回 502；归档端本地也保存一份
  **经独立验签**的链，冷启动时先在本地从锚点重验，见证离线也保有完整密钥环。
- 回执按其携带的 `public_key_fingerprint` 在密钥环中选钥验签：**旧钥签发的历史回执
  原样保留、继续可验**（含切换前已签发、迟到返回的回执）；轮换后新签发一律用新钥。

**幂等、并发与崩溃安全**

- 轮换单号是幂等键：同单重试（含响应丢失后重试）返回**原结果**，不会再换一次钥；
  见证端 `rotation_id` 唯一约束是第二道防线。并发轮换被串行化，同版至多一份成功，
  其余按单号返回既有证明。
- 生成新钥期间上传/查询照常：签名与落库在同一把进程内轮换锁内完成，切换瞬间不会用
  错钥；上传若遇到尚未同步的新钥指纹，归档端会重新拉取并从锚点验签整条链后再受理。
- 任何时刻数据库当前指纹指向的私钥文件必然存在。写入失败或切换中退出后重启：
  见证端清理 `.part`/未提交的游离密钥、补粉碎已退役私钥，并恢复到可签发状态；
  已签发回执一条不丢。归档端重启后重建密钥环并自动接续 pending 批次。

**接口一览**

| 方法 路径 | 说明 |
|---|---|
| `GET  witness:8001/rotations` | 换钥证明链 + 当前密钥指纹 |
| `GET  witness:8001/rotations/{id}` | 按单号取单次轮换证明 |
| `POST witness:8001/rotations`（表单 `rotation_id`） | 执行/幂等重试一次轮换 |
| `GET  archive:8000/api/rotations` | 归档端本地已验签链与密钥环 |
| `GET  archive:8000/api/rotations/{id}` | 按单号查结果（响应丢失取回，不会重复换钥） |
| `POST archive:8000/api/rotations`（表单 `rotation_id`） | 网页提交轮换单，随后从锚点重验整条链 |

网页 `/rotations` 可：查看锚点/现用密钥指纹与链校验状态、生成并提交轮换单、
按单号查询结果、展开每份换钥证明原文。

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
（临时目录充当两个独立卷），覆盖 85 项检查：

```bash
pip install -r requirements.txt
python3 scripts/self_test.py
```

覆盖点：健康检查、空清单不误报通过、正常上传与验签下载、幂等复用、异文 409、
>2 MiB 拒绝、同批双窗口并发不重复归档、异批并行各自归档一次（无全局锁）、
见证后崩溃→重启自动接续、见证卷重启后回执与签名完整保持、
见证不可达 pending 且不重投、核查发现篡改/缺件/目录漏登、
伪造回执（他方 Ed25519 私钥）被固定公钥拒绝、见证停服时核查 503 不通过，
以及**签名密钥轮换全套**：换钥证明链从锚点逐级验签、旧私钥从卷中移除、
同单幂等重试不重复换钥、并发轮换串行且单号唯一、轮换中上传照常、
新旧钥回执混合可验、迟到旧钥回执可登记、伪造换钥证明被拒、
两端冷启动后链/当前钥/回执/可签发状态完整、见证离线时换钥失败不污染信任状态。

> 注：CI 沙箱禁用 `kill(2)`，测试进程通过应用内 `POST /__selftest_shutdown`
> 优雅退出；该端点仅用于测试，生产可经反向代理屏蔽。

## 5. 目录结构

```
common/receipt.py          Ed25519 回执与换钥证明的载荷、签名、验签（两端共享）
witness/                   独立见证服务（FastAPI + SQLite + 私钥目录）
  main.py                  回执签发、换钥接口、轮换锁
  db.py                    回执表、换钥证明链表、当前密钥状态表
  keystore.py              卷内私钥管理：原子生成、启动清理、退役私钥粉碎
archive/                   归档网页（FastAPI + SQLite + 锚点公钥 + 原件存储）
  main.py                  上传/核查/下载/换钥代理与链同步
  trust.py                 锚点→密钥环推导、按指纹验签、链校验
  templates/               上传/批次/核查/换钥四个页面
keys/                      Ed25519 锚点密钥对（演示用，生产请重新生成）
scripts/generate-keys.sh   密钥生成
scripts/self_test.py       85 项端到端自测
scripts/demo.sh            断连接续 + 原件损坏演示
docker-compose.yml         双服务 + 两个独立持久卷 + 只读密钥挂载 + 健康检查 + 自动重启
Dockerfile                 单镜像双命令
```

## 6. 安全说明与边界

- 回执载荷为确定性 JSON（排序键、紧凑分隔），签名覆盖
  `version/batch_id/filename/length/sha256/issued_at`，并含公钥指纹防错钥；
- 换钥证明同为确定性 JSON，签名覆盖
  `type/version/rotation_id/old/new 指纹/新钥 PEM/issued_at`，
  旧钥签新钥、逐跳成链，归档端只认能追溯到固定锚点的链；
- 退役私钥在证明持久化提交后才粉碎（随机覆写 + unlink）；归档端卷内
  **从不出现任何私钥**，`keys/` 在 compose 中以只读方式挂载；
- 演示密钥随仓库提供仅为开箱即用；真实部署应在受信环境运行
  `generate-keys.sh` 重新生成，私钥只挂载进见证端；
- 当前为单节点 SQLite、HTTP 明文，生产部署应置于 TLS 反向代理之后，
  并按需给见证/归档管理接口（含换钥接口）加鉴权。
