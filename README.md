# 探针告警签名接收

面向安全运营的签名告警接收台：拦截伪造 JSONL 与失陷探针，提供不可恢复的探针撤销，并将通过全部校验的告警批次以单个事务原子发布。

- 首页：<http://localhost:8000>
- 签名接收页：<http://localhost:8000/ingest>
- 健康检查：<http://localhost:8000/healthz>

## 快速启动

```bash
docker compose up --build
```

浏览器打开 <http://localhost:8000>，点击“进入签名接收台”。

若 8000 端口被占用：

```bash
APP_PORT=8080 docker compose up --build
```

停止并保留数据：

```bash
docker compose down
```

彻底删除本地测试数据：

```bash
docker compose down -v
```

Compose 启动 **2 个 Uvicorn Web 进程**，共享 `/data` 命名卷中的同一个 SQLite 告警库；一个一次性初始化容器先把卷目录交给非 root 应用用户，然后正式服务启动。暂存文件位于容器 `/tmp` tmpfs。应用容器以非 root 运行，根文件系统只读，丢弃全部 capabilities，启用 `no-new-privileges`。

## 页面功能

签名接收页包含：

1. **签名批次提交**：选择探针，上传 UTF-8 JSONL 与独立 RSA-PSS/SHA256 签名。
2. **正常/篡改样例**：可直接下载，见下文“样例走查”。
3. **探针撤销**：展示每台探针的公钥指纹、授权主机和撤销状态；撤销操作有不可恢复提示。
4. **告警分页**：按事件时间倒序分页查看已提交告警，可按探针筛选。
5. **导入审计**：分页查看成功/失败批次、行数、新写入、跳过数及完整失败原因与行号。

## 输入约束

| 项目 | 约束 |
| --- | --- |
| JSONL 文件 | UTF-8，最多 **32 MiB**（33,554,432 字节） |
| 每行 | 最多 **4 KiB**（4,096 字节） |
| 签名 | 独立文件，**RSA-PSS / SHA-256**，MGF1(SHA-256)，salt 长度固定 **32 字节** |
| 必填字段 | `probe_id`、`event_id`、`host`、`time`、`rule` |
| `time` | UTC 整数秒，64 位有符号整数 |
| 探针绑定 | 每行 `probe_id` 必须等于表单选择的探针 ID |
| 主机授权 | 每行 `host` 必须在该探针的本地授权主机列表内 |

JSON 对象允许额外字段；重复键、`NaN`/`Infinity`、无效 Unicode 代理项、空行、非对象行均会被拒绝。签名同时接受原始二进制、base64 文本和 PEM 包裹的 base64。

## 样例走查

正常样例：

- `examples/probe-alpha-valid.jsonl`：6 行，其中第 6 行与第 5 行完全相同。
- `examples/probe-alpha-valid.sig`：对应签名。

上传后应得到：`total_lines=6`、`imported_lines=5`、`skipped_lines=1`。重复上传同一批次应得到 `imported_lines=0`、`skipped_lines=6`，不会产生重复告警。

篡改样例：

- `examples/probe-alpha-tampered.jsonl`：签名生成后修改了首行 `rule`。
- 请搭配 `examples/probe-alpha-valid.sig` 上传，应得到 `signature_invalid`，告警总数保持不变。

也提供 `probe-beta-valid.jsonl` 与对应签名，用于验证探针选择隔离。

### curl 示例

```bash
curl -sS \
  -F probe_id=probe-alpha \
  -F events=@examples/probe-alpha-valid.jsonl \
  -F signature=@examples/probe-alpha-valid.sig \
  http://localhost:8000/api/ingest | jq
```

```bash
curl -sS \
  -F probe_id=probe-alpha \
  -F events=@examples/probe-alpha-tampered.jsonl \
  -F signature=@examples/probe-alpha-valid.sig \
  http://localhost:8000/api/ingest | jq
```

撤销探针：

```bash
curl -sS -X POST http://localhost:8000/api/probes/probe-alpha/revoke | jq
```

撤销后，该探针的任何新导入都会在读取前和最终提交屏障处被拒绝；已有历史告警仍可查询。

## 原子性与并发设计

### 流式读取

`app/ingest.py` 以 64 KiB 块读取上传文件，同时更新 SHA-256；行缓冲上限固定为 4 KiB + 行尾，不会随行数增长而增长。每行只保留当前 JSON 对象，规范化后立即写入**独立暂存 SQLite 文件**。

### 两阶段提交

1. 全部行通过格式、探针、主机、时间、重复一致性检查；
2. 对原始字节的签名验证通过；
3. 打开业务库短写事务 `BEGIN IMMEDIATE`；
4. 在写锁内再次检查 `revocations`；
5. 与已提交告警做整批重复比对：字段相同则跳过，字段不同则回滚整批；
6. 用 `INSERT ... SELECT` 从暂存库复制新告警，并写入成功导入审计；
7. 提交。

签名失败、行校验失败、重复冲突、撤销或进程中断时，业务事务回滚；暂存库位于业务库之外，不会留下半批可见告警。

### 不阻塞撤销

长耗时的读取、逐行校验、SHA-256 与暂存写入都不接触业务库，也不持有业务库写锁。撤销接口只做一条短小的 `BEGIN IMMEDIATE` 状态写入，因此在导入接收期间仍可迅速完成。

### 撤销屏障

- 撤销在 SQLite 中持久化，没有恢复接口。
- 导入最终事务内重新读取撤销状态；若撤销已提交，整批失败。
- 若导入已先取得写锁并提交，则撤销在其后生效——不存在“撤销已成功后仍有未提交导入提交成功”的窗口。
- 重启时只重新载入配置里的公钥与授权主机，不删除 `revocations` 表；配置变化不能恢复已撤销探针。

### 两进程共享

Compose 使用 `uvicorn --workers 2` 与共享 `/data` 卷。SQLite 使用 WAL；每个请求独立连接，状态全部来自共享数据库，不存在仅进程内可见的撤销或告警状态。

## 本地配置

默认：`config/probes.json`

```json
{
  "probes": [
    {
      "probe_id": "probe-alpha",
      "public_key_file": "probe-alpha-public.pem",
      "authorized_hosts": [
        "web-01.example.internal",
        "db-01.example.internal"
      ]
    },
    {
      "probe_id": "probe-beta",
      "public_key_file": "probe-beta-public.pem",
      "authorized_hosts": [
        "web-02.example.internal",
        "db-02.example.internal"
      ]
    }
  ]
}
```

- 相对 `public_key_file` 相对于配置文件所在目录。
- 也可直接使用 `public_key_pem` 字段。
- 公钥必须是 RSA 公钥。
- 每次进程启动都会把当前公钥和主机白名单 upsert 到 SQLite，方便两个 Worker 读取一致状态；**不会清空撤销表**。

修改配置后重启服务生效：

```bash
docker compose restart probe-alert-ingest
```

样例私钥没有进入仓库。需要重新生成一套公钥和签名样例时：

```bash
python tools/generate_examples.py
```

该脚本只在临时目录中持有私钥，生成后即删除。

## 自己生成签名

OpenSSL 示例：

```bash
openssl dgst -sha256 \
  -sign probe-alpha-private.pem \
  -sigopt rsa_padding_mode:pss \
  -sigopt rsa_pss_saltlen:32 \
  -out batch.sig batch.jsonl
```

Python 示例：

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

signature = private_key.sign(
    payload,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
    hashes.SHA256(),
)
```

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/` | 首页，含签名接收页入口 |
| `GET` | `/ingest`（`/alerts` 同页别名） | 签名接收、撤销、告警分页和导入审计页面 |
| `POST` | `/api/ingest` | 表单字段 `probe_id`、`events`（JSONL）与 `signature` |
| `GET` | `/api/alerts` | `page`、`page_size`（1–100）、可选 `probe_id` |
| `GET` | `/api/imports` | `page`、`page_size`（1–100），含失败原因 |
| `GET` | `/api/probes` | 探针、授权主机、公钥指纹、持久化撤销状态 |
| `POST` | `/api/probes/{probe_id}/revoke` | 不可恢复地撤销探针 |
| `GET` | `/api/samples` | 正常/篡改样例清单 |
| `GET` | `/samples/{name}` | 下载样例 |
| `GET` | `/api/meta` | 文件、行、salt 限制 |
| `GET` | `/api/openapi.json` | OpenAPI 描述 |
| `GET` | `/healthz` | 数据库可达性健康检查 |

导入兼容字段别名：`file` / `jsonl` 代替 `events`，`signature_file` / `sig` 代替 `signature`。

成功响应：

```json
{
  "status": "committed",
  "batch_id": "056dda2969374122957b2d613c772d22",
  "probe_id": "probe-alpha",
  "total_lines": 6,
  "imported_lines": 5,
  "skipped_lines": 1,
  "size_bytes": 777,
  "message": "签名与全文件校验通过，整批告警已原子提交。"
}
```

错误响应使用 `detail` 对象：

```json
{
  "detail": {
    "code": "duplicate_conflict",
    "message": "第 6 行的 event_id 已存在且字段内容不同，整批拒绝",
    "line": 6
  }
}
```

常见失败码：

| 失败码 | 含义 |
| --- | --- |
| `signature_invalid` | RSA-PSS 签名不匹配或格式无效 |
| `probe_mismatch` | 行内 `probe_id` 与所选探针不一致 |
| `host_unauthorized` | 行内主机不在该探针授权列表 |
| `line_too_large` / `file_too_large` | 行或文件超过上限 |
| `invalid_json` / `invalid_utf8` | JSONL 格式错误 |
| `duplicate_conflict` | 同探针同 `event_id` 已存在但字段不同 |
| `probe_revoked` | 探针已撤销 |
| `storage_busy` | 最终短事务等待 SQLite 写锁超时 |

告警分页响应包含 `items`、`page`、`page_size`、`total`、`pages`、`has_prev`、`has_next`。

## 本地开发与测试

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

python3 -m unittest discover -s tests -v
```

本地运行两个 Worker：

```bash
ALERT_DB_PATH=./data/alerts.sqlite3 \
STAGING_DIR=/tmp/probe-alert-staging \
uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 2
```

环境变量：

| 变量 | 默认值 |
| --- | --- |
| `PROBE_CONFIG` | `<项目>/config/probes.json` |
| `ALERT_DB_PATH` | `<项目>/data/alerts.sqlite3` |
| `STAGING_DIR` | 系统临时目录下的 `probe-alert-staging` |
| `MAX_EVENTS_BYTES` | `33554432` |
| `SQLITE_BUSY_TIMEOUT_MS` | `30000` |
| `APP_PORT` | Compose 端口，默认 `8000` |
| `INGEST_TMP_SIZE` | Compose `/tmp` tmpfs 大小，默认 `512m` |

## 目录结构

```text
app/
  main.py       FastAPI 路由、页面入口、生命周期
  config.py     本地探针/公钥/主机白名单加载
  db.py         SQLite schema、撤销、告警与导入分页
  ingest.py     流式哈希、逐行校验、签名、暂存与原子提交
  static/       首页、签名接收页、样式与前端逻辑
config/         两台探针公钥及 probes.json
examples/       正常、篡改、第二探针样例与签名
tests/          流式校验、重复、原子性、撤销与 API 测试
tools/          样例与密钥生成脚本
Dockerfile
docker-compose.yml
```

## 部署提示

控制台本身不实现用户登录。生产环境应将其置于受控运维网络、VPN 或带身份认证的反向代理之后，并限制对撤销接口的访问。公钥配置应按权限保护；私钥只应保存在探针侧，不应放入本服务。
