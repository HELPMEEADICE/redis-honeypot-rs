# redis-honeypot-rs

一个用纯 Rust 写的、极小体积的 **Redis 高交互蜜罐**。只监听一个 TCP 端口（默认 `0.0.0.0:6379`），
模拟一个"配置错误、没有密码"的 Redis 实例，捕获互联网上的扫描、密码爆破、未授权访问和恶意命令。

- 不依赖真实 Redis 服务端，不需要 Docker，不监听任何其他端口，没有 HTTP API / Web UI。
- 认证永远是**成功**：`AUTH` 随机异步延迟 2–6 秒后返回 `+OK`，把爆破者的时间成本拉满。
- 危险命令（`MODULE LOAD`、`EVAL`、`CONFIG SET dir`、`REPLICAOF`、`SHUTDOWN` …）
  **只回协议、不动主机**：不读文件、不执行命令、不发起外部连接、不停止进程。
- 所有交互异步写入本地 SQLite（WAL + 批量事务 + 有界队列），网络路径永不阻塞在磁盘上。

---

## 1. 快速开始

```bash
# 编译（Rust stable 1.85+，Edition 2024）
cargo build --release

# 默认启动：0.0.0.0:6379，数据库 ./redis-honeypot.db
./target/release/redis-honeypot-rs

# 等价写法
./target/release/redis-honeypot-rs serve
```

本机验证（任意 redis 客户端，包括 `redis-cli`）：

```bash
redis-cli -h 127.0.0.1 -p 6379 ping                 # PONG
time redis-cli -h 127.0.0.1 -p 6379 -a whatever ping # 先 AUTH，随机 2–6 秒后 OK
redis-cli -h 127.0.0.1 -p 6379 info server
redis-cli -h 127.0.0.1 -p 6379 set hello world
redis-cli -h 127.0.0.1 -p 6379 get hello             # "world"
redis-cli -h 127.0.0.1 -p 6379 config get dir       # 伪造值 /var/lib/redis
```

也可以用 `nc` 手搓协议：

```bash
printf '*1\r\n$4\r\nPING\r\n' | nc 127.0.0.1 6379    # +PONG
printf 'PING\r\n' | nc 127.0.0.1 6379                 # inline 命令同样支持
```

---

## 2. 命令行

```bash
redis-honeypot-rs                                   # 无参数 = serve
redis-honeypot-rs serve --bind 0.0.0.0:6379
redis-honeypot-rs serve --db ./honeypot.db
redis-honeypot-rs serve --min-delay 2000 --max-delay 6000
redis-honeypot-rs serve --ipv6                      # 额外监听 [::]:6379
redis-honeypot-rs serve --record-passwords          # 显式开启：明文记录密码（取证用）
redis-honeypot-rs serve --max-connections 256 --max-per-ip 8
redis-honeypot-rs serve --config ./config.toml      # TOML 覆盖默认值
redis-honeypot-rs stats                             # 本地统计，不监听任何端口
redis-honeypot-rs stats --top-ips 20
redis-honeypot-rs stats --top-commands 20
redis-honeypot-rs stats --auth
redis-honeypot-rs stats --dangerous
redis-honeypot-rs --help
```

`stats` 子命令只读本地 SQLite 文件，即使蜜罐正在运行也安全（WAL 允许并发读）。

---

## 3. 配置文件（可选）

`--config config.toml`，未出现的字段沿用默认值。示例见 `deploy/config.example.toml`：

```toml
bind = "0.0.0.0:6379"
enable_ipv6 = false
record_passwords = false

[timing]
auth_min_delay_ms = 2000
auth_max_delay_ms = 6000
command_jitter_max_ms = 0        # >0 时对普通命令追加 0..=N 毫秒抖动

[limits]
max_connections = 512
max_connections_per_ip = 16
max_message_bytes = 524288
max_bulk_len = 524288
max_array_len = 1024
max_depth = 8
max_args = 256
max_commands_per_conn = 1024
max_auth_attempts = 64
idle_timeout_secs = 1800
partial_frame_timeout_secs = 30
max_stored_param_bytes = 2048
store_max_keys = 1024
store_max_bytes = 1048576
store_max_value_bytes = 4096
store_max_ttl_secs = 86400

[database]
path = "./redis-honeypot.db"
max_bytes = 268435456
queue_capacity = 8192
batch_size = 128
batch_interval_ms = 250
retention_days = 30
checkpoint_interval_secs = 300
maintenance_interval_secs = 60
```

配置在启动时校验：越界、自相矛盾（例如 `min_delay > max_delay`）会直接拒绝启动并返回退出码 2。

---

## 4. 数据库结构

默认 `./redis-honeypot.db`，WAL 模式，自动建表建索引。所有时间戳是 **UTC Unix 毫秒**。

| 表 | 用途 | 关键字段 |
| --- | --- | --- |
| `connections` | 每条连接一行 | `conn_id` `ip` `port` `connected_at` `disconnected_at` `duration_ms` `command_count` `close_reason` |
| `commands` | 每条命令一行（先记录后响应） | `conn_id` `ts` `ip` `name` `args` `arg_count` `resp_type` `simulated` `risk` `risk_label` |
| `auth_attempts` | 每次认证尝试一行（`AUTH` 或 `HELLO … AUTH`） | `conn_id` `ts` `ip` `username` `arg_count` `password_len` `password` `simulated_ok` `delay_ms` `meta` |
| `security_events` | 危险命令/协议异常/超限/限流/异常断开 | `conn_id` `ts` `ip` `kind` `command` `detail` |
| `writer_stats` | 写入器自身的健康（单行，`id=1`） | `updated_at` `lost` `retried` `retry_failed` `pruned_rows` `vacuum_pages` `checkpoint_blocked` |

`auth_attempts` 的两个时间字段分工明确，避免统计误读：

- `delay_ms` 是**计划延迟**（配置窗口里抽到的那个值，单位毫秒）；
- `meta` 是 `key=value;…` 串，包含 `via=auth|hello`（认证方式）、`proto=2|3`（协商到的协议版本）、
  `planned_ms`、`waited_ms`（**实测**等待时间）与 `outcome=ok|client_fin|client_reset|server_shutdown`。

因此一次被客户端提前挂断的认证不会被误记成"完整延迟过一次"：它的 `waited_ms` 明显小于 `planned_ms`，
`outcome` 直接写出取消原因。`meta` 与 `commands.args` 共用同一个上限（见第 6 节）。

`writer_stats` 让"丢了多少记录"跨进程可见：写入器每个维护节拍（以及退出时）把计数器写进这一行，
于是另一个进程跑 `redis-honeypot-rs stats` 也能看到 `writer.lost` / `writer.retried` / `writer.pruned_rows`。
`user_version` 因此从 1 升到 2——DDL 是可增量的，旧库跑一次 `init` 就自动多出这张表；没有任何破坏性迁移。

索引：`ip`、`commands(name, ts)`、`ts`、`security_events(kind, ts)`，满足"按来源 IP / 命令名 / 时间"三类检索。

密码默认**不落明文**：只记录 `username`、参数个数和 `password_len`。需要字典取证时用
`--record-passwords` 或 `record_passwords = true` 显式开启。

存储自我保护：单字段长度截断、队列有界、按 `retention_days` 清理、`max_bytes` 到顶后按最旧优先裁剪，
并周期性 `wal_checkpoint(TRUNCATE)`。数据库故障只记日志、退避重试，不会让网络服务崩溃。

---

## 5. 安全模型（"不动手"清单）

| 命令 | 蜜罐行为 | 真实副作用 |
| --- | --- | --- |
| `MODULE LOAD` | 返回加载失败错误，记录尝试路径 | 无（绝不 `dlopen`） |
| `EVAL` / `EVALSHA` / `SCRIPT LOAD` | 返回协议响应或 40 位假 sha1 | 无（绝不执行 Lua） |
| `CONFIG SET dir` / `dbfilename` | 写入虚拟配置表，回 `+OK` | 无（不改真实目录/文件名） |
| `SAVE` / `BGSAVE` / `BGREWRITEAOF` | 回 `+OK` / `Background saving started` | 无（不生成 RDB/AOF） |
| `REPLICAOF` / `SLAVEOF` | 回 `+OK` | 无（不发起任何外部连接） |
| `FLUSHALL` / `FLUSHDB` | 回 `+OK` | 只清空受限额约束的虚拟键空间 |
| `SHUTDOWN` | 回 `+OK` 后关闭**这条连接** | 蜜罐进程继续运行 |
| `DEBUG` | 少量子命令回 `+OK`，其余报错 | 无 |

全局保证：不调用 shell、不创建子进程、不读写任意主机文件、不主动连接外部地址、不使用 `unsafe`。

---

## 6. 资源上限

| 维度 | 默认值 | 位置 |
| --- | --- | --- |
| 最大并发连接 | 512 | `limits.max_connections` |
| 单 IP 并发连接 | 16 | `limits.max_connections_per_ip` |
| 单条 RESP 消息 | 512 KiB | `limits.max_message_bytes` |
| 单个 Bulk String | 512 KiB | `limits.max_bulk_len` |
| 数组元素数 | 1024 | `limits.max_array_len` |
| 嵌套深度 | 8 | `limits.max_depth` |
| 命令参数个数 | 256 | `limits.max_args` |
| 单连接命令数 | 1024 | `limits.max_commands_per_conn` |
| 单连接 AUTH 次数 | 64 | `limits.max_auth_attempts` |
| 空闲超时 | 1800 s | `limits.idle_timeout_secs` |
| 半包（慢速客户端）超时 | 30 s | `limits.partial_frame_timeout_secs` |
| 单字段入库长度 | 2048 B（上限 64 KiB 且 ≤ `max_bulk_len`） | `limits.max_stored_param_bytes` |
| 虚拟键空间 · 键数 | 1024 | `limits.store_max_keys` |
| 虚拟键空间 · 计费字节 | 1 MiB | `limits.store_max_bytes` |
| 单键载荷 | 4096 B | `limits.store_max_value_bytes` |
| 单集合元素个数 | 256 | `limits.store_max_collection_len` |
| 单条回复编码后上限 | 1.5 MiB（`max_message_bytes + store_max_bytes`） | 派生值，见 6.2 |
| 数据库软上限 | 256 MiB（**数据实占页**，不是文件大小） | `database.max_bytes` |
| 记录队列 | 8192 条 | `database.queue_capacity` |

解析器不按不可信长度分配内存；所有长度/整数转换都做溢出检查（见 `src/resp/parser.rs`）。

### 6.1 虚拟键空间的计费模型

只按 `len()` 统计元素是**不够**的：`RPUSH k "" "" ""` 的载荷是 0 字节，但每个元素仍要一个分配。
所以两个数字被刻意分开：

| 计费项 | 含义 | 上限 |
| --- | --- | --- |
| `payload_bytes` | 逻辑载荷（攻击者真正"写进去"的数据量） | `store_max_value_bytes` |
| `charged_bytes` | 保守堆估算 = 载荷 + 每元素 32 B 元数据 | `store_max_bytes`（与键名 + 每键 64 B 一起算） |
| 元素个数 | list/set/hash 的元素数 | `store_max_collection_len` |

三者任一超限都会返回明确的 Redis 协议错误（`value is too large` / `too many elements`），
**不 panic、不整数溢出、不静默截断**，并且原键值与 TTL 保持原样（写前校验，写失败不改状态）。

超限时不会因为"写一个不可能的键"而先清空别人：能一次性判断装不下的写入在**驱逐之前**就被拒绝。

`charged_bytes` 是真实堆用量的**下界**（不计分配器 rounding 与 `VecDeque` 的容量冗余），
方向是安全的：它只会更早拒绝，不会更晚。

### 6.2 单条回复的上限

回复是**先整体编码再写出**的，所以它的长度就是这条连接的瞬时内存峰值。上限由配置派生：

```
reply_cap = limits.max_message_bytes + limits.store_max_bytes
```

它同时是一个真实上界：单键载荷不会超过 `store_max_value_bytes`（已校验 ≤ `max_message_bytes`），
而 RESP 分帧开销被 `store_max_bytes` 卡住（每个元素至少计入 32 B 元数据，分帧约 12 B/元素）。
超过时返回 `-ERR simulated reply exceeds the configured limit` 并**保持连接可用**，
而不是把几 MB 分配出去。默认值 512 KiB + 1 MiB = 1.5 MiB/连接，
配合 `REPLY_BUF_RETAIN`（回复写完就释放大缓冲）不会常驻。

---

## 7. 日志

控制台只打印一行一条的人类可读事件，字段全部转义并截断，且带每秒行数上限（超限后按窗口汇总，防止被打成日志洪水）：

```text
[2026-11-06 12:00:00] CONNECT  198.51.100.23:54321
[2026-11-06 12:00:04] AUTH     198.51.100.23 admin ****** 3821ms OK
[2026-11-06 12:00:05] COMMAND  198.51.100.23 INFO
[2026-11-06 12:00:06] COMMAND  198.51.100.23 CONFIG GET *
[2026-11-06 12:00:08] ALERT    198.51.100.23 MODULE LOAD [simulated]
[2026-11-06 12:00:09] CLOSE    198.51.100.23 client_closed 9421ms 5cmds
```

上例 IP 为文档保留地址。结构化、无损的记录在 SQLite 里，控制台只是人读的侧信道。

数据库侧的健康状态也在同一路输出里（都带节流，不会刷屏）：

- `NOTICE … auth_cancelled <原因> after <实测>ms of a <计划>ms delay`：认证延迟被提前取消（断线/停机）；
- `WARN  record queue saturated: N records dropped so far`：记录队列打满（丢失已计数）；
- `WARN  database rejected N records so far (… retried batches, … pruned rows)`：SQLite 重试预算耗尽后的真实丢失；
- `WARN  database over its used-space cap; pruned oldest rows`：触发容量维护，附带 `used/allocated/free` 三组数字；
- `WARN  rewrote a mostly-free database once and enabled incremental auto-vacuum`：一次性体量修复；
- `INFO  configuration reloaded: …` / `WARN restart required for: …`：SIGHUP 的结果；
- `[PANIC] redis-honeypot-rs at <file:line:col>: <msg>`：`panic="abort"` 下崩溃前唯一能留下的取证行。

---

## 8. 部署

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin redishoney
sudo install -m 0755 target/release/redis-honeypot-rs /usr/local/bin/
sudo install -d -o redishoney -g redishoney -m 0700 /var/lib/redis-honeypot
sudo install -m 0644 deploy/redis-honeypot-rs.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now redis-honeypot-rs
journalctl -u redis-honeypot-rs -f
```

unit 文件做了较严格的沙箱：`NoNewPrivileges`、`ProtectSystem=strict`、`ProtectHome`、
`MemoryDenyWriteExecute`、空 `CapabilityBoundingSet`、`SystemCallFilter=@system-service`、
`RestrictAddressFamilies=AF_INET AF_INET6`，以及 `MemoryMax=256M` / `CPUQuota=50%` 等资源上限。
6379 是高位端口，不需要任何 capability。

四个部署相关取舍，都写在 unit 文件的注释里：

- **`RestrictFileSystems=@basic-api @common-block`**：只有 `@basic-api`（tmpfs/proc/sysfs/devtmpfs 等）时，
  ext4/XFS/Btrfs 上的 SQLite 数据库**根本打不开**。加上 `@common-block` 才覆盖常见块设备文件系统。
  数据库放在网络或 FUSE 文件系统上时必须再追加对应类型，否则服务无法创建文件。
- **`ExecReload=/bin/kill -HUP $MAINPID` 是真的能用**：进程真的处理 SIGHUP（见第 9 节"热重载"）。
  它会重读、重新校验 `--config` 指定的文件，非法配置只记一条 WARN 并保留原配置——重载永远不会把服务弄挂。
  `bind`、`enable_ipv6`、`max_connections(_per_ip)` 与全部 `[database]` 项仍固定于启动，重载会明确列出"需要重启"的项。
- **不启用 `PrivateUsers=`**：它依赖 unprivileged user namespace，部分加固发行版/容器关闭了该特性，
  一旦不可用服务会**直接启动失败**。蜜罐本身已是非特权用户 + 空 capability + `ProtectSystem=strict`，
  收益有限；内核允许时可在本地自行打开。
- **`StartLimitIntervalSec=60` / `StartLimitBurst=5`**：防止坏配置或坏二进制导致无限重启循环。
  `TimeoutStopSec=30s` 覆盖"最多 15 s 排空连接 + 最多 5 s 刷 SQLite 队列"。

云主机上请确认安全组放行 6379；**不要**在生产 Redis 同机同端口部署。

---

## 9. 开发与测试

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
```

测试全部是本地闭环的：不访问公网、不加载动态模块、不修改主机 Redis 配置、
不依赖真实 Redis 服务端；集成测试在 `127.0.0.1:0` 上起真服务，用裸 TCP 说协议。

### 9.1 热重载（SIGHUP）

`kill -HUP <pid>` / `systemctl reload redis-honeypot-rs` 会：

1. 重新读 `--config` 指向的 TOML 并跑一遍完整校验（含命令行覆盖）；
2. 校验失败 → 打一条 `SIGHUP received, keeping the running configuration (…)` 的 WARN，**旧配置继续生效**；
3. 校验通过 → 立刻把虚拟键空间按新预算重新裁剪（额度调小会当场驱逐），
   再把新配置交给**之后**建立的连接；已经跑着的连接保留自己启动时的快照，回复不会自相矛盾；
4. 对绑定地址、`enable_ipv6`、连接准入上限、`[database]` 各项打印
   `restart required for: … (these values are fixed at startup)`，绝不静默忽略。

`tests/deploy.rs` 会同时校验 unit 里的 `ExecReload` 与 `src/main.rs` 真的订阅了
`SignalKind::hangup()`，防止配置与实现再次脱节。

### 9.2 GitHub Actions

| 工作流 | 触发 | 内容 |
| --- | --- | --- |
| `.github/workflows/ci.yml` | push 到 `main`、PR、手动 | `rustfmt --check`、`cargo clippy -D warnings`、三平台（Linux/Windows/macOS）`cargo test --all-targets`、release 构建 + 裸 TCP `PING` 冒烟 |
| `.github/workflows/build.yml` | Release published、手动 | 9 个目标交叉编译，产物打包成 archive 并作为可下载 artifact；Release 触发时自动上传到该 Release，并附 `SHA256SUMS.txt` |

构建矩阵（全部使用 `Cargo.toml` 里的体积优先 profile）：

| 矩阵名 | target triple | runner | 构建方式 |
| --- | --- | --- | --- |
| `linux-x86_64` | `x86_64-unknown-linux-gnu` | ubuntu-latest | 原生 cargo |
| `linux-aarch64` | `aarch64-unknown-linux-gnu` | ubuntu-latest | `cross`（Docker 工具链） |
| `linux-armv7` | `armv7-unknown-linux-gnueabihf` | ubuntu-latest | `cross` |
| `linux-riscv64` | `riscv64gc-unknown-linux-gnu` | ubuntu-latest | `cross` |
| `linux-mips` | `mips-unknown-linux-gnu` | ubuntu-latest | `cross` + nightly `-Z build-std=std,panic_abort` |
| `macos-x86_64` | `x86_64-apple-darwin` | macos-latest | 原生 cargo（arm64 主机交叉到 x86_64） |
| `macos-aarch64` | `aarch64-apple-darwin` | macos-latest | 原生 cargo |
| `windows-x86_64` | `x86_64-pc-windows-msvc` | windows-latest | 原生 cargo |
| `windows-aarch64` | `aarch64-pc-windows-msvc` | windows-latest | 原生 cargo + ARM64 MSVC 工具链 |

`linux-mips` 单独处理的原因：`mips-unknown-linux-gnu` 是 tier 3 目标，官方不发布预编译 `std`，
必须 nightly + `-Z build-std`；同时 rusqlite 的 `bundled` 会编译 SQLite 的 C 代码，所以需要一个真正的
mips 交叉工具链（由 `cross` 的镜像提供——注意 Ubuntu 24.04 已移除 `gcc-mips-linux-gnu` 包）。

mips 还有两个与架构本身有关的坑，都在仓库里解决掉了：

- **没有 64 位原子指令**：`target_has_atomic = "64"` 为假，`AtomicU64` 在该目标上不存在。
  计数器改为机器字长（见 `src/record.rs` 的 `DropCounter`），在 API 边界再拓宽成 `u64`。
- **没有 `getrandom(2)`**：glibc 2.24 是最后一个支持 mips o32 的版本，而 `getrandom(2)` 到 2.25 才出现；
  `std` 与 `getrandom` crate 都无条件引用该符号，链接会报 `undefined reference to 'getrandom'`。
  `build.rs` 因此只为 `mips*-linux-gnu` 编译一个 5 行的 C shim（`src/shim/getrandom_mips.c`），
  直接走 `syscall(SYS_getrandom)`；其他目标不编译这段代码（SQLite 之外唯一的一处 C）。

目标清单本身在 `.github/targets.json` 里维护（`setup` 作业读取它、按 `only` 过滤后生成构建矩阵），
加一个目标只需要往这个 JSON 里加一条记录。

手动触发时可以只构建部分目标，便于排查单个平台：

```bash
gh workflow run build.yml --repo HELPMEEADICE/redis-honeypot-rs -f only=linux-mips,windows-aarch64
```

产物命名：`redis-honeypot-rs-<version>-<target>.tar.gz`（Windows 为 `.zip`），
Linux 的包内额外带 `deploy/` 下的 systemd unit 与示例配置。

---

## 10. 实测数据

以下数字全部来自本机实测（Windows 11 x86_64，rustc 1.98.1，`cargo build --release`），不是估算。

### 10.1 构建产物体积

当前 `Cargo.toml` 的 profile 按"优化开满"配置：`opt-level="z"` `lto="fat"` `codegen-units=1`
`panic="abort"` `strip="debuginfo"` `debug=false` `incremental=false` `overflow-checks=false`。

| profile | 参数差异 | 体积 |
| --- | --- | --- |
| **release（当前）** | `strip="debuginfo"`（保留符号表） | **3,577,355 B = 3.41 MiB**（本轮修复前 3,517,691 B，+1.7%） |
| 对比：去掉符号表 | 同配置但 `strip="symbols"` | 2,265,088 B = 2.16 MiB（**−35.6%**） |
| 对比：吞吐优先 | `opt-level=3` `lto="thin"` `codegen-units=16` `strip="symbols"` | 2,982,912 B = 2.84 MiB |
| 对比：debug | 默认 dev profile | 71,763,480 B = 68.44 MiB |

`strip="debuginfo"` 只删调试信息、保留符号表，所以比 `strip="symbols"` 大 1.19 MiB——
换来的是崩溃栈里能直接看到函数名。要最小体积就把它改成 `strip="symbols"`。
SQLite 用 `bundled` 编进二进制（C amalgamation），所以这些数字里已包含完整 SQLite，运行时**没有任何动态依赖**。
release 全量构建约 14–40 秒（纯增量 14 s，含依赖 40 s）。

### 10.2 运行时内存与线程

| 场景 | 工作集（Windows） | 线程 |
| --- | --- | --- |
| 启动后空闲 | 5.6 MiB | 6 |
| 一条连接灌 1000 条 `RPUSH flood ""`（空元素洪水） | 6.0 MiB | 6 |
| 一条连接灌 1000 条 5 KB `SET`（全部被单值上限拒绝） | 9.6 MiB | 6 |
| 一条连接灌 900 条 400 B `SET`（触发全局预算驱逐） | 10.0 MiB | 6 |

（`tools/flood-check.ps1` 可复现上表。）空闲 15 s 的 CPU 时间**低于 Windows 计时精度**（`TotalProcessorTime`
读数 0 ms，即 <0.1% 单核）；写入线程的空闲唤醒节拍是 100 ms 一次（见 `IDLE_SLICE`），只做一次
`try_recv` + 一次 sleep，代价可以忽略，换来的是"没有任何攻击流量也能按时清理与 checkpoint"。

空元素洪水是本次修复的核心：**1000 条里前 256 条被接受，其余 744 条返回
`-ERR too many elements (257, simulated limit 256)`**，工作集只涨 0.4 MiB 然后停住。
修复前同样的流量在账面上"零字节"，列表却能一直长下去
（按 `size_of::<Vec<u8>>() = 24` 估算，100 万个空元素 ≈ 24 MiB 未计入任何上限——这是推算，不是实测）。

5 KB `SET` 那一行的 9.6 MiB 主要是 1000 条命令的记录队列（每条 `args` 截断到 2048 B）与 WAL，
不是虚拟键空间；队列本身有界（`queue_capacity` × `max_stored_param_bytes`）。

观测到 6 个线程：其中确定包含 2 个 tokio worker（`worker_threads(2)`）和 1 个 SQLite 阻塞写线程，
其余为主线程与运行时内部线程。内存不随命令量增长，只受 `limits.store_max_bytes`（默认 1 MiB 虚拟键空间）与连接数上限约束。

### 10.3 测试

`cargo test --all-targets --locked` —— **203 个测试全部通过**（Linux/Windows/macOS 由 CI 跑同一套）：

| 套件 | 数量 | 覆盖 |
| --- | --- | --- |
| lib 单元测试 | 164 | RESP 编解码（含 300×5 KB 流水线分片）、虚拟键空间计费与驱逐、命令表、SQLite 写入/重试/维护/容量、监听器与连接状态机、CLI、配置校验、时间/转义工具 |
| `tests/protocol.rs` | 12 | RESP2 基础、inline 命令、粘包/拆包（逐字节喂）、`HELLO 2/3`、非法长度、整数溢出、超长 Bulk、二进制安全、错误有界 |
| `tests/auth.rs` | 11 | 认证永远成功、默认 2–6 秒延迟、延迟可配置、并发不串行、无认证执行命令、密码不落库、`--record-passwords` 开关、**AUTH 延迟期间 FIN/RST 断线检测与连接槽释放**、**pipeline 不被断线探测吞字节**、**HELLO AUTH 入库** |
| `tests/persistence.rs` | 7 | 四张表各就各位、危险命令零副作用、超长/二进制参数截断、并发写入不丢、`stats` 报表、凭据不泄漏 |
| `tests/shutdown.rs` | 6 | 优雅退出、空闲超时、慢速客户端超时、全局/单 IP 连接上限、单连接命令数上限 |
| `tests/deploy.rs` | 3 | unit 文件沙箱不误伤数据库文件系统、`ExecReload` 与真实 SIGHUP 处理器一致、`config.example.toml` 能被真实 loader 解析 |

回归测试中与本次修复直接对应的几组：

- **空元素列表**：`empty_string_list_cannot_grow_past_the_element_cap`、`repeated_empty_elements_are_charged_each_time`；
- **原子性**：`refused_collection_writes_roll_back_completely`、`impossible_write_does_not_evict_the_store`、`repeated_overwrites_do_not_leak_charge`；
- **并发**：`concurrent_readers_and_writers_keep_the_accounting_consistent`（4 线程 × 250 次混合写，并重算总账）；
- **LPUSH 性能**：`lpush_keeps_redis_order_and_scales`（1000 次 LPUSH 计时 + 顺序校验）；
- **SQLite 容量**：`size_cap_prunes_against_used_pages_and_keeps_history`（历史不被清空）、`idle_checkpoint_truncates_the_wal`、`maintenance_runs_on_its_own_clock_without_traffic`（零流量仍维护）；
- **写入失败**：`transient_lock_contention_is_retried_without_duplicates`（模拟 `SQLITE_BUSY`）、`fatal_write_failure_is_counted_as_lost_and_not_retried`（`SQLITE_READONLY` → 计入丢失，不空转）；
- **HELLO**：`hello_auth_is_captured_like_auth`、`hello_option_errors_are_reported_and_not_recorded`；
- **截断**：`tiny_caps_stay_inside_the_bound`（多字节字符边界）、`param_cap_follows_the_configured_limit`（配置值真的传到写入器）；
- **回复上限**：`oversized_reply_is_refused_by_the_reply_cap`（超限回复返回 ERR 且连接继续可用）；
- **热重载**：`reload_applies_to_new_connections_and_recaps_the_store`（新连接用新窗口、键空间当场重新裁剪）、`set_caps_takes_effect_on_the_live_keyspace`；
- **写入器健康**：`writer_health_is_persisted_and_reported`（计数器落库，`stats` 报表能读回来）、`bloat_repair_runs_once_and_enables_incremental_auto_vacuum`。

复现：

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
```

### 10.4 协议兼容性（真实 release 二进制 + 裸 TCP 逐字节实测）

本机没有安装 `redis-cli`，所以用裸 TCP 手工拼出与 `redis-cli` **完全一致**的 RESP 字节（`*N\r\n$len\r\n…`），
下表是实际收到的回复（`\r\n` 已转义）。用 `redis-cli` 复现的命令写在最后。

| 发送 | 实际回复 |
| --- | --- |
| `PING` | `+PONG\r\n` |
| `SET hello world` | `+OK\r\n` |
| `GET hello` | `$5\r\nworld\r\n` |
| `GET missing` | `$-1\r\n` |
| `INFO server` | `$559\r\n# Server\r\nredis_version:7.2.4\r\n…`（含 `redis_mode` `os` `arch_bits` 等 559 字节） |
| `CONFIG GET dir` | `*2\r\n$3\r\ndir\r\n$14\r\n/var/lib/redis\r\n` |
| `HELLO 3` | `%7\r\n$6\r\nserver\r\n$5\r\nredis\r\n…`（RESP3 map，含 `proto` `:3`、`modules` 空数组） |
| `MODULE LOAD /tmp/evil.so` | `-ERR Error loading the extension. Please check the server logs.\r\n` |
| `EVAL 'redis.call("ping")' 0` | `-ERR Error compiling script (new function): user_script:1: function not available\r\n` |
| `AUTH admin wrongpassword` | `+OK\r\n`，延迟 **4165 ms**（`delay_ms` 记计划延迟，`meta.waited_ms` 记实测） |

同一连接上的控制台输出（真实日志，密码已脱敏）：

```text
[2026-11-06 13:56:29] CONNECT   127.0.0.1:14134
[2026-11-06 13:56:29] COMMAND   127.0.0.1:14134 SET hello world
[2026-11-06 13:56:31] COMMAND   127.0.0.1:14134 CONFIG GET dir
[2026-11-06 13:56:32] COMMAND   127.0.0.1:14134 HELLO 3
[2026-11-06 13:56:32] ALERT     127.0.0.1:14134 MODULE [MODULE LOAD /tmp/evil.so attempted; no loader exists on this server]
[2026-11-06 13:56:33] COMMAND   127.0.0.1:14134 AUTH admin ******
[2026-11-06 13:56:38] AUTH      127.0.0.1:14134 admin ****** 4165ms OK
[2026-11-06 13:56:47] CLOSE     127.0.0.1:14134 client_closed 17875ms 10cmds
```

`stats` 子命令（同一份数据库，进程已被强杀后仍可读，WAL 生效）。注意
`db.used_bytes`（实占页，容量上限用的就是它）与 `db.size_bytes`（文件大小）现在是两个独立字段，
`writer.*` 是写入器上次刷新的健康快照（旧版本写的库没有这张表时，这一段会自动省略）：

```text
Redis honeypot stats — …\rhp-demo.db
============================================================================
connections.total        1
connections.active       0
commands.total           9
commands.distinct_ips    1
auth.attempts            1
auth.simulated_ok        1
security.events          2
dangerous.commands       2
…
Recent AUTH attempts (1)
  2026-11-06 13:56:38  127.0.0.1  admin  13  4165ms  ok
Recent dangerous commands (2)
  2026-11-06 13:56:32  127.0.0.1  MODULE  MODULE LOAD /tmp/evil.so  critical
  2026-11-06 13:56:33  127.0.0.1  EVAL  EVAL "redis.call("ping")" 0  critical
```

用 `redis-cli` 等价复现：

```bash
redis-cli -h 127.0.0.1 -p 6379 ping
redis-cli -h 127.0.0.1 -p 6379 set hello world
redis-cli -h 127.0.0.1 -p 6379 get hello
redis-cli -h 127.0.0.1 -p 6379 info server
redis-cli -h 127.0.0.1 -p 6379 config get dir
redis-cli -h 127.0.0.1 -p 6379 -a wrongpassword ping   # 2–6 秒后成功
redis-cli -h 127.0.0.1 -p 6379 hello 3
```

注意：`CLOSE` 行里的 `10cmds` 是这条连接收到的**全部**命令数，而 `commands` 表只有 9 行——
`AUTH` 不进 `commands`，它单独落在 `auth_attempts`（含用户名、参数个数、密码长度、实测延迟），
避免同一件事在两张表里各存一份。

### 10.5 本次未验证的内容

- **Linux 构建与运行**：只在 Windows 上编译、测试、实测（见"已知限制"第 4 条）。
- **`systemd-analyze verify`**：本机无 systemd，unit 文件按较严格沙箱写并补了 `tests/deploy.rs` 静态校验，
  但**没有**在真实主机上跑过 `systemd-analyze verify`，也没有做过实际的服务启动 + SQLite 落盘测试。
  本次特意去掉 `PrivateUsers=`、把 `RestrictFileSystems` 扩到 `@common-block`，正是为了让它在普通 Linux 上能起来——
  这一条仍需要你在目标主机上确认。
- **`redis-cli` 交互**：本机无 `redis-cli`，用等价的裸 TCP 字节替代（见 10.4）。
- **长跑稳定性**：未做 24 小时以上的持续压测；内存/连接/队列上限是代码保证，不是长跑观测。

---

## 11. 已知限制

诚实清单，按重要程度排序。前三条是有意为之的取舍，不是遗漏。

**1. `panic = "abort"`：任何 panic 仍会让整个进程退出（但会留一行取证）。**
这是任务书指定的 release profile。蜜罐的可攻击面在解析器和命令模拟器，二者都按"对任意字节序列全函数、不许 `unwrap`/索引越界/按不可信长度分配"来写，
并有针对畸形输入、超长 Bulk、整数溢出、深层嵌套的测试兜底；`src/**` 非测试代码里没有任何 `panic!/unreachable!`，也没有 `unsafe`。
崩溃前会执行 panic hook，往 stderr/journald 打一行
`[PANIC] redis-honeypot-rs at <file:line:col>: <转义并截断后的消息>`，所以"进程没了但不知道为什么"这种最坏情况被消除了。
但重启是必须的——部署时请配 `Restart=always`（unit 文件已配）。

**2. 数据库 `max_bytes` 的语义是"数据实占页"，不是文件大小。**
上限比较的是 `page_count - freelist_count`（行、索引与 SQLite 元数据真正占用的页）。
`DELETE` 释放的页会留在文件里，靠 `incremental_vacuum` 逐次归还（每次维护最多 512 页）。
这样做的原因很直接：按文件大小判断会陷入死循环——`DELETE` 不缩小文件，条件永远不满足，
于是每个节拍继续删，最后把整段历史删光。
代价是：如果数据库**不是** `auto_vacuum=INCREMENTAL`，文件不会自己变小（只有逻辑容量收敛）。
`init_db` 会尽力迁移（空库直接设置；已有库在 ≤64 MiB 时用一次 `VACUUM` 迁移；更大的库跳过并打 WARN）。
跳过之后还有第二道保险：维护节拍发现库仍是非 incremental、且**空闲页已占文件 3/4 以上**、
并且文件 ≤64 MiB 时，会**自己重写一次**（每个进程最多一次）——这次重写同时把库切成 incremental，
此后的 `DELETE` 就能真正缩小文件了。再往后仍可手工 `VACUUM`。
剩下的边界仍然存在：一个 >64 MiB 且从未被迁移过的库不会自动重写，这是有意为之（重写会阻塞写入器）。

**3. 普通命令的**值**按设计明文记录。**
脱敏只作用于凭据位置（`AUTH`、`HELLO … AUTH`、`CONFIG SET requirepass`）。
攻击者把密码塞进 `SET somekey <password>`，它会被当作普通数据、按 `max_stored_param_bytes` 截断后入库——
这是取证价值最高的一类情报（攻击者准备用哪个密码、注入什么载荷），所以默认保留。
需要绝对不落明文时，请缩小 `max_stored_param_bytes` 或在入库前做外部脱敏。

**4. 只在本机 Windows x86_64 上实测。**
本次交付的二进制体积、内存占用、`cargo test` 结果都来自 Windows 11 + rustc 1.98.1。
代码本身除了 SIGTERM 处理放在 `#[cfg(unix)]` 下以外没有平台相关分支，但**本次没有在 Linux 上编译/运行过**，
`deploy/redis-honeypot-rs.service` 也没有在真实 systemd 主机上跑过 `systemd-analyze verify`。上生产前请先 `systemd-analyze verify` 并冒烟一次。

**5. 虚拟键空间是所有连接共享的，且有硬上限。**
和真实 Redis 一样，不同攻击者能看到彼此的 `SET`。上限为 1024 key / 1 MiB 计费字节 / 单值 4 KiB /
单集合 256 元素，到顶后按插入顺序淘汰——一个刷 key 的攻击者会把另一个攻击者的"证据"挤掉。
要完全隔离就得每连接一份存储，代价是内存随连接数线性增长。

**6. 未实现 RESP3 的推送/订阅、事务与阻塞命令。**
没有 `SUBSCRIBE`/`PUBLISH`、`MULTI`/`EXEC`、`BLPOP`。`HELLO 3` 只协商协议版本与 `CLIENT` 相关字段。
扫描器最常用的那批命令都覆盖了，但"高交互"不等于"完整 Redis"。

**7. `DBSIZE` 与 `INFO keyspace` 带一个虚构基数。**
为了让新实例看起来"有人用过"，两者都报 `真实 key 数 + 4`。这是欺骗设计的一部分，不是 bug；但也意味着这两个值不能当作精确统计。

**8. 不模拟的时序特征。**
真实 Redis 的 `INFO`、`DEBUG SLEEP`、`SAVE` 有真实的耗时与磁盘行为，这里没有。
`DEBUG SLEEP` 立即返回，`SAVE` 不落盘。有经验的扫描器可以通过耗时差异识别蜜罐。

**9. `stats` 以读写方式打开数据库。**
为了容忍 WAL 恢复，它不走 `SQLITE_OPEN_READ_ONLY`；它对缺失文件返回错误且**不会创建**文件，但严格意义上不是纯只读连接。
并发运行中的蜜罐是安全的（WAL 允许并发读）。

**10. 单条命令的延迟上限，以及它仍占用的一个连接槽。**
`AUTH` 的 2–6 秒延迟是可取消的：等待期间用 `peek` 探测 FIN/RST（不消费后续 pipeline 字节），
客户端提前挂断会立刻结束连接任务、释放全局与每 IP 槽位，并把这次尝试连同取消原因写进 `auth_attempts`；
SIGTERM/SIGINT 会同样立即取消所有等待中的 AUTH（同样留证）。
但它确实**占用一个连接槽直到取消为止**：`max_connections` 打满时，正在等待的那批连接就是
"被爆破者按住的连接"。按 512 并发 × 6 秒估算，最坏情况下准入会被拖慢——必要时调小 `max_connections_per_ip`。

**11. 写入器计数器是"上次刷新"的快照，不是实时值。**
`lost` / `retried` / `pruned_rows` 会随每个维护节拍（默认 60 s）和退出时写进 SQLite 的 `writer_stats` 单行，
所以 `redis-honeypot-rs stats` 能跨进程读到 `writer.lost` 等字段；但**两次刷新之间**的数字只活在内存里，
进程被 `SIGKILL` 时最多丢一个节拍的增量。实时性要求高的话，把 journald 里的
`database rejected …` 行接进告警管道。

**12. 单条回复的内存是"配置派生"的上限，不是常数。**
回复整条编码后才写出，所以单连接峰值 = `max_message_bytes + store_max_bytes`（默认 1.5 MiB），
超过就返回 `-ERR simulated reply exceeds the configured limit` 并保持连接可用。
它随配置放大：把 `store_max_bytes` 调到 16 MiB 就会得到 16.5 MiB/连接的理论峰值。
默认配置下 `512 × 1.5 MiB` 仍是理论上界（实际远低于此，因为 `REPLY_BUF_RETAIN` 用完即释放、
单键载荷默认只有 4 KiB）。真要放大键空间，请同时下调 `max_connections`。

**13. 热重载只覆盖"能安全换掉"的部分。**
新连接才会拿到新的时序/解析上限；已建立的连接保留启动时的快照（否则同一条连接上的回复可能自相矛盾）。
绑定地址、`enable_ipv6`、连接准入上限与全部 `[database]` 项固定于启动，重载只报告它们变了、需要重启。
虚拟键空间的预算是个例外：它会**当场**重新裁剪（额度调小的瞬间就驱逐）。

**14. 重试只在"可恢复"的错误上发生。**
`SQLITE_BUSY`/`SQLITE_LOCKED`/`SQLITE_PROTOCOL`/短 I/O 错误会重试（最多 4 次、总预算 2 s、指数退避）；
`SQLITE_FULL`/`SQLITE_READONLY`/`SQLITE_CORRUPT`/`SQLITE_NOTADB`/约束错误被视为不可恢复，**立即**计入丢失并记录原因。
这样不会把磁盘满变成"卡住 2 秒再丢"，也不会在数据库损坏时无声空转。

---

## 12. 许可证

本项目以 **GNU General Public License v3.0 或更高版本（GPL-3.0-or-later）** 发布。
完整条款见 [`LICENSE`](LICENSE)（GPLv3 原文，逐字未改），SPDX 标识：`GPL-3.0-or-later`。

Copyright (c) 2026 redis-honeypot-rs contributors

> 本程序是自由软件：你可以依据自由软件基金会发布的 GNU 通用公共许可证条款（第 3 版或你选择的任何更高版本）
> 再分发和／或修改它。本程序按"原样"分发，不提供任何担保，也不暗示任何适销性或特定用途适用性的担保。
> 详见 `LICENSE` 中的 GPLv3 第 15–17 条。

选择 `or-later` 是 FSF 对新项目的推荐写法。若你的场景要求锁定版本，把 `Cargo.toml` 的 `license = "GPL-3.0-or-later"`
与本节改成 `GPL-3.0-only` 即可，`LICENSE` 文件无需改动（GPLv3 正文对两者相同）。

**依赖许可**：tokio、clap、tracing、rand、serde、toml 为 MIT 或 Apache-2.0；rusqlite 为 MIT；随二进制编入的 SQLite 本体为公有领域。
这些都属于宽松许可，与 GPLv3 兼容，不会改变本项目的许可义务。
