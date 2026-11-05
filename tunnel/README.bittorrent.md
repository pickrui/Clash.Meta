# BT 客户端强制直连

Windows、macOS 和 Linux 的 FlClash 内核在选择全局代理、匹配订阅规则或采用入站指定策略之前，查询本机连接所属的进程
命中内置识别条件后直接使用 `DIRECT`，TCP 和 UDP 均适用

这是始终启用的内核策略，没有关闭开关，订阅配置、覆写脚本、`find-process-mode: off` 和模式切换均不能关闭
“查找进程”开关仍控制其他应用的进程规则和显示，BT 客户端的识别独立执行
Android 和其他平台不启用此策略

## 按需识别

查询连接归属需要扫描整张系统 socket 表，因此只在可能命中下载客户端时执行：

- 目标不是 TCP 80/443 或 UDP 443 的本机连接照常逐个识别；Peer、DHT、UDP Tracker 和非标准端口 Tracker 都属于这一类，客户端的第一条此类连接即被识别并直连
- 网页端口连接（TCP 80/443、UDP 443）只在以下任一条件成立时才识别：最近 60 秒内有连接被识别为下载客户端；或按需扫描进程列表发现下载客户端正在运行
- 进程列表扫描不使用后台定时器，只在出现网页端口连接且近期未识别到客户端时触发，最多每 3 秒一次；扫描复用下方的名称与入口识别，只为 Java / Python 候选读取参数
- 无法读取进程列表时视为有客户端运行，网页端口连接也逐个识别，与按需识别前一致
- 代价：客户端启动后、下一次扫描之前（最多 3 秒），若尚未产生非网页端口连接，其 HTTP(S) Tracker 请求可能仍按原策略路由

## 客户端识别

桌面端按可执行文件名精确匹配，忽略大小写，并支持 `.exe` 后缀：

- qBittorrent、qBittorrent-nox
- Transmission、transmission-daemon、transmission-gtk、transmission-qt、transmission-cli
- Deluge、deluged、deluge-gtk、deluge-debug、deluged-debug
- BiglyBT、BiglyBT-console
- µTorrent、BitTorrent、BitComet、BitComet_x64
- aria2c、Motrix、rTorrent、KTorrent、Tixati

Deluge 和 BiglyBT 使用共享运行时时，还识别以下入口：

| 客户端 | 可识别的启动方式 |
| --- | --- |
| Deluge | Python / Pythonw 及带版本号的 Python 启动精确匹配的 Deluge 入口脚本，包括 Windows 的 `.exe` 和 `-script.py` 启动入口 |
| Deluge | `python -m` 启动 `deluge`、`deluge.ui`、`deluge.ui.ui_entry`、`deluge.ui.gtk3`、`deluge.core.daemon_entry` |
| Deluge | `setproctitle` 将 Python 进程标题改为 Deluge 入口名，其余参数为空的形式 |
| BiglyBT | Java / Javaw 的 `-jar BiglyBT.jar`，或主类为 `com.biglybt.ui.Main` 且显式 classpath 含精确匹配的 `BiglyBT.jar` |
| BiglyBT | macOS 的 `BiglyBT.app/Contents/MacOS/JavaApplicationStub` |

入口名称依据 [Deluge 启动配置](https://github.com/deluge-torrent/deluge/blob/develop/setup.py)和 [BiglyBT 命令行说明](https://github.com/BiglySoftware/BiglyBT/wiki/Command-Line-Options)核对
Python / Java 自身不会整体直连，普通应用的参数、目录名或 Java 系统属性中出现客户端名称也不会触发
`python -c`、Java `@argfile`、未知入口和 Deluge 远程控制端不会通过运行时识别补猜身份

## 防误判和资源边界

- 只为实际可执行文件是 Python / Java 的候选进程读取启动参数，普通原生应用不读取参数
- 按启动选项语义定位入口，不对整条命令行做关键词搜索；不执行命令行，不读取参数文件
- 参数读取上限为 64 KiB / 1,024 个参数，读取失败或截断时不进行运行时识别
- macOS 只解析 argv，不把紧随其后的环境变量加入匹配
- macOS / Linux 在参数读取前后核对可执行路径和进程启动时间；Windows 在同一个进程句柄上核对路径和读取参数
- 不缓存 PID、端口或命令行识别结果，避免将退出进程的结果沿用到后续连接；命令行不写入连接元数据或日志
- 三个桌面平台均校验 socket 的本地地址、端口和归属；UDP 可使用同地址族的通配绑定，精确地址优先，同等匹配条件下存在归属歧义就放弃识别
- 进程名和入口名匹配不是二进制身份认证，刻意使用相同文件名或伪装启动入口的程序仍可能命中

## 生效范围

- 命中进程的全部连接都会直连，包括 Tracker、DHT、Peer 和该进程的普通 HTTP 下载
- 不依赖下载端口、域名或 BT 握手嗅探，名称相似的普通进程不会因此强制直连
- 仅适用于当前设备上可查询到归属的连接；局域网其他设备、隔离容器、改名客户端、未知启动方式或权限不足可能无法识别，未识别连接仍按原策略路由
- 内核自身的订阅下载、DNS 和节点探测连接不参与客户端识别
- 对新建连接生效，已有 TCP 连接和 UDP 会话需要重建
- 按需识别的时间窗口见上文“按需识别”
- 客户端自行指定远程代理时，本策略不能去除客户端自身的代理协议或配置
- 现有“BT 下载直连”预设仍可用于规则模式下的 Tracker / PT 域名匹配

## 验证结果

2026-10-16，Go 1.26.9，构建标签 `with_gvisor,with_mips_low_memory`

- macOS arm64：`component/process` 与 `tunnel` 的完整测试和竞态检测通过，FlClash Go 主模块测试、静态检查通过
- 36 组运行时识别样例覆盖 Deluge / BiglyBT 入口、普通 Python / Java 程序、相似名称、目录及参数诱导、读取失败
- 64 个 goroutine 共执行 64,000 次混合 TCP / UDP 路由，在全局模式和关闭常规进程查找时反复复用四个模拟源端口，样例中未出现误判或竞态
- socket 归属测试覆盖多进程共享端口、重复记录、精确地址与通配地址优先级、IPv4 / IPv6 和无效归属；macOS 原始表解析用例实际运行通过
- 自有测试子进程退出后不再返回参数，可执行路径不符时拒绝读取，截断数据和环境变量不会作为入口
- Windows / Linux 的 amd64、arm64 进程包及测试二进制通过编译和静态检查；Windows / Linux amd64 的 tunnel 测试二进制也通过编译和静态检查
- macOS amd64 进程包测试二进制通过编译和静态检查，Android arm64 共享进程包通过编译，Android 路由排除用例通过
- Windows / Linux 未做实机执行，本次没有启动应用或执行真实 BT 下载

### 性能

Apple M4 / macOS arm64，`GOMAXPROCS=8`，64 个工作 goroutine，单项测量 1 秒、重复 3 次，下表取中位数
基准进程禁止 IP 网络与主机文件写入，前后系统代理 / DNS 快照一致

| 测量阶段 | 串行每次 | 64 并发摊销每次 | 每次分配内存 |
| --- | ---: | ---: | ---: |
| 混合样例的运行时分类 | 78.94 ns | 17.35 ns | 20 B，混合样例平均 |
| 原生读取自有进程参数并校验身份 | 15.771 µs | 13.854 µs | 约 2.1 KiB |
| 扫描 1,024 条模拟 TCP 记录，目标在末尾 | 0.5364 µs | 0.1448 µs | 168 B |
| 扫描 16,384 条模拟 TCP 记录，目标在末尾 | 9.199 µs | 1.754 µs | 168 B |

并发栏是总耗时除以完成次数，反映整体吞吐，不是单请求延迟
模拟表扫描包含地址、端口和归属歧义判断，不包含系统调用生成 socket 表的成本
参数基准读取的是自有测试进程，参数长度会影响耗时与分配

按需识别的进程列表扫描（Apple M4 / macOS arm64，本机 566 个进程）：每次 1.0–1.6 ms、约 515 KB 分配；最多每 3 秒一次，只在出现网页端口连接且近期未识别到客户端时执行
没有下载客户端运行时，网页端口连接不再查询 socket 表

当前权限下原生 TCP 表只返回 48 字节头尾数据，完整原生 socket 查询基准已显式跳过，空表数据不计入性能结论
以上结果证明新增分类和参数读取的局部开销，不能替代管理员权限下的完整连接查找、端到端吞吐或三平台实机压测

### 复现命令

在 `core/Clash.Meta` 中执行以下检查，性能基准应与编译及竞态测试分开运行：

```sh
GOTOOLCHAIN=go1.26.9 CGO_ENABLED=1 go test -race -count=1 -tags with_gvisor,with_mips_low_memory ./component/process ./tunnel

bench_dir=$(mktemp -d /private/tmp/flclash-bt-bench.XXXXXX)
GOTOOLCHAIN=go1.26.9 CGO_ENABLED=0 go test -c -tags with_gvisor,with_mips_low_memory -o "$bench_dir/process.test" ./component/process
GOTOOLCHAIN=go1.26.9 CGO_ENABLED=0 go test -c -tags with_gvisor,with_mips_low_memory -o "$bench_dir/tunnel.test" ./tunnel
cat > "$bench_dir/bench.sb" <<EOF
(version 1)
(allow default)
(deny network*)
(deny system-socket)
(deny file-write*)
(allow file-write* (subpath "$bench_dir") (literal "/dev/null"))
EOF
sandbox-exec -f "$bench_dir/bench.sb" "$bench_dir/process.test" -test.run='^$' -test.bench='Benchmark(NativeProcess|DarwinSocketTable)' -test.benchmem -test.benchtime=1s -test.count=3 -test.cpu=8 -test.v
sandbox-exec -f "$bench_dir/bench.sb" "$bench_dir/tunnel.test" -test.run='^$' -test.bench=BenchmarkBittorrentRuntime -test.benchmem -test.benchtime=1s -test.count=3 -test.cpu=8 -test.v
```

主要实现位于 `tunnel/bittorrent.go`、`tunnel/bittorrent_gate.go`、`tunnel/bittorrent_runtime.go`、`tunnel/tunnel.go` 和 `component/process/`
CI 的 Go 基础检查已包含 `component/process` 和 `tunnel` 回归测试
