# ippeek

[English](README.md) | **简体中文**

超精简、零第三方依赖的 Go IP 查询 API 服务器，支持指定网卡严格出站绑定、公网 IPv4/IPv6 智能获取、纯文本/JSON 双格式以及全不合规请求 **444 连接级 0 字节丢弃**。

## 架构概览

```text
Client ──GET /ip?token=...──▶ 严格校验 (路径/方法/白名单/常量时间多 Token 鉴权)
                                │
                  不合规 ───────┴───────▶ 444 连接级丢弃 (0 字节直接断连)
                                │
                    通过 ───────▼
                           智能解析器 (Resolver)
                           ├─ source=local    → 直读网卡 IP (含内网)
                           ├─ source=auto     → 优先网卡稳定公网 IP (排除内网/CGNAT/ULA/已废弃地址)
                           │                    未命中时回退外部探测 (TTL缓存+并发合并)
                           └─ source=external → 强制外部探测 (严格绑定指定网卡出站)
                                │
                                ▼
                  format=text (纯IP) / format=json (总体信息)
```

### 构建版本与 Release 产物

所有版本均基于单一 `master` 分支通过 Go build tags 构建：

| 版本 | 构建命令 | 说明 | 体积 (`linux/amd64`) |
| :--- | :--- | :--- | :---: |
| **`std`**（标准版） | `go build .` | Go 标准库 `net/http`，支持 `http://` 与 `https://` 探测源 | ~5.6 MB |
| **`tiny`**（精简版） | `go build -tags tiny .` | 去除 `net/http`/`reflect`，纯 `net` 手写 HTTP/1.1 与 JSON（仅 `http://` 探测源） | ~1.9 MB |
| **`tiny-upx`**（压缩版） | `go build -tags tiny .` + UPX | `tiny` 版经 UPX (`--best --lzma`) 压缩，适合路由器/嵌入式 | **~658 KB** |

## 用法说明

### 1. systemd 一键部署 / 更新 / 检查 / 卸载（Linux）

```bash
# 一键部署（默认安装 tiny-upx，未传 --token 时自动生成随机密钥）
curl -fsSL https://raw.githubusercontent.com/x-5/ippeek/master/install.sh | \
  sudo bash -s -- install --token YOUR_SECRET --listen :8080

# 指定 std 版本、多 Token 平滑轮换及静默 444 丢弃日志
sudo bash install.sh install --variant std --token "NEW_SECRET,OLD_SECRET" --quiet-drops

# 一键更新（保留 /etc/ippeek/ippeek.env 配置）
sudo bash install.sh update

# 一键检查（二进制 -version、服务状态、通过 curl -K - 的 444/200 回环自检与日志）
sudo bash install.sh check

# 一键卸载（追加 --keep-config 可保留配置）
sudo bash install.sh uninstall
```

### 2. 直接运行 / 环境变量

CLI 参数优先于环境变量（除 `-version` 外，`-token` / `IPPEEK_TOKEN` 为必填）：

```bash
IPPEEK_TOKEN="NEW_SECRET,OLD_SECRET" ./ippeek -listen :8080 -quiet-drops
./ippeek -version
```

| 参数 | 环境变量 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `-listen` | `IPPEEK_LISTEN` | `:8080` | 监听地址 |
| `-token` | `IPPEEK_TOKEN` | **必填** | 鉴权 Token（逗号分隔支持多 Token 无停机轮换） |
| `-cache-ttl` | `IPPEEK_CACHE_TTL` | `60s` | 外部探测缓存 TTL（`0` 禁用） |
| `-probe-timeout` | `IPPEEK_PROBE_TIMEOUT` | `3s` | 单次探测超时 |
| `-v4-probes` | `IPPEEK_V4_PROBES` | `4.ipw.cn,ip.3322.net,api4.ipify.org,ipv4.icanhazip.com` | IPv4 探测源 |
| `-v6-probes` | `IPPEEK_V6_PROBES` | `6.ipw.cn,api6.ipify.org,ipv6.icanhazip.com` | IPv6 探测源 |
| `-trust-proxy` | `IPPEEK_TRUST_PROXY` | `false` | 信任反代头提取 `client_ip` |
| `-quiet-drops` | `IPPEEK_QUIET_DROPS` | `false` | 静默 444 连接丢弃日志 |
| `-version` | — | `false` | 输出版本信息并退出 |

### 3. API 调用（唯一入口 `GET /ip`）

参数白名单：`token`（必填）、`v`（`4`/`6`/`all`）、`format`（`text`/`json`）、`iface`（网卡名）、`source`（`auto`/`local`/`external`）、`refresh`（`1`/`true`）。任何不合规请求均触发 444 断连。

```bash
# 纯文本公网 IPv4 / IPv6（v=4/6 默认 text，无尾部换行）
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=4"
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=6"

# 指定网卡（严格绑定出站 / 仅本地内网）
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=4&iface=eth0"
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=4&iface=eth0&source=local"

# 总体信息 JSON（v=all 默认 json）
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET"

# 强制刷新缓存
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=4&refresh=1"
```

### 4. Docker 编译与运行

```bash
make test                         # 运行 std 与 -tags tiny 全部单元测试与 444 断连测试
make build                        # 编译 std、tiny、tiny-upx 的 linux/amd64 产物到 dist/
make build-all                    # 交叉编译全部三版本矩阵与 checksums.txt 到 dist/
make docker-image                 # 构建 FROM scratch 镜像（默认 BUILD_TAGS=tiny；BUILD_TAGS="" 为 std）
```
