# ippeek

超精简、零第三方依赖的 Go IP 查询 API 服务器，支持指定网卡、公网 IPv4/IPv6 智能获取、纯文本/JSON 双格式以及全不合规请求 **444 连接级 0 字节丢弃**。

## 架构概览

```text
Client ──GET /ip?token=...──▶ 严格校验 (路径/方法/白名单/常量时间Token)
                                │
                  不合规 ───────┴───────▶ 444 连接级丢弃 (0 字节直接断连)
                                │
                    通过 ───────▼
                           智能解析器 (Resolver)
                           ├─ source=local    → 直读网卡 IP (含内网)
                           ├─ source=auto     → 优先网卡公网 IP (排除内网/CGNAT/ULA)
                           │                    未命中时回退外部探测 (TTL缓存+并发合并)
                           └─ source=external → 强制外部探测 (支持绑定指定网卡出站)
                                │
                                ▼
                  format=text (纯IP) / format=json (总体信息)
```

### 分支与 Release 版本

| 版本 | 分支 | 说明 | 体积 (`linux/amd64`) |
| :--- | :--- | :--- | :---: |
| **`std`**（标准版） | `master` | Go 标准库 `net/http`，支持 `http://` 与 `https://` 探测源 | ~5.6 MB |
| **`tiny`**（精简版） | `go-tiny` | 去除 `net/http`/`reflect`，纯 `net` 手写 HTTP/1.1 与 JSON（仅 `http://` 探测源） | ~1.9 MB |
| **`tiny-upx`**（压缩版） | `go-tiny` | `tiny` 版经 UPX (`--best --lzma`) 压缩，适合路由器/嵌入式 | **~658 KB** |

## 用法说明

### 1. systemd 一键部署 / 更新 / 检查 / 卸载（Linux）

```bash
# 一键部署（默认安装 tiny-upx，未传 --token 时自动生成随机密钥）
curl -fsSL https://raw.githubusercontent.com/x-5/ippeek/master/install.sh | \
  sudo bash -s -- install --token YOUR_SECRET --listen :8080

# 指定版本部署（tiny-upx / tiny / std）
sudo bash install.sh install --variant std --token YOUR_SECRET

# 一键更新（保留 /etc/ippeek/ippeek.env 配置）
sudo bash install.sh update

# 一键检查（服务状态 + 444 断连与鉴权回环自检 + 日志）
sudo bash install.sh check

# 一键卸载（追加 --keep-config 可保留配置）
sudo bash install.sh uninstall
```

### 2. 直接运行 / 环境变量

CLI 参数优先于环境变量（`-token` / `IPPEEK_TOKEN` 为必填）：

```bash
IPPEEK_TOKEN=YOUR_SECRET ./ippeek -listen :8080
```

| 参数 | 环境变量 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `-listen` | `IPPEEK_LISTEN` | `:8080` | 监听地址 |
| `-token` | `IPPEEK_TOKEN` | **必填** | 鉴权 Token |
| `-cache-ttl` | `IPPEEK_CACHE_TTL` | `60s` | 外部探测缓存 TTL（`0` 禁用） |
| `-probe-timeout` | `IPPEEK_PROBE_TIMEOUT` | `3s` | 单次探测超时 |
| `-v4-probes` | `IPPEEK_V4_PROBES` | `4.ipw.cn,ip.3322.net,api4.ipify.org,ipv4.icanhazip.com` | IPv4 探测源 |
| `-v6-probes` | `IPPEEK_V6_PROBES` | `6.ipw.cn,api6.ipify.org,ipv6.icanhazip.com` | IPv6 探测源 |
| `-trust-proxy` | `IPPEEK_TRUST_PROXY` | `false` | 信任反代头提取 `client_ip` |

### 3. API 调用（唯一入口 `GET /ip`）

参数白名单：`token`（必填）、`v`（`4`/`6`/`all`）、`format`（`text`/`json`）、`iface`（网卡名）、`source`（`auto`/`local`/`external`）、`refresh`（`1`/`true`）。任何不合规请求均触发 444 断连。

```bash
# 纯文本公网 IPv4 / IPv6（v=4/6 默认 text，无尾部换行）
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=4"
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=6"

# 指定网卡（智能公网 / 仅本地内网）
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=4&iface=eth0"
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=4&iface=eth0&source=local"

# 总体信息 JSON（v=all 默认 json）
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET"

# 强制刷新缓存
curl "http://127.0.0.1:8080/ip?token=YOUR_SECRET&v=4&refresh=1"
```

### 4. Docker 编译与运行

```bash
make test           # 运行全部单元测试与 444 TCP 断连测试
make build-all      # 交叉编译全部硬件平台产物到 dist/
make docker-image   # 构建 FROM scratch 运行镜像
```
