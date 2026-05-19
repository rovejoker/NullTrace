# NullTrace

IP 隐藏代理工具，为安全渗透测试提供源 IP 隐匿能力。支持 HTTP/HTTPS + SOCKS5 代理协议，内置多源免费代理池、Tor 匿名层集成、付费代理适配和自建中继网络。

## 安装

```bash
git clone https://github.com/rovejoker/NullTrace.git
cd NullTrace
pip install -e ".[dev]"
```

## 快速开始

```bash
# 启动免费代理池（默认模式）
proxy start

# 指定代理类型
proxy start --provider tor          # 使用 Tor 网络
proxy start --provider free         # 免费代理池
proxy start --provider custom --proxy socks5://1.2.3.4:1080  # 自定义代理

# 多跳链路
proxy start --chain free,tor        # 免费代理 → Tor → 目标

# 单 IP 模式（从池中固定一个）
proxy start --mode single

# 查看状态
proxy status

# 切换模式
proxy switch pool

# 停止服务
proxy stop

# 启动 Web 管理控制台
proxy web
```

代理服务默认监听 `127.0.0.1:1080`，在你的安全工具中配置该代理地址即可。

## Tor 集成

需本地安装 Tor 守护进程：

| 平台 | 安装方式 |
|------|----------|
| Linux | `apt install tor && systemctl start tor` |
| macOS | `brew install tor && brew services start tor` |
| Windows | 下载 [Tor Expert Bundle](https://www.torproject.org/download/tor/) 或使用 Tor Browser 自带的 `tor.exe` |

启动时自动检测 `127.0.0.1:9050`，不可用时给出安装指引。

## CLI 命令

| 命令 | 说明 |
|------|------|
| `proxy start` | 启动代理服务 |
| `proxy stop` | 停止代理服务 |
| `proxy status` | 查看当前状态 |
| `proxy switch <mode>` | 切换 single/pool 模式 |
| `proxy config --get <key>` | 查看配置项 |
| `proxy config --set <key> <value>` | 修改配置项 |
| `proxy web` | 启动 Web 管理控制台 |

### start 选项

| 选项 | 说明 |
|------|------|
| `--provider` | 代理源：free / paid / tor / self / custom |
| `--mode` | 模式：single / pool |
| `--chain` | 自定义链路，如 `free,tor,self-relay` |
| `--proxy` | 自定义代理 URL（single 模式） |
| `--port` | 本地监听端口（默认 1080） |
| `--api-key` | 付费代理 API 密钥 |

## 配置文件

编辑项目根目录的 `config.yaml`：

```yaml
proxy:
  host: "127.0.0.1"
  port: 1080

free_pool:
  min_pool_size: 10
  health_check_interval: 60
  request_timeout: 10
  max_retries: 3
  unstable_threshold: 3
  banned_threshold: 5
  cooldown_minutes: 30

tor:
  host: "127.0.0.1"
  port: 9050

paid:
  api_key: ""
  api_endpoint: ""

webui:
  port: 8080
```

## Web 管理控制台

`proxy web` 启动后在浏览器打开 `http://127.0.0.1:8080`，提供：

- 仪表盘：服务状态、池子大小、平均评分、运行时间
- 代理控制：启停服务、切换模式、换 IP
- 配置管理：查看和修改配置
- 代理池列表：实时刷新，显示评分和延迟

## 架构

```
Interface Layer    CLI (click)  ·  Web UI (FastAPI + HTMX)  ·  REST API
       │
Core Engine        ProxyManager / RelayChain / IPRotator / HealthMonitor
       │
Provider Layer     FreePool / PaidAPI / TorRelay / Custom
       │
Protocol Layer     HTTP Proxy (aiohttp) / SOCKS5 Server (asyncio)
```

## 运行测试

```bash
pytest tests/ -v
```

## 免责声明

本工具仅供授权的安全测试和教育用途使用。使用者应遵守当地法律法规，并对自身行为负责。
