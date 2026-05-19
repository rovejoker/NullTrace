# Proxy Vault — 设计文档

## 概述

IP 隐藏代理工具，为安全渗透测试提供源 IP 隐匿能力。支持 HTTP/HTTPS + SOCKS5 代理协议，提供 CLI 和 Web UI 两种交互模式，内置多源免费代理池、付费代理适配、Tor 匿名层集成和自建中继网络。

## 核心决策

| 维度 | 决定 |
|------|------|
| 代理协议 | HTTP/HTTPS + SOCKS5 |
| IP 来源 | 混合模式：免费池 / 付费API / 自建中继 / Tor，全部可插拔 |
| CLI 模式 | 守护进程，本地端口代理 (127.0.0.1:1080) |
| Web UI | 管理控制台：监控 + 切换模式 + 换IP + 配置 + 启停 |
| 中继跳数 | 免费=1跳 / 付费=1-2跳 / 自建=2-5跳 / Tor=内置3跳 |
| 单IP模式 | 手动指定外部代理 + 从池中固定一个IP |
| 可靠性 | 五层防护：预检→心跳→重试→评分→池底保护 |
| 免费代理源 | 10+ 源聚合，交叉验证，插件式采集器 |
| 动态更新 | 定时刷新 + 阈值触发 + 紧急补充 |
| Tor 集成 | 作为匿名转发层，可插入链路任意位置 |
| 技术栈 | asyncio / FastAPI / click / aiohttp / python-socks / HTMX / YAML |

## 系统架构

### 四层架构

```
Interface Layer    CLI (click)  ·  Web UI (FastAPI + HTMX)  ·  REST API
       │
Core Engine        ProxyManager / RelayChain / IPRotator / HealthMonitor
       │
Provider Layer     FreePool / PaidAPI / SelfRelay / TorRelay / Custom
       │
Protocol Layer     HTTP Proxy (aiohttp) / SOCKS5 Server (asyncio)
```

### 模块职责

**proxy-server** — 本地 HTTP/SOCKS5 代理服务，接收安全工具的代理请求，转发到 Provider Layer 处理后发送到目标。

**relay-chain** — 多跳链路编排。支持任意顺序组合代理源和匿名层，如 `free → tor → target` 或 `tor → paid → target`。

**ip-pool** — IP 池管理。维护已验证代理列表，支持健康检查、评分排名和多种轮换策略（round-robin / random / weighted）。

**providers** — 可插拔的代理源适配器，统一接口 `BaseCollector`。

**cli** — 基于 click 的命令行控制，支持 `start/stop/status/switch/config/web`。

**webui** — FastAPI + 原生 HTML/HTMX 构建的管理控制台。

## 免费代理池可靠性

### 五层防护

| 层级 | 机制 | 说明 |
|------|------|------|
| L1 | 入库前验证 | 向验证端点发请求，5s 超时，失败直接丢弃 |
| L2 | 周期性健康检查 | 每 60s 探测池内代理，连续 3 次失败标记 UNSTABLE |
| L3 | 请求级超时+重试 | 单次代理超时 10s，自动换代理重试，最多 3 次，上游透明 |
| L4 | 智能评分加权 | 基于延迟+成功率+连续失败数，分数高者优先选取 |
| L5 | 池底保护 | 可用代理 < 5 时紧急补充；池枯竭时降级直连+告警 |

### 代理 IP 状态机

```
UNKNOWN → TESTING → ACTIVE ⇄ UNSTABLE → BANNED
                      ↑                    │
                      └─── 30min 冷却 ─────┘
```

- ACTIVE → UNSTABLE：连续失败 ≥ 3 次
- UNSTABLE → BANNED：连续失败 ≥ 5 次
- UNSTABLE → ACTIVE：连续成功 2 次恢复
- BANNED → TESTING：冷却 30 分钟后重新验证

### 关键参数

| 参数 | 默认值 |
|------|--------|
| 健康检查间隔 | 60s |
| 代理请求超时 | 10s |
| 自动重试次数 | 3 |
| UNSTABLE 阈值 | 连续失败 ≥ 3 次 |
| BANNED 阈值 | 连续失败 ≥ 5 次 |
| 冷却时间 | 30min |
| 池底阈值 | ≤ 5 个 |

## 免费代理源

### 多源聚合

内置采集源按类型分组：

- HTTP/HTTPS 列表源：proxyscrape.com、free-proxy-list.net、proxy-list.download、proxylist.geonode.com
- SOCKS5 列表源：socks-proxy.net、openproxy.space、hidemy.name
- GitHub 仓库源：TheSpeedX/PROXY-List、monosans/proxy-list、jetkai/proxy-list
- 聚合 API 源：proxylist.geonode.com/api、api.proxyscrape.com/v2

### 聚合策略

- 多源同时采集 → 去重合并（ip:port 唯一键）→ 并发验证（50 并发）→ 入池评分
- 交叉验证加权：同一 IP 出现在多个源中，初始分 +20
- 时效性加权：最近 30 分钟内采集的 IP，初始分 +10
- 速度加权：< 1s +15 分，1-3s +5 分，> 3s +0 分
- 匿名度过滤：透明代理直接丢弃，只保留匿名和高匿

### 动态更新

| 触发机制 | 条件 | 行为 |
|----------|------|------|
| 定时刷新 | 每 5-10 分钟 | 从所有源拉取最新列表 |
| 阈值触发 | 可用 IP 降至最低线以下 | 立即全量采集，降低验证标准 |
| 紧急补充 | 可用 IP 归零 | 跳过验证直接入库，边用边验 |
| 手动注入 | 用户 CLI/WebUI 添加 | 直接插入验证流水线 |

### 采集器接口

```python
class BaseCollector(ABC):
    @property
    def name(self) -> str: ...
    @property
    def interval(self) -> int: ...  # 采集间隔(秒)
    async def collect(self) -> list[ProxyEntry]: ...
    async def validate(self, proxy: ProxyEntry) -> bool: ...
```

## Tor 集成

Tor 作为独立匿名转发层，不替代代理源，可插入链路中任意位置。

### 三种使用模式

| 模式 | 链路 | 隐匿性 | 速度 |
|------|------|--------|------|
| 纯 Tor | `tor → target` | 强 | 慢(100-500ms) |
| 免费代理 + Tor | `free → tor → target` | 强 | 较慢(叠加) |
| Tor + 付费代理 | `tor → paid → target` | 极强 | 慢 |

### 系统依赖

工具不内置 Tor，连接本地 Tor 守护进程。启动时自动检测 `127.0.0.1:9050`，不可用时给出各平台安装指引。

### CLI 示例

```bash
proxy start --provider tor                           # 纯 Tor
proxy start --provider free --relay tor              # 免费代理 → Tor
proxy start --provider paid --api-key xxx --entry tor # Tor → 付费代理
proxy start --chain free,tor,self-relay              # 自定义链路
proxy start --provider free --hops 1                 # 纯免费单跳(不用Tor)
```

## 目录结构

```
proxy-vault/
├── pyproject.toml
├── config.yaml
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── server/
│   │   ├── http_proxy.py
│   │   └── socks5_proxy.py
│   ├── core/
│   │   ├── proxy_manager.py
│   │   ├── relay_chain.py
│   │   ├── ip_rotator.py
│   │   └── health_monitor.py
│   ├── providers/
│   │   ├── base.py
│   │   ├── free_pool.py
│   │   ├── paid_adapter.py
│   │   ├── self_relay.py
│   │   ├── tor_relay.py
│   │   └── collectors/
│   ├── webui/
│   │   ├── app.py
│   │   ├── api.py
│   │   └── templates/
│   └── cli/
│       └── commands.py
└── tests/
```

## CLI 命令

```bash
proxy start    # 启动代理服务（默认：免费池+单跳）
proxy stop     # 停止代理服务
proxy status   # 查看当前状态
proxy switch   # 切换代理模式/更换当前IP
proxy config   # 查看/修改配置
proxy web      # 启动 Web 管理控制台

# 启动选项
--provider   free|paid|tor|self|custom
--mode       single|pool
--chain      free,tor,self
--proxy      socks5://1.2.3.4:1080
--port       1080
--api-key    xxx
```

## Web UI

管理控制台（FastAPI + HTMX + 原生 HTML），功能：

- 仪表盘：代理状态、当前 IP、流量统计、连接数
- 代理控制：切换模式（单IP/池/链路）、手动换 IP
- 配置管理：代理源选择、API Key、端口、跳数
- 启停控制：启动/停止/重启代理服务
- 池子状态：可用 IP 数、评分分布、健康趋势

## 并发模型

- `asyncio` 驱动全链路异步
- 代理验证：`asyncio.gather()` 50 并发探测
- 请求处理：每个客户端连接 → 独立 `asyncio.Task`
- 健康检查：后台协程定时执行
- 采集器：各源独立协程，按各自间隔触发
