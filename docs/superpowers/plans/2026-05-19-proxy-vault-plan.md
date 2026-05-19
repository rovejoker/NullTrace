# Proxy Vault Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an IP-hiding proxy tool (like Tor) for security pentesting with CLI + Web UI, supporting free proxy pools, paid APIs, Tor relay, and custom proxy chains.

**Architecture:** Four-layer async Python app — Interface (click CLI + FastAPI/HTMX Web UI), Core Engine (ProxyManager/RelayChain/IPRotator/HealthMonitor), Providers (FreePool/PaidAPI/TorRelay/Custom), Protocol (HTTP & SOCKS5 proxy servers). All providers implement a common `BaseProvider` interface for pluggability.

**Tech Stack:** Python 3.11+, asyncio, FastAPI, click, aiohttp, python-socks, HTMX, YAML config

---

### Task 1: Project Scaffolding & Data Models

**Files:**
- Create: `pyproject.toml`
- Create: `config.yaml`
- Create: `src/proxy_vault/__init__.py`
- Create: `src/proxy_vault/models.py`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "proxy-vault"
version = "0.1.0"
description = "IP-hiding proxy tool for security pentesting"
requires-python = ">=3.11"
dependencies = [
    "aiohttp>=3.9",
    "click>=8.1",
    "fastapi>=0.109",
    "uvicorn>=0.27",
    "python-socks[asyncio]>=2.4",
    "pyyaml>=6.0",
    "httpx>=0.26",
    "jinja2>=3.1",
]

[tool.setuptools.packages.find]
where = ["src"]

[project.scripts]
proxy = "proxy_vault.main:cli"

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "pytest-cov>=4.1",
]
```

- [ ] **Step 2: Write `config.yaml`**

```yaml
proxy:
  host: "127.0.0.1"
  port: 1080

defaults:
  provider: free
  mode: pool
  hops: 1

free_pool:
  min_pool_size: 10
  max_pool_size: 200
  health_check_interval: 60
  request_timeout: 10
  max_retries: 3
  unstable_threshold: 3
  banned_threshold: 5
  cooldown_minutes: 30
  validate_concurrency: 50
  collect_interval_min: 5
  collect_interval_max: 10

tor:
  host: "127.0.0.1"
  port: 9050

paid:
  api_key: ""
  api_endpoint: ""

self_relay:
  nodes_file: "nodes.json"

webui:
  host: "127.0.0.1"
  port: 8080
```

- [ ] **Step 3: Write `src/proxy_vault/models.py`**

```python
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from typing import Optional


class ProxyStatus(Enum):
    UNKNOWN = "unknown"
    TESTING = "testing"
    ACTIVE = "active"
    UNSTABLE = "unstable"
    BANNED = "banned"


class ProxyType(Enum):
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


class AnonymityLevel(Enum):
    TRANSPARENT = "transparent"
    ANONYMOUS = "anonymous"
    ELITE = "elite"


@dataclass
class ProxyEntry:
    host: str
    port: int
    types: list[ProxyType] = field(default_factory=list)
    anonymity: AnonymityLevel = AnonymityLevel.ANONYMOUS
    status: ProxyStatus = ProxyStatus.UNKNOWN
    score: int = 50
    latency_ms: int = 0
    success_count: int = 0
    fail_count: int = 0
    consecutive_fails: int = 0
    sources: set[str] = field(default_factory=set)
    country: str = ""
    last_checked: Optional[datetime] = None
    last_used: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def is_available(self) -> bool:
        return self.status in (ProxyStatus.ACTIVE, ProxyStatus.UNSTABLE)


@dataclass
class ChainNode:
    provider: str
    config: dict = field(default_factory=dict)


@dataclass
class ProxyState:
    running: bool = False
    provider: str = "free"
    mode: str = "pool"
    chain: list[ChainNode] = field(default_factory=list)
    current_ip: Optional[str] = None
    pool_size: int = 0
    active_connections: int = 0
    total_requests: int = 0
    uptime_seconds: int = 0
```

- [ ] **Step 4: Write `src/proxy_vault/__init__.py`**

```python
"""Proxy Vault - IP-hiding proxy tool for security pentesting."""
__version__ = "0.1.0"
```

- [ ] **Step 5: Write `tests/__init__.py`** — empty file

- [ ] **Step 6: Write `tests/conftest.py`**

```python
import pytest
from proxy_vault.models import ProxyEntry, ProxyType, ProxyStatus, AnonymityLevel


@pytest.fixture
def sample_proxy():
    return ProxyEntry(
        host="1.2.3.4",
        port=8080,
        types=[ProxyType.HTTP],
        anonymity=AnonymityLevel.ELITE,
        status=ProxyStatus.ACTIVE,
        score=70,
        latency_ms=200,
    )


@pytest.fixture
def sample_proxies():
    return [
        ProxyEntry(host=f"10.0.0.{i}", port=8080 + i, types=[ProxyType.HTTP])
        for i in range(1, 6)
    ]
```

- [ ] **Step 7: Verify tests pass**

Run: `pip install -e ".[dev]" && pytest tests/ -v`
Expected: PASS (0 tests collected or just conftest loads)

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml config.yaml src/ tests/
git commit -m "feat: project scaffolding with data models and config"
```

---

### Task 2: Base Provider Interface

**Files:**
- Create: `src/proxy_vault/providers/__init__.py`
- Create: `src/proxy_vault/providers/base.py`
- Create: `tests/providers/__init__.py`
- Create: `tests/providers/test_base.py`

- [ ] **Step 1: Write `src/proxy_vault/providers/base.py`**

```python
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from proxy_vault.models import ProxyEntry


class BaseProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique provider identifier."""

    @abstractmethod
    async def fetch_proxies(self) -> list[ProxyEntry]:
        """Fetch proxy list from this provider. Returns empty list if unavailable."""

    async def get_proxy(self) -> ProxyEntry | None:
        """Get a single proxy. Override for providers that don't use a pool."""
        proxies = await self.fetch_proxies()
        return proxies[0] if proxies else None

    async def validate(self, proxy: ProxyEntry) -> bool:
        """Validate a single proxy is reachable. Base: TCP connect check."""
        import asyncio
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(proxy.host, proxy.port),
                timeout=5,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def startup(self) -> None:
        """Called when the provider is activated."""

    async def shutdown(self) -> None:
        """Called when the provider is deactivated."""

    @property
    def max_hops(self) -> int:
        """Maximum relay hops supported by this provider."""
        return 1
```

- [ ] **Step 2: Write `tests/providers/test_base.py`**

```python
import pytest
from proxy_vault.providers.base import BaseProvider
from proxy_vault.models import ProxyEntry, ProxyType, ProxyStatus


class MockProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "mock"

    async def fetch_proxies(self) -> list[ProxyEntry]:
        return [
            ProxyEntry(host="1.2.3.4", port=8080, types=[ProxyType.HTTP], status=ProxyStatus.ACTIVE)
        ]


@pytest.mark.asyncio
async def test_provider_name():
    p = MockProvider()
    assert p.name == "mock"


@pytest.mark.asyncio
async def test_fetch_proxies():
    p = MockProvider()
    proxies = await p.fetch_proxies()
    assert len(proxies) == 1
    assert proxies[0].host == "1.2.3.4"


@pytest.mark.asyncio
async def test_get_proxy_returns_first():
    p = MockProvider()
    proxy = await p.get_proxy()
    assert proxy is not None
    assert proxy.host == "1.2.3.4"


@pytest.mark.asyncio
async def test_get_proxy_empty():
    class EmptyProvider(BaseProvider):
        @property
        def name(self) -> str:
            return "empty"
        async def fetch_proxies(self) -> list[ProxyEntry]:
            return []

    p = EmptyProvider()
    proxy = await p.get_proxy()
    assert proxy is None


@pytest.mark.asyncio
async def test_default_max_hops():
    p = MockProvider()
    assert p.max_hops == 1


@pytest.mark.asyncio
async def test_validate_unreachable():
    p = MockProvider()
    bad = ProxyEntry(host="10.255.255.1", port=9999, types=[ProxyType.HTTP])
    result = await p.validate(bad)
    assert result is False
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/providers/test_base.py -v`
Expected: 6 PASS

- [ ] **Step 4: Write `src/proxy_vault/providers/__init__.py`**

```python
from proxy_vault.providers.base import BaseProvider

__all__ = ["BaseProvider"]
```

- [ ] **Step 5: Commit**

```bash
git add src/proxy_vault/providers/ tests/providers/
git commit -m "feat: add BaseProvider interface"
```

---

### Task 3: Config Manager

**Files:**
- Create: `src/proxy_vault/config.py`
- Create: `tests/test_config.py`

- [ ] **Step 1: Write `tests/test_config.py`**

```python
import yaml

def test_config_has_required_sections():
    with open("config.yaml") as f:
        config = yaml.safe_load(f)
    assert "proxy" in config
    assert "defaults" in config
    assert "free_pool" in config
    assert "tor" in config
    assert "webui" in config


def test_proxy_defaults():
    with open("config.yaml") as f:
        config = yaml.safe_load(f)
    assert config["proxy"]["host"] == "127.0.0.1"
    assert config["proxy"]["port"] == 1080
    assert config["defaults"]["provider"] == "free"
```

- [ ] **Step 2: Write `src/proxy_vault/config.py`**

```python
import os
import yaml
from pathlib import Path
from typing import Any


class Config:
    _instance = None

    def __init__(self, path: str | None = None):
        if path is None:
            path = os.environ.get("PROXY_VAULT_CONFIG", "config.yaml")
        self._path = Path(path)
        self._data: dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        if self._path.exists():
            with open(self._path) as f:
                self._data = yaml.safe_load(f) or {}

    def save(self) -> None:
        with open(self._path, "w") as f:
            yaml.safe_dump(self._data, f, default_flow_style=False)

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split(".")
        value = self._data
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        return value if value is not None else default

    def set(self, key: str, value: Any) -> None:
        keys = key.split(".")
        d = self._data
        for k in keys[:-1]:
            if k not in d:
                d[k] = {}
            d = d[k]
        d[keys[-1]] = value

    @property
    def proxy_host(self) -> str:
        return self.get("proxy.host", "127.0.0.1")

    @property
    def proxy_port(self) -> int:
        return self.get("proxy.port", 1080)

    @property
    def webui_port(self) -> int:
        return self.get("webui.port", 8080)

    @property
    def data(self) -> dict:
        return self._data


config = Config()
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/test_config.py -v`
Expected: 2 PASS

- [ ] **Step 4: Commit**

```bash
git add src/proxy_vault/config.py tests/test_config.py
git commit -m "feat: add config manager"
```

---

### Task 4: Free Proxy Collectors

**Files:**
- Create: `src/proxy_vault/providers/collectors/__init__.py`
- Create: `src/proxy_vault/providers/collectors/http_collectors.py`
- Create: `src/proxy_vault/providers/collectors/socks_collectors.py`
- Create: `src/proxy_vault/providers/collectors/github_collectors.py`
- Create: `src/proxy_vault/providers/collectors/api_collectors.py`
- Create: `tests/providers/collectors/__init__.py`
- Create: `tests/providers/collectors/test_http_collectors.py`

- [ ] **Step 1: Write `tests/providers/collectors/test_http_collectors.py`**

```python
import pytest
from proxy_vault.providers.collectors.http_collectors import (
    ProxyScrapeCollector,
    FreeProxyListCollector,
)


def test_proxyscrape_name():
    c = ProxyScrapeCollector()
    assert c.name == "proxyscrape"


def test_proxyscrape_has_interval():
    c = ProxyScrapeCollector()
    assert c.interval > 0


def test_free_proxy_list_name():
    c = FreeProxyListCollector()
    assert c.name == "free-proxy-list"


@pytest.mark.asyncio
async def test_proxyscrape_collect_returns_list():
    c = ProxyScrapeCollector()
    proxies = await c.collect()
    assert isinstance(proxies, list)
    for p in proxies:
        assert p.host
        assert p.port > 0


@pytest.mark.asyncio
async def test_free_proxy_list_collect_returns_list():
    c = FreeProxyListCollector()
    proxies = await c.collect()
    assert isinstance(proxies, list)
```

- [ ] **Step 2: Write `src/proxy_vault/providers/collectors/http_collectors.py`**

```python
import re
import aiohttp
from proxy_vault.models import ProxyEntry, ProxyType, AnonymityLevel
from proxy_vault.providers.base import BaseProvider


class ProxyScrapeCollector(BaseProvider):
    @property
    def name(self) -> str:
        return "proxyscrape"

    @property
    def interval(self) -> int:
        return 600

    async def fetch_proxies(self) -> list[ProxyEntry]:
        return await self.collect()

    async def collect(self) -> list[ProxyEntry]:
        proxies = []
        url = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    text = await resp.text()
                    for line in text.strip().split("\n"):
                        line = line.strip()
                        if ":" in line:
                            host, port = line.rsplit(":", 1)
                            if port.isdigit():
                                proxies.append(ProxyEntry(
                                    host=host.strip(),
                                    port=int(port.strip()),
                                    types=[ProxyType.HTTP],
                                    anonymity=AnonymityLevel.ANONYMOUS,
                                    sources={self.name},
                                ))
        except Exception:
            pass
        return proxies


class FreeProxyListCollector(BaseProvider):
    @property
    def name(self) -> str:
        return "free-proxy-list"

    @property
    def interval(self) -> int:
        return 600

    async def fetch_proxies(self) -> list[ProxyEntry]:
        return await self.collect()

    async def collect(self) -> list[ProxyEntry]:
        proxies = []
        url = "https://free-proxy-list.net/"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    text = await resp.text()
                    pattern = re.compile(
                        r'<tr><td>(\d+\.\d+\.\d+\.\d+)</td><td>(\d+)</td>'
                        r'<td>[^<]*</td><td>[^<]*</td><td>((?:anonymous|elite proxy)[^<]*)</td>',
                        re.IGNORECASE,
                    )
                    for match in pattern.finditer(text):
                        host = match.group(1)
                        port = int(match.group(2))
                        anon_text = match.group(3).lower()
                        anonymity = AnonymityLevel.ELITE if "elite" in anon_text else AnonymityLevel.ANONYMOUS
                        proxies.append(ProxyEntry(
                            host=host, port=port,
                            types=[ProxyType.HTTP],
                            anonymity=anonymity,
                            sources={self.name},
                        ))
        except Exception:
            pass
        return proxies
```

- [ ] **Step 3: Write `src/proxy_vault/providers/collectors/socks_collectors.py`**

```python
import re
import aiohttp
from proxy_vault.models import ProxyEntry, ProxyType, AnonymityLevel
from proxy_vault.providers.base import BaseProvider


class SocksProxyCollector(BaseProvider):
    @property
    def name(self) -> str:
        return "socks-proxy"

    @property
    def interval(self) -> int:
        return 600

    async def fetch_proxies(self) -> list[ProxyEntry]:
        return await self.collect()

    async def collect(self) -> list[ProxyEntry]:
        proxies = []
        url = "https://socks-proxy.net/"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    text = await resp.text()
                    pattern = re.compile(
                        r'<tr><td>(\d+\.\d+\.\d+\.\d+)</td><td>(\d+)</td>'
                        r'<td>[^<]*</td><td>[^<]*</td><td>(Socks[45][^<]*)</td>',
                        re.IGNORECASE,
                    )
                    for match in pattern.finditer(text):
                        host = match.group(1)
                        port = int(match.group(2))
                        socks_type = match.group(3).lower()
                        ptype = ProxyType.SOCKS5 if "5" in socks_type else ProxyType.SOCKS4
                        proxies.append(ProxyEntry(
                            host=host, port=port,
                            types=[ptype],
                            anonymity=AnonymityLevel.ANONYMOUS,
                            sources={self.name},
                        ))
        except Exception:
            pass
        return proxies


class OpenProxySpaceCollector(BaseProvider):
    @property
    def name(self) -> str:
        return "openproxy-space"

    @property
    def interval(self) -> int:
        return 600

    async def fetch_proxies(self) -> list[ProxyEntry]:
        return await self.collect()

    async def collect(self) -> list[ProxyEntry]:
        proxies = []
        url = "https://api.openproxylist.xyz/socks5.txt"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    text = await resp.text()
                    for line in text.strip().split("\n"):
                        line = line.strip()
                        if ":" in line and not line.startswith("#"):
                            host, port = line.rsplit(":", 1)
                            if port.isdigit():
                                proxies.append(ProxyEntry(
                                    host=host.strip(),
                                    port=int(port.strip()),
                                    types=[ProxyType.SOCKS5],
                                    anonymity=AnonymityLevel.ANONYMOUS,
                                    sources={self.name},
                                ))
        except Exception:
            pass
        return proxies
```

- [ ] **Step 4: Write `src/proxy_vault/providers/collectors/github_collectors.py`**

```python
import aiohttp
from proxy_vault.models import ProxyEntry, ProxyType, AnonymityLevel
from proxy_vault.providers.base import BaseProvider


class TheSpeedXCollector(BaseProvider):
    @property
    def name(self) -> str:
        return "thespeedx"

    @property
    def interval(self) -> int:
        return 600

    async def fetch_proxies(self) -> list[ProxyEntry]:
        return await self.collect()

    async def collect(self) -> list[ProxyEntry]:
        proxies = []
        urls = [
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        ]
        type_map = {0: ProxyType.HTTP, 1: ProxyType.SOCKS4, 2: ProxyType.SOCKS5}
        async with aiohttp.ClientSession() as session:
            for i, url in enumerate(urls):
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        text = await resp.text()
                        for line in text.strip().split("\n"):
                            line = line.strip()
                            if ":" in line:
                                host, port = line.rsplit(":", 1)
                                if port.isdigit():
                                    proxies.append(ProxyEntry(
                                        host=host.strip(),
                                        port=int(port.strip()),
                                        types=[type_map[i]],
                                        anonymity=AnonymityLevel.ANONYMOUS,
                                        sources={self.name},
                                    ))
                except Exception:
                    pass
        return proxies


class MonosansCollector(BaseProvider):
    @property
    def name(self) -> str:
        return "monosans"

    @property
    def interval(self) -> int:
        return 600

    async def fetch_proxies(self) -> list[ProxyEntry]:
        return await self.collect()

    async def collect(self) -> list[ProxyEntry]:
        proxies = []
        url = "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    text = await resp.text()
                    for line in text.strip().split("\n"):
                        line = line.strip()
                        if ":" in line and not line.startswith("#"):
                            parts = line.split("|")[0].strip()
                            host, port = parts.rsplit(":", 1)
                            if port.isdigit():
                                proxies.append(ProxyEntry(
                                    host=host.strip(),
                                    port=int(port.strip()),
                                    types=[ProxyType.HTTP, ProxyType.SOCKS5],
                                    anonymity=AnonymityLevel.ANONYMOUS,
                                    sources={self.name},
                                ))
        except Exception:
            pass
        return proxies
```

- [ ] **Step 5: Write `src/proxy_vault/providers/collectors/api_collectors.py`**

```python
import aiohttp
from proxy_vault.models import ProxyEntry, ProxyType, AnonymityLevel
from proxy_vault.providers.base import BaseProvider


class GeonodeCollector(BaseProvider):
    @property
    def name(self) -> str:
        return "geonode"

    @property
    def interval(self) -> int:
        return 600

    async def fetch_proxies(self) -> list[ProxyEntry]:
        return await self.collect()

    async def collect(self) -> list[ProxyEntry]:
        proxies = []
        url = "https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc&filterUpTime=80&protocols=http,https,socks4,socks5"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    data = await resp.json()
                    for item in data.get("data", []):
                        protocols = item.get("protocols", [])
                        ptypes = []
                        for proto in protocols:
                            if proto == "http":
                                ptypes.append(ProxyType.HTTP)
                            elif proto == "https":
                                ptypes.append(ProxyType.HTTPS)
                            elif proto == "socks4":
                                ptypes.append(ProxyType.SOCKS4)
                            elif proto == "socks5":
                                ptypes.append(ProxyType.SOCKS5)
                        anonymity = AnonymityLevel.ELITE if item.get("anonymityLevel") == "elite" else AnonymityLevel.ANONYMOUS
                        proxies.append(ProxyEntry(
                            host=item["ip"],
                            port=int(item["port"]),
                            types=ptypes,
                            anonymity=anonymity,
                            country=item.get("country", ""),
                            latency_ms=int(item.get("responseTime", 0)),
                            sources={self.name},
                        ))
        except Exception:
            pass
        return proxies


class ProxyScrapeV2Collector(BaseProvider):
    @property
    def name(self) -> str:
        return "proxyscrape-v2"

    @property
    def interval(self) -> int:
        return 600

    async def fetch_proxies(self) -> list[ProxyEntry]:
        return await self.collect()

    async def collect(self) -> list[ProxyEntry]:
        proxies = []
        endpoints = [
            ("https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000", ProxyType.HTTP),
            ("https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000", ProxyType.SOCKS5),
        ]
        async with aiohttp.ClientSession() as session:
            for url, ptype in endpoints:
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        text = await resp.text()
                        for line in text.strip().split("\n"):
                            line = line.strip()
                            if ":" in line:
                                host, port = line.rsplit(":", 1)
                                if port.isdigit():
                                    proxies.append(ProxyEntry(
                                        host=host.strip(),
                                        port=int(port.strip()),
                                        types=[ptype],
                                        anonymity=AnonymityLevel.ANONYMOUS,
                                        sources={self.name},
                                    ))
                except Exception:
                    pass
        return proxies
```

- [ ] **Step 6: Write `src/proxy_vault/providers/collectors/__init__.py`**

```python
from proxy_vault.providers.collectors.http_collectors import ProxyScrapeCollector, FreeProxyListCollector
from proxy_vault.providers.collectors.socks_collectors import SocksProxyCollector, OpenProxySpaceCollector
from proxy_vault.providers.collectors.github_collectors import TheSpeedXCollector, MonosansCollector
from proxy_vault.providers.collectors.api_collectors import GeonodeCollector, ProxyScrapeV2Collector

ALL_COLLECTORS = [
    ProxyScrapeCollector,
    FreeProxyListCollector,
    SocksProxyCollector,
    OpenProxySpaceCollector,
    TheSpeedXCollector,
    MonosansCollector,
    GeonodeCollector,
    ProxyScrapeV2Collector,
]
```

- [ ] **Step 7: Run tests**

Run: `pytest tests/providers/collectors/ -v`
Expected: tests pass (collectors return lists; network-dependent tests may be skipped)

- [ ] **Step 8: Commit**

```bash
git add src/proxy_vault/providers/collectors/ tests/providers/collectors/
git commit -m "feat: add free proxy collectors (8 sources)"
```

---

### Task 5: Free Proxy Pool Manager

**Files:**
- Create: `src/proxy_vault/providers/free_pool.py`
- Create: `tests/providers/test_free_pool.py`

- [ ] **Step 1: Write `tests/providers/test_free_pool.py`**

```python
import pytest
from proxy_vault.providers.free_pool import FreeProxyPool
from proxy_vault.models import ProxyEntry, ProxyType, ProxyStatus, AnonymityLevel
from proxy_vault.config import config


@pytest.fixture
def pool():
    return FreeProxyPool()


def make_proxy(host, port, score=50, status=ProxyStatus.ACTIVE, sources=None):
    return ProxyEntry(
        host=host, port=port,
        types=[ProxyType.HTTP],
        anonymity=AnonymityLevel.ELITE,
        status=status, score=score,
        sources=sources or {"test"},
    )


def test_pool_starts_empty(pool):
    assert pool.size == 0
    assert len(pool.get_available()) == 0


def test_add_proxy_increases_size(pool):
    pool.add(make_proxy("1.1.1.1", 80))
    assert pool.size == 1


def test_add_duplicate_ignored(pool):
    p1 = make_proxy("1.1.1.1", 80)
    p2 = make_proxy("1.1.1.1", 80)
    pool.add(p1)
    pool.add(p2)
    assert pool.size == 1


def test_add_duplicate_merges_sources(pool):
    p1 = make_proxy("1.1.1.1", 80, sources={"src_a"})
    p2 = make_proxy("1.1.1.1", 80, sources={"src_b"})
    pool.add(p1)
    pool.add(p2)
    proxy = pool.get_available()[0]
    assert "src_a" in proxy.sources
    assert "src_b" in proxy.sources
    assert proxy.score >= 70  # cross-validation bonus +20


def test_cross_validation_bonus(pool):
    p1 = make_proxy("1.1.1.1", 80, sources={"a", "b", "c"})
    pool.add(p1)
    proxy = pool.get_available()[0]
    assert proxy.score >= 50  # base score maintained, multi-source bonus added at add time


def test_get_available_returns_active_only(pool):
    pool.add(make_proxy("1.1.1.1", 80, status=ProxyStatus.ACTIVE))
    pool.add(make_proxy("2.2.2.2", 80, status=ProxyStatus.BANNED))
    pool.add(make_proxy("3.3.3.3", 80, status=ProxyStatus.UNSTABLE))
    available = pool.get_available()
    assert len(available) == 2


def test_get_best_returns_highest_score(pool):
    pool.add(make_proxy("1.1.1.1", 80, score=30))
    pool.add(make_proxy("2.2.2.2", 80, score=90))
    pool.add(make_proxy("3.3.3.3", 80, score=60))
    best = pool.get_best()
    assert best.host == "2.2.2.2"


def test_get_best_empty_pool(pool):
    assert pool.get_best() is None


def test_mark_failure_increases_consecutive(pool):
    p = make_proxy("1.1.1.1", 80, status=ProxyStatus.ACTIVE)
    pool.add(p)
    pool.mark_failure("1.1.1.1:80")
    proxy = pool._proxies["1.1.1.1:80"]
    assert proxy.consecutive_fails == 1
    assert proxy.fail_count == 1


def test_mark_failure_triggers_unstable(pool):
    p = make_proxy("1.1.1.1", 80, status=ProxyStatus.ACTIVE, score=60)
    p.consecutive_fails = 2
    pool.add(p)
    pool._check_thresholds(pool._proxies["1.1.1.1:80"])
    assert pool._proxies["1.1.1.1:80"].status == ProxyStatus.UNSTABLE


def test_mark_success_resets_consecutive(pool):
    p = make_proxy("1.1.1.1", 80, status=ProxyStatus.UNSTABLE)
    p.consecutive_fails = 3
    pool.add(p)
    pool.mark_success("1.1.1.1:80", latency=100)
    proxy = pool._proxies["1.1.1.1:80"]
    assert proxy.consecutive_fails == 0
    assert proxy.success_count == 1


def test_remove_banned(pool):
    p = make_proxy("1.1.1.1", 80, status=ProxyStatus.BANNED)
    pool.add(p)
    pool.remove("1.1.1.1:80")
    assert pool.size == 0


def test_size_property(pool):
    for i in range(5):
        pool.add(make_proxy(f"1.1.1.{i}", 80))
    assert pool.size == 5


def test_get_stats(pool):
    pool.add(make_proxy("1.1.1.1", 80, status=ProxyStatus.ACTIVE, score=70))
    pool.add(make_proxy("2.2.2.2", 80, status=ProxyStatus.UNSTABLE, score=30))
    stats = pool.stats
    assert stats["total"] == 2
    assert stats["active"] == 1
    assert stats["unstable"] == 1
    assert "avg_score" in stats
```

- [ ] **Step 2: Write `src/proxy_vault/providers/free_pool.py`**

```python
import asyncio
import time
import random
from datetime import datetime, timedelta
from proxy_vault.models import ProxyEntry, ProxyStatus, AnonymityLevel
from proxy_vault.config import config


class FreeProxyPool:
    def __init__(self):
        self._proxies: dict[str, ProxyEntry] = {}
        self._lock = asyncio.Lock()

    @property
    def size(self) -> int:
        return len(self._proxies)

    def add(self, proxy: ProxyEntry) -> bool:
        key = proxy.key
        if key in self._proxies:
            existing = self._proxies[key]
            existing.sources.update(proxy.sources)
            if len(existing.sources) >= 2:
                existing.score = min(100, existing.score + 20)
            return False
        if proxy.anonymity == AnonymityLevel.TRANSPARENT:
            return False
        source_count = len(proxy.sources)
        if source_count >= 3:
            proxy.score = min(100, proxy.score + 30)
        elif source_count >= 2:
            proxy.score = min(100, proxy.score + 20)
        if proxy.latency_ms > 0 and proxy.latency_ms < 1000:
            proxy.score = min(100, proxy.score + 15)
        elif proxy.latency_ms > 0 and proxy.latency_ms < 3000:
            proxy.score = min(100, proxy.score + 5)
        proxy.created_at = datetime.now()
        self._proxies[key] = proxy
        return True

    def get_available(self) -> list[ProxyEntry]:
        return [p for p in self._proxies.values() if p.is_available]

    def get_best(self) -> ProxyEntry | None:
        available = self.get_available()
        if not available:
            return None
        return max(available, key=lambda p: p.score)

    def get_random(self) -> ProxyEntry | None:
        available = self.get_available()
        if not available:
            return None
        total = sum(p.score for p in available)
        if total == 0:
            return random.choice(available)
        r = random.uniform(0, total)
        cumulative = 0
        for p in available:
            cumulative += p.score
            if r <= cumulative:
                return p
        return available[-1]

    def get_worst(self) -> ProxyEntry | None:
        available = self.get_available()
        if not available:
            return None
        return min(available, key=lambda p: p.score)

    async def get_for_request(self) -> ProxyEntry | None:
        async with self._lock:
            proxy = self.get_random()
            if proxy:
                proxy.last_used = datetime.now()
            return proxy

    def mark_success(self, key: str, latency: int) -> None:
        proxy = self._proxies.get(key)
        if proxy is None:
            return
        proxy.success_count += 1
        proxy.consecutive_fails = 0
        proxy.latency_ms = int((proxy.latency_ms + latency) / 2)
        proxy.last_checked = datetime.now()
        proxy.score = min(100, proxy.score + 1)
        if proxy.status == ProxyStatus.UNSTABLE:
            if proxy.consecutive_fails == 0:
                proxy.status = ProxyStatus.ACTIVE

    def mark_failure(self, key: str) -> None:
        proxy = self._proxies.get(key)
        if proxy is None:
            return
        proxy.fail_count += 1
        proxy.consecutive_fails += 1
        proxy.last_checked = datetime.now()
        proxy.score = max(0, proxy.score - 5)
        self._check_thresholds(proxy)

    def _check_thresholds(self, proxy: ProxyEntry) -> None:
        unstable_threshold = config.get("free_pool.unstable_threshold", 3)
        banned_threshold = config.get("free_pool.banned_threshold", 5)
        if proxy.consecutive_fails >= banned_threshold:
            proxy.status = ProxyStatus.BANNED
        elif proxy.consecutive_fails >= unstable_threshold:
            proxy.status = ProxyStatus.UNSTABLE

    def remove(self, key: str) -> None:
        self._proxies.pop(key, None)

    def get_cooldown_proxies(self) -> list[ProxyEntry]:
        cooldown_minutes = config.get("free_pool.cooldown_minutes", 30)
        cutoff = datetime.now() - timedelta(minutes=cooldown_minutes)
        return [
            p for p in self._proxies.values()
            if p.status == ProxyStatus.BANNED
            and p.last_checked
            and p.last_checked < cutoff
        ]

    def recheck_cooldown(self) -> list[ProxyEntry]:
        return self.get_cooldown_proxies()

    @property
    def stats(self) -> dict:
        available = self.get_available()
        active = [p for p in available if p.status == ProxyStatus.ACTIVE]
        unstable = [p for p in available if p.status == ProxyStatus.UNSTABLE]
        scores = [p.score for p in self._proxies.values()]
        return {
            "total": len(self._proxies),
            "active": len(active),
            "unstable": len(unstable),
            "banned": len(self._proxies) - len(available),
            "avg_score": round(sum(scores) / len(scores), 1) if scores else 0,
            "min_pool_size": config.get("free_pool.min_pool_size", 10),
        }
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/providers/test_free_pool.py -v`
Expected: all tests PASS

- [ ] **Step 4: Commit**

```bash
git add src/proxy_vault/providers/free_pool.py tests/providers/test_free_pool.py
git commit -m "feat: add free proxy pool manager with scoring"
```

---

### Task 6: IP Rotator & Health Monitor

**Files:**
- Create: `src/proxy_vault/core/__init__.py`
- Create: `src/proxy_vault/core/ip_rotator.py`
- Create: `src/proxy_vault/core/health_monitor.py`
- Create: `tests/core/__init__.py`
- Create: `tests/core/test_ip_rotator.py`
- Create: `tests/core/test_health_monitor.py`

- [ ] **Step 1: Write `tests/core/test_ip_rotator.py`**

```python
import pytest
from proxy_vault.core.ip_rotator import IPRotator, RotationStrategy
from proxy_vault.models import ProxyEntry, ProxyType


def make_proxy(host):
    return ProxyEntry(host=host, port=80, types=[ProxyType.HTTP])


class TestRoundRobin:
    def test_round_robin_cycles(self):
        proxies = [make_proxy(f"1.1.1.{i}") for i in range(3)]
        rotator = IPRotator(RotationStrategy.ROUND_ROBIN)
        assert rotator.next(proxies).host == "1.1.1.1"
        assert rotator.next(proxies).host == "1.1.1.2"
        assert rotator.next(proxies).host == "1.1.1.3"
        assert rotator.next(proxies).host == "1.1.1.1"

    def test_round_robin_empty(self):
        rotator = IPRotator(RotationStrategy.ROUND_ROBIN)
        assert rotator.next([]) is None


class TestRandom:
    def test_random_returns_from_pool(self):
        proxies = [make_proxy(f"1.1.1.{i}") for i in range(10)]
        rotator = IPRotator(RotationStrategy.RANDOM)
        for _ in range(20):
            p = rotator.next(proxies)
            assert p is not None
            assert p.host.startswith("1.1.1.")


class TestWeighted:
    def test_weighted_prefers_high_score(self):
        proxies = [
            ProxyEntry(host="1.1.1.1", port=80, score=10, types=[ProxyType.HTTP]),
            ProxyEntry(host="2.2.2.2", port=80, score=90, types=[ProxyType.HTTP]),
        ]
        rotator = IPRotator(RotationStrategy.WEIGHTED)
        counts = {"1.1.1.1": 0, "2.2.2.2": 0}
        for _ in range(100):
            p = rotator.next(proxies)
            counts[p.host] += 1
        assert counts["2.2.2.2"] > counts["1.1.1.1"]


class TestFixed:
    def test_fixed_returns_same(self):
        proxies = [make_proxy(f"1.1.1.{i}") for i in range(5)]
        rotator = IPRotator(RotationStrategy.FIXED)
        first = rotator.next(proxies)
        for _ in range(10):
            assert rotator.next(proxies).host == first.host
```

- [ ] **Step 2: Write `src/proxy_vault/core/ip_rotator.py`**

```python
from enum import Enum
import random
from proxy_vault.models import ProxyEntry


class RotationStrategy(Enum):
    ROUND_ROBIN = "round_robin"
    RANDOM = "random"
    WEIGHTED = "weighted"
    FIXED = "fixed"


class IPRotator:
    def __init__(self, strategy: RotationStrategy = RotationStrategy.WEIGHTED):
        self._strategy = strategy
        self._index = 0
        self._fixed_proxy: str | None = None

    @property
    def strategy(self) -> RotationStrategy:
        return self._strategy

    @strategy.setter
    def strategy(self, value: RotationStrategy) -> None:
        self._strategy = value
        self._index = 0

    def next(self, proxies: list[ProxyEntry]) -> ProxyEntry | None:
        if not proxies:
            return None
        match self._strategy:
            case RotationStrategy.ROUND_ROBIN:
                return self._round_robin(proxies)
            case RotationStrategy.RANDOM:
                return random.choice(proxies)
            case RotationStrategy.WEIGHTED:
                return self._weighted(proxies)
            case RotationStrategy.FIXED:
                return self._fixed(proxies)
        return None

    def _round_robin(self, proxies: list[ProxyEntry]) -> ProxyEntry:
        proxy = proxies[self._index % len(proxies)]
        self._index += 1
        return proxy

    def _weighted(self, proxies: list[ProxyEntry]) -> ProxyEntry:
        total = sum(p.score for p in proxies)
        if total == 0:
            return random.choice(proxies)
        r = random.uniform(0, total)
        cumulative = 0
        for p in proxies:
            cumulative += p.score
            if r <= cumulative:
                return p
        return proxies[-1]

    def _fixed(self, proxies: list[ProxyEntry]) -> ProxyEntry:
        if self._fixed_proxy is None or not any(p.key == self._fixed_proxy for p in proxies):
            self._fixed_proxy = proxies[0].key
        for p in proxies:
            if p.key == self._fixed_proxy:
                return p
        self._fixed_proxy = proxies[0].key
        return proxies[0]

    def reset(self) -> None:
        self._index = 0
        self._fixed_proxy = None
```

- [ ] **Step 3: Write `tests/core/test_health_monitor.py`**

```python
import asyncio
import pytest
from proxy_vault.core.health_monitor import HealthMonitor
from proxy_vault.providers.free_pool import FreeProxyPool
from proxy_vault.models import ProxyEntry, ProxyType, ProxyStatus


@pytest.mark.asyncio
async def test_health_monitor_checks_proxies():
    pool = FreeProxyPool()
    p = ProxyEntry(host="127.0.0.1", port=9999, types=[ProxyType.HTTP], status=ProxyStatus.ACTIVE)
    pool.add(p)
    monitor = HealthMonitor(pool, check_interval=0.1)
    task = asyncio.create_task(monitor.start())
    await asyncio.sleep(0.3)
    monitor.stop()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert p.consecutive_fails > 0


@pytest.mark.asyncio
async def test_health_monitor_handles_empty_pool():
    pool = FreeProxyPool()
    monitor = HealthMonitor(pool, check_interval=0.1)
    task = asyncio.create_task(monitor.start())
    await asyncio.sleep(0.2)
    monitor.stop()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_is_running():
    pool = FreeProxyPool()
    monitor = HealthMonitor(pool)
    assert not monitor.is_running
    task = asyncio.create_task(monitor.start())
    await asyncio.sleep(0.1)
    assert monitor.is_running
    monitor.stop()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
```

- [ ] **Step 4: Write `src/proxy_vault/core/health_monitor.py`**

```python
import asyncio
from proxy_vault.providers.free_pool import FreeProxyPool
from proxy_vault.models import ProxyEntry, ProxyStatus
from proxy_vault.config import config


class HealthMonitor:
    def __init__(self, pool: FreeProxyPool, check_interval: float | None = None):
        self._pool = pool
        self._interval = check_interval or config.get("free_pool.health_check_interval", 60)
        self._running = False
        self._task: asyncio.Task | None = None

    @property
    def is_running(self) -> bool:
        return self._running

    async def start(self) -> None:
        self._running = True
        while self._running:
            await self._check_all()
            await asyncio.sleep(self._interval)

    async def _check_all(self) -> None:
        proxies = list(self._pool._proxies.values())
        if not proxies:
            return
        semaphore = asyncio.Semaphore(50)
        async def check_one(p: ProxyEntry):
            async with semaphore:
                import asyncio as asyncio_mod
                try:
                    _, writer = await asyncio_mod.wait_for(
                        asyncio_mod.open_connection(p.host, p.port),
                        timeout=5,
                    )
                    writer.close()
                    await writer.wait_closed()
                    self._pool.mark_success(p.key, latency=0)
                except Exception:
                    self._pool.mark_failure(p.key)
        await asyncio.gather(*[check_one(p) for p in proxies])

    async def check_single(self, proxy: ProxyEntry) -> bool:
        import asyncio as asyncio_mod
        try:
            _, writer = await asyncio_mod.wait_for(
                asyncio_mod.open_connection(proxy.host, proxy.port),
                timeout=5,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    def stop(self) -> None:
        self._running = False
```

- [ ] **Step 5: Write `src/proxy_vault/core/__init__.py`**

```python
from proxy_vault.core.ip_rotator import IPRotator, RotationStrategy
from proxy_vault.core.health_monitor import HealthMonitor

__all__ = ["IPRotator", "RotationStrategy", "HealthMonitor"]
```

- [ ] **Step 6: Run tests**

Run: `pytest tests/core/ -v`
Expected: all tests PASS

- [ ] **Step 7: Commit**

```bash
git add src/proxy_vault/core/ tests/core/
git commit -m "feat: add IP rotator and health monitor"
```

---

### Task 7: Relay Chain

**Files:**
- Create: `src/proxy_vault/core/relay_chain.py`
- Create: `tests/core/test_relay_chain.py`

- [ ] **Step 1: Write `tests/core/test_relay_chain.py`**

```python
import pytest
from proxy_vault.core.relay_chain import RelayChain
from proxy_vault.models import ChainNode


def test_relay_chain_parses_chain_string():
    chain = RelayChain.parse_chain("free,tor,self-relay")
    assert len(chain) == 3
    assert chain[0].provider == "free"
    assert chain[1].provider == "tor"
    assert chain[2].provider == "self-relay"


def test_relay_chain_parses_single():
    chain = RelayChain.parse_chain("tor")
    assert len(chain) == 1
    assert chain[0].provider == "tor"


def test_relay_chain_parses_empty():
    chain = RelayChain.parse_chain("")
    assert len(chain) == 0


def test_relay_chain_validates_hops():
    chain = RelayChain.parse_chain("free,tor,self-relay")
    assert RelayChain.validate_hops(chain, {"free": 1, "tor": 3, "self-relay": 5}) is True


def test_relay_chain_validates_hops_exceeded():
    chain = RelayChain.parse_chain("free,free,free")  # free only allows 1 hop
    assert RelayChain.validate_hops(chain, {"free": 1, "tor": 3}) is False


def test_relay_chain_to_list():
    chain = RelayChain.parse_chain("free,tor")
    result = RelayChain.to_provider_list(chain)
    assert result == ["free", "tor"]


def test_relay_chain_build_chain():
    chain = RelayChain.parse_chain("free,tor")
    nodes = RelayChain.build_chain(chain, target_host="example.com", target_port=443)
    assert len(nodes) == 2
    assert nodes[0]["provider"] == "free"
    assert nodes[1]["provider"] == "tor"
    assert nodes[1]["config"]["target_host"] == "example.com"
    assert nodes[1]["config"]["target_port"] == 443
```

- [ ] **Step 2: Write `src/proxy_vault/core/relay_chain.py`**

```python
from proxy_vault.models import ChainNode


class RelayChain:
    @staticmethod
    def parse_chain(chain_str: str) -> list[ChainNode]:
        if not chain_str.strip():
            return []
        providers = [p.strip() for p in chain_str.split(",") if p.strip()]
        return [ChainNode(provider=p) for p in providers]

    @staticmethod
    def validate_hops(chain: list[ChainNode], max_hops_map: dict[str, int]) -> bool:
        provider_counts: dict[str, int] = {}
        for node in chain:
            provider_counts[node.provider] = provider_counts.get(node.provider, 0) + 1
            if provider_counts[node.provider] > max_hops_map.get(node.provider, 1):
                return False
        return True

    @staticmethod
    def to_provider_list(chain: list[ChainNode]) -> list[str]:
        return [node.provider for node in chain]

    @staticmethod
    def build_chain(chain: list[ChainNode], target_host: str, target_port: int) -> list[dict]:
        nodes = []
        for i, node in enumerate(chain):
            is_last = (i == len(chain) - 1)
            config = {}
            if is_last:
                config["target_host"] = target_host
                config["target_port"] = target_port
            nodes.append({"provider": node.provider, "config": config})
        return nodes

    @staticmethod
    def resolve_entry(chain: list[ChainNode]) -> str | None:
        if not chain:
            return None
        return chain[0].provider

    @staticmethod
    def resolve_exit(chain: list[ChainNode]) -> str | None:
        if not chain:
            return None
        return chain[-1].provider
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/core/test_relay_chain.py -v`
Expected: all PASS

- [ ] **Step 4: Update `src/proxy_vault/core/__init__.py`**

```python
from proxy_vault.core.ip_rotator import IPRotator, RotationStrategy
from proxy_vault.core.health_monitor import HealthMonitor
from proxy_vault.core.relay_chain import RelayChain

__all__ = ["IPRotator", "RotationStrategy", "HealthMonitor", "RelayChain"]
```

- [ ] **Step 5: Commit**

```bash
git add src/proxy_vault/core/ tests/core/
git commit -m "feat: add relay chain parser and validator"
```

---

### Task 8: Tor, Custom, and Paid Providers

**Files:**
- Create: `src/proxy_vault/providers/tor_relay.py`
- Create: `src/proxy_vault/providers/custom_proxy.py`
- Create: `src/proxy_vault/providers/paid_adapter.py`
- Create: `tests/providers/test_tor_relay.py`
- Create: `tests/providers/test_custom_proxy.py`
- Create: `tests/providers/test_paid_adapter.py`

- [ ] **Step 1: Write `src/proxy_vault/providers/tor_relay.py`**

```python
from proxy_vault.providers.base import BaseProvider
from proxy_vault.models import ProxyEntry, ProxyType, AnonymityLevel
from proxy_vault.config import config


class TorRelayProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "tor"

    @property
    def max_hops(self) -> int:
        return 3

    async def fetch_proxies(self) -> list[ProxyEntry]:
        host = config.get("tor.host", "127.0.0.1")
        port = config.get("tor.port", 9050)
        return [ProxyEntry(
            host=host, port=port,
            types=[ProxyType.SOCKS5],
            anonymity=AnonymityLevel.ELITE,
            sources={"tor"},
        )]

    async def is_available(self) -> bool:
        host = config.get("tor.host", "127.0.0.1")
        port = config.get("tor.port", 9050)
        try:
            import asyncio
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=3,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
```

- [ ] **Step 2: Write `src/proxy_vault/providers/custom_proxy.py`**

```python
from proxy_vault.providers.base import BaseProvider
from proxy_vault.models import ProxyEntry, ProxyType, AnonymityLevel


class CustomProxyProvider(BaseProvider):
    def __init__(self, proxy_url: str):
        self._proxy_url = proxy_url
        self._parsed = self._parse_url(proxy_url)

    @property
    def name(self) -> str:
        return "custom"

    def _parse_url(self, url: str) -> dict:
        # Format: socks5://host:port or http://host:port
        parts = url.split("://")
        scheme = parts[0] if len(parts) > 1 else "http"
        host_port = parts[-1].rsplit(":", 1)
        host = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 1080
        ptype = ProxyType.SOCKS5 if "socks5" in scheme else ProxyType.HTTP
        return {"host": host, "port": port, "type": ptype, "scheme": scheme}

    async def fetch_proxies(self) -> list[ProxyEntry]:
        return [ProxyEntry(
            host=self._parsed["host"],
            port=self._parsed["port"],
            types=[self._parsed["type"]],
            anonymity=AnonymityLevel.ELITE,
            sources={"custom"},
        )]

    @property
    def proxy_url(self) -> str:
        return self._proxy_url
```

- [ ] **Step 3: Write `src/proxy_vault/providers/paid_adapter.py`**

```python
from proxy_vault.providers.base import BaseProvider
from proxy_vault.models import ProxyEntry, ProxyType, AnonymityLevel
from proxy_vault.config import config


class PaidAdapterProvider(BaseProvider):
    def __init__(self, api_key: str | None = None, endpoint: str | None = None):
        self._api_key = api_key or config.get("paid.api_key", "")
        self._endpoint = endpoint or config.get("paid.api_endpoint", "")

    @property
    def name(self) -> str:
        return "paid"

    @property
    def max_hops(self) -> int:
        return 2

    async def fetch_proxies(self) -> list[ProxyEntry]:
        if not self._api_key or not self._endpoint:
            return []
        import aiohttp
        proxies = []
        try:
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {self._api_key}"}
                async with session.get(self._endpoint, headers=headers,
                                       timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    data = await resp.json()
                    for item in data if isinstance(data, list) else data.get("proxies", []):
                        proxies.append(ProxyEntry(
                            host=item.get("host") or item.get("ip", ""),
                            port=int(item.get("port", 1080)),
                            types=[ProxyType.HTTP, ProxyType.SOCKS5],
                            anonymity=AnonymityLevel.ELITE,
                            sources={"paid"},
                        ))
        except Exception:
            pass
        return proxies

    @property
    def is_configured(self) -> bool:
        return bool(self._api_key and self._endpoint)
```

- [ ] **Step 4: Write tests for Tor provider**

```python
# tests/providers/test_tor_relay.py
import pytest
from proxy_vault.providers.tor_relay import TorRelayProvider


def test_tor_name():
    p = TorRelayProvider()
    assert p.name == "tor"


def test_tor_max_hops():
    p = TorRelayProvider()
    assert p.max_hops == 3


@pytest.mark.asyncio
async def test_tor_fetch_returns_entry():
    p = TorRelayProvider()
    proxies = await p.fetch_proxies()
    assert len(proxies) == 1
    assert proxies[0].host == "127.0.0.1"
    assert proxies[0].port == 9050


@pytest.mark.asyncio
async def test_tor_availability_check():
    p = TorRelayProvider()
    result = await p.is_available()
    assert isinstance(result, bool)
```

- [ ] **Step 5: Write tests for Custom and Paid providers**

```python
# tests/providers/test_custom_proxy.py
import pytest
from proxy_vault.providers.custom_proxy import CustomProxyProvider


def test_custom_parse_http():
    p = CustomProxyProvider("http://1.2.3.4:8080")
    assert p.name == "custom"
    proxies = p.fetch_proxies_sync()
    assert proxies[0].host == "1.2.3.4"
    assert proxies[0].port == 8080


def test_custom_parse_socks5():
    p = CustomProxyProvider("socks5://5.6.7.8:1080")
    proxies = p.fetch_proxies_sync()
    assert proxies[0].port == 1080


# tests/providers/test_paid_adapter.py
import pytest
from proxy_vault.providers.paid_adapter import PaidAdapterProvider


def test_paid_not_configured_by_default():
    p = PaidAdapterProvider()
    assert not p.is_configured


@pytest.mark.asyncio
async def test_paid_fetch_empty_when_not_configured():
    p = PaidAdapterProvider()
    proxies = await p.fetch_proxies()
    assert proxies == []
```

Note: Need to add `fetch_proxies_sync` helper to CustomProxyProvider. Update the file:

Add to `custom_proxy.py`:
```python
    def fetch_proxies_sync(self) -> list[ProxyEntry]:
        return [ProxyEntry(
            host=self._parsed["host"],
            port=self._parsed["port"],
            types=[self._parsed["type"]],
            anonymity=AnonymityLevel.ELITE,
            sources={"custom"},
        )]
```

- [ ] **Step 6: Update `src/proxy_vault/providers/__init__.py`**

```python
from proxy_vault.providers.base import BaseProvider
from proxy_vault.providers.tor_relay import TorRelayProvider
from proxy_vault.providers.custom_proxy import CustomProxyProvider
from proxy_vault.providers.paid_adapter import PaidAdapterProvider
from proxy_vault.providers.free_pool import FreeProxyPool

__all__ = [
    "BaseProvider",
    "TorRelayProvider",
    "CustomProxyProvider",
    "PaidAdapterProvider",
    "FreeProxyPool",
]
```

- [ ] **Step 7: Run tests**

Run: `pytest tests/providers/test_tor_relay.py tests/providers/test_custom_proxy.py tests/providers/test_paid_adapter.py -v`
Expected: all PASS

- [ ] **Step 8: Commit**

```bash
git add src/proxy_vault/providers/ tests/providers/
git commit -m "feat: add Tor, custom proxy, and paid adapter providers"
```

---

### Task 9: Proxy Manager (Orchestrator)

**Files:**
- Create: `src/proxy_vault/core/proxy_manager.py`
- Create: `tests/core/test_proxy_manager.py`

- [ ] **Step 1: Write `tests/core/test_proxy_manager.py`**

```python
import pytest
import asyncio
from proxy_vault.core.proxy_manager import ProxyManager
from proxy_vault.models import ProxyState


@pytest.fixture
def manager():
    return ProxyManager()


def test_initial_state(manager):
    state = manager.state
    assert state.running is False
    assert state.provider == "free"
    assert state.mode == "pool"


@pytest.mark.asyncio
async def test_start_stop(manager):
    await manager.start(provider="custom", proxy_url="socks5://1.2.3.4:1080", mode="single")
    assert manager.state.running is True
    assert manager.state.provider == "custom"
    assert manager.state.mode == "single"
    await manager.stop()
    assert manager.state.running is False


@pytest.mark.asyncio
async def test_start_free_pool(manager):
    await manager.start(provider="free", mode="pool")
    assert manager.state.running is True
    assert manager.state.provider == "free"
    await manager.stop()


@pytest.mark.asyncio
async def test_start_with_chain(manager):
    await manager.start(provider="free", chain="free,tor")
    assert manager.state.running is True
    await manager.stop()


@pytest.mark.asyncio
async def test_restart(manager):
    await manager.start(provider="free")
    await manager.stop()
    await manager.start(provider="tor")
    assert manager.state.provider == "tor"
    await manager.stop()


@pytest.mark.asyncio
async def test_get_available_proxies(manager):
    await manager.start(provider="free", mode="pool")
    await asyncio.sleep(0.5)  # allow collectors to run
    proxies = manager.get_available_proxies()
    assert isinstance(proxies, list)
    await manager.stop()


@pytest.mark.asyncio
async def test_switch_mode(manager):
    await manager.start(provider="free", mode="pool")
    manager.switch_mode("single")
    assert manager.state.mode == "single"
    await manager.stop()


def test_switch_mode_when_stopped(manager):
    manager.switch_mode("pool")
    assert manager.state.mode == "pool"
```

- [ ] **Step 2: Write `src/proxy_vault/core/proxy_manager.py`**

```python
import asyncio
import time
from proxy_vault.models import ProxyState, ProxyEntry, ChainNode
from proxy_vault.core.relay_chain import RelayChain
from proxy_vault.core.ip_rotator import IPRotator, RotationStrategy
from proxy_vault.core.health_monitor import HealthMonitor
from proxy_vault.providers.free_pool import FreeProxyPool
from proxy_vault.providers.tor_relay import TorRelayProvider
from proxy_vault.providers.custom_proxy import CustomProxyProvider
from proxy_vault.providers.paid_adapter import PaidAdapterProvider
from proxy_vault.providers.collectors import ALL_COLLECTORS
from proxy_vault.config import config


class ProxyManager:
    def __init__(self):
        self._state = ProxyState()
        self._pool: FreeProxyPool | None = None
        self._rotator = IPRotator()
        self._health_monitor: HealthMonitor | None = None
        self._collector_tasks: list[asyncio.Task] = []
        self._health_task: asyncio.Task | None = None
        self._start_time: float = 0
        self._custom_provider: CustomProxyProvider | None = None
        self._tor_provider = TorRelayProvider()
        self._paid_provider = PaidAdapterProvider()

    @property
    def state(self) -> ProxyState:
        return self._state

    async def start(self, provider: str = "free", mode: str = "pool",
                    chain: str = "", proxy_url: str = "",
                    api_key: str = "", port: int = 0) -> None:
        if self._state.running:
            await self.stop()

        self._state.provider = provider
        self._state.mode = mode

        if chain:
            self._state.chain = RelayChain.parse_chain(chain)
        else:
            self._state.chain = [ChainNode(provider=provider)]

        if provider == "free" or "free" in chain:
            self._pool = FreeProxyPool()
            self._health_monitor = HealthMonitor(self._pool)
            self._health_task = asyncio.create_task(self._health_monitor.start())
            for collector_cls in ALL_COLLECTORS:
                collector = collector_cls()
                task = asyncio.create_task(self._run_collector(collector))
                self._collector_tasks.append(task)

        if provider == "custom" or proxy_url:
            self._custom_provider = CustomProxyProvider(proxy_url)

        if provider == "paid" or api_key:
            self._paid_provider = PaidAdapterProvider(api_key=api_key) if api_key else PaidAdapterProvider()

        self._state.running = True
        self._start_time = time.time()

    async def _run_collector(self, collector) -> None:
        while self._state.running:
            try:
                proxies = await collector.collect()
                for p in proxies:
                    is_new = self._pool.add(p)
                    if is_new:
                        asyncio.create_task(self._validate_and_activate(p))
                min_size = config.get("free_pool.min_pool_size", 10)
                if self._pool.size < min_size:
                    await self._emergency_collect()
            except Exception:
                pass
            await asyncio.sleep(collector.interval)

    async def _validate_and_activate(self, proxy: ProxyEntry) -> None:
        try:
            import asyncio as asyncio_mod
            _, writer = await asyncio_mod.wait_for(
                asyncio_mod.open_connection(proxy.host, proxy.port),
                timeout=5,
            )
            writer.close()
            await writer.wait_closed()
            proxy.status = ProxyEntry.__dataclass_fields__["status"].type.ACTIVE if hasattr(ProxyEntry, '__dataclass_fields__') else __import__('proxy_vault.models', fromlist=['ProxyStatus']).ProxyStatus.ACTIVE
            from proxy_vault.models import ProxyStatus
            proxy.status = ProxyStatus.ACTIVE
            proxy.last_checked = __import__('datetime').datetime.now()
        except Exception:
            pass

    async def _emergency_collect(self) -> None:
        for collector_cls in ALL_COLLECTORS:
            try:
                collector = collector_cls()
                proxies = await collector.collect()
                for p in proxies:
                    self._pool.add(p)
            except Exception:
                pass

    async def stop(self) -> None:
        self._state.running = False
        for task in self._collector_tasks:
            task.cancel()
        self._collector_tasks.clear()
        if self._health_task:
            self._health_monitor.stop()
            self._health_task.cancel()
            self._health_task = None
        self._rotator.reset()

    def get_available_proxies(self) -> list[ProxyEntry]:
        if self._pool is None:
            return []
        return self._pool.get_available()

    async def get_next_proxy(self) -> ProxyEntry | None:
        if self._state.mode == "single":
            if self._custom_provider:
                return await self._custom_provider.get_proxy()
            if self._pool:
                return self._pool.get_best()
        if self._pool:
            return await self._pool.get_for_request()
        return None

    def mark_result(self, key: str, success: bool, latency: int = 0) -> None:
        if self._pool is None:
            return
        if success:
            self._pool.mark_success(key, latency)
        else:
            self._pool.mark_failure(key)

    def switch_mode(self, mode: str) -> None:
        self._state.mode = mode

    def rotate_ip(self) -> None:
        self._rotator.reset()
        self._pool.remove("")  # no-op, triggers rotation

    def get_stats(self) -> dict:
        uptime = int(time.time() - self._start_time) if self._start_time > 0 else 0
        pool_stats = self._pool.stats if self._pool else {}
        return {
            **pool_stats,
            "uptime_seconds": uptime,
            "running": self._state.running,
            "provider": self._state.provider,
            "mode": self._state.mode,
        }
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/core/test_proxy_manager.py -v`
Expected: all PASS

- [ ] **Step 4: Update core `__init__.py`**

```python
from proxy_vault.core.ip_rotator import IPRotator, RotationStrategy
from proxy_vault.core.health_monitor import HealthMonitor
from proxy_vault.core.relay_chain import RelayChain
from proxy_vault.core.proxy_manager import ProxyManager

__all__ = ["IPRotator", "RotationStrategy", "HealthMonitor", "RelayChain", "ProxyManager"]
```

- [ ] **Step 5: Commit**

```bash
git add src/proxy_vault/core/ tests/core/
git commit -m "feat: add proxy manager orchestrator"
```

---

### Task 10: HTTP Proxy Server

**Files:**
- Create: `src/proxy_vault/server/__init__.py`
- Create: `src/proxy_vault/server/http_proxy.py`
- Create: `tests/server/__init__.py`
- Create: `tests/server/test_http_proxy.py`

- [ ] **Step 1: Write `src/proxy_vault/server/http_proxy.py`**

```python
import asyncio
import aiohttp
from aiohttp import web
from proxy_vault.core.proxy_manager import ProxyManager
from proxy_vault.config import config


class HTTPProxyServer:
    def __init__(self, manager: ProxyManager):
        self._manager = manager
        self._app = web.Application()
        self._runner: web.AppRunner | None = None
        self._host = config.proxy_host
        self._port = config.proxy_port

    async def handle_request(self, request: web.Request) -> web.Response:
        proxy = await self._manager.get_next_proxy()
        if proxy is None:
            return web.Response(status=502, text="No proxy available")

        target_url = str(request.url)
        method = request.method
        headers = dict(request.headers)
        headers.pop("Host", None)
        body = await request.read()

        retries = config.get("free_pool.max_retries", 3)
        timeout = config.get("free_pool.request_timeout", 10)
        last_error = None

        for attempt in range(retries):
            try:
                proxy_url = f"http://{proxy.host}:{proxy.port}"
                async with aiohttp.ClientSession() as session:
                    async with session.request(
                        method, target_url,
                        headers=headers,
                        data=body,
                        proxy=proxy_url,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                    ) as resp:
                        response_body = await resp.read()
                        response_headers = dict(resp.headers)
                        response_headers.pop("Transfer-Encoding", None)
                        self._manager.mark_result(proxy.key, success=True,
                                                  latency=int(resp.headers.get("X-Response-Time", 0)))
                        return web.Response(
                            status=resp.status,
                            headers=response_headers,
                            body=response_body,
                        )
            except Exception as e:
                last_error = e
                self._manager.mark_result(proxy.key, success=False)
                if attempt < retries - 1:
                    proxy = await self._manager.get_next_proxy()
                    if proxy is None:
                        break

        return web.Response(status=502, text=f"Proxy error: {last_error}")

    async def handle_connect(self, request: web.Request) -> web.StreamResponse:
        """Handle CONNECT method for HTTPS tunneling."""
        proxy = await self._manager.get_next_proxy()
        if proxy is None:
            return web.Response(status=502, text="No proxy available")

        target_host = request.path.split(":")[0] if ":" in request.path else request.path
        target_port = int(request.path.split(":")[1]) if ":" in request.path else 443

        try:
            reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
            connect_req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
            writer.write(connect_req.encode())
            await writer.drain()
            response = await asyncio.wait_for(reader.readline(), timeout=10)
            if b"200" not in response:
                writer.close()
                return web.Response(status=502, text="Proxy CONNECT rejected")

            client_reader = request.transport
            ws = web.WebSocketResponse()
            await ws.prepare(request)

            async def forward(src_reader, dst_writer):
                try:
                    while True:
                        data = await asyncio.wait_for(src_reader.read(8192), timeout=300)
                        if not data:
                            break
                        dst_writer.write(data)
                        await dst_writer.drain()
                except Exception:
                    pass

            task1 = asyncio.create_task(forward(client_reader, writer))
            task2 = asyncio.create_task(forward(reader, client_reader))
            await asyncio.gather(task1, task2)
            writer.close()
            self._manager.mark_result(proxy.key, success=True)
            return ws
        except Exception as e:
            self._manager.mark_result(proxy.key, success=False)
            return web.Response(status=502, text=str(e))

    async def start(self) -> None:
        self._app.router.add_route("*", "/{path:.*}", self.handle_request)
        self._app.router.add_route("CONNECT", "/{path:.*}", self.handle_connect)
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self._host, self._port)
        await site.start()

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
```

- [ ] **Step 2: Run existing tests to verify imports**

Run: `python -c "from proxy_vault.server.http_proxy import HTTPProxyServer; print('OK')"`
Expected: OK

- [ ] **Step 3: Write `src/proxy_vault/server/__init__.py`**

```python
from proxy_vault.server.http_proxy import HTTPProxyServer

__all__ = ["HTTPProxyServer"]
```

- [ ] **Step 4: Commit**

```bash
git add src/proxy_vault/server/
git commit -m "feat: add HTTP proxy server with retry and CONNECT support"
```

---

### Task 11: SOCKS5 Proxy Server

**Files:**
- Create: `src/proxy_vault/server/socks5_proxy.py`
- Create: `tests/server/test_socks5_proxy.py`

- [ ] **Step 1: Write `src/proxy_vault/server/socks5_proxy.py`**

```python
import asyncio
import struct
import socket
from proxy_vault.core.proxy_manager import ProxyManager


SOCKS5_VERSION = 5
NO_AUTH = 0
USER_PASS_AUTH = 2
NO_ACCEPTABLE = 0xFF

CMD_CONNECT = 1
CMD_BIND = 2
CMD_UDP = 3

ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4

REP_SUCCESS = 0
REP_GENERAL_FAILURE = 1
REP_NOT_ALLOWED = 2
REP_NET_UNREACHABLE = 3
REP_HOST_UNREACHABLE = 4
REP_REFUSED = 5
REP_TTL_EXPIRED = 6
REP_CMD_NOT_SUPPORTED = 7
REP_ADDR_NOT_SUPPORTED = 8


class SOCKS5Server:
    def __init__(self, manager: ProxyManager, host: str = "127.0.0.1", port: int = 1080):
        self._manager = manager
        self._host = host
        self._port = port
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, self._host, self._port,
        )

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await self._handle_handshake(reader, writer)
            await self._handle_request(reader, writer)
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        version, nmethods = struct.unpack("!BB", await reader.readexactly(2))
        if version != SOCKS5_VERSION:
            writer.write(struct.pack("!BB", SOCKS5_VERSION, NO_ACCEPTABLE))
            await writer.drain()
            return
        methods = await reader.readexactly(nmethods)
        if NO_AUTH in methods:
            writer.write(struct.pack("!BB", SOCKS5_VERSION, NO_AUTH))
        else:
            writer.write(struct.pack("!BB", SOCKS5_VERSION, NO_ACCEPTABLE))
        await writer.drain()

    async def _handle_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        version, cmd, rsv, atyp = struct.unpack("!BBBB", await reader.readexactly(4))
        if version != SOCKS5_VERSION or cmd != CMD_CONNECT:
            self._send_reply(writer, REP_CMD_NOT_SUPPORTED)
            return

        if atyp == ATYP_IPV4:
            addr = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == ATYP_DOMAIN:
            domain_len = (await reader.readexactly(1))[0]
            addr = (await reader.readexactly(domain_len)).decode()
        elif atyp == ATYP_IPV6:
            addr = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        else:
            self._send_reply(writer, REP_ADDR_NOT_SUPPORTED)
            return

        port = struct.unpack("!H", await reader.readexactly(2))[0]

        proxy = await self._manager.get_next_proxy()
        if proxy is None:
            self._send_reply(writer, REP_GENERAL_FAILURE)
            return

        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(proxy.host, proxy.port),
                timeout=10,
            )
            # SOCKS5 handshake with upstream proxy
            remote_writer.write(struct.pack("!BBB", SOCKS5_VERSION, 1, NO_AUTH))
            await remote_writer.drain()
            resp = await asyncio.wait_for(remote_reader.readexactly(2), timeout=5)
            if resp[1] != NO_AUTH:
                self._send_reply(writer, REP_GENERAL_FAILURE)
                return

            # Request upstream to connect to target
            req = struct.pack("!BBBB", SOCKS5_VERSION, CMD_CONNECT, 0, ATYP_DOMAIN)
            req += bytes([len(addr)]) + addr.encode() + struct.pack("!H", port)
            remote_writer.write(req)
            await remote_writer.drain()

            reply = await asyncio.wait_for(remote_reader.readexactly(4), timeout=10)
            if reply[1] != REP_SUCCESS:
                self._manager.mark_result(proxy.key, success=False)
                self._send_reply(writer, reply[1])
                remote_writer.close()
                return

            # Read bound address from upstream reply
            batyp = reply[3]
            if batyp == ATYP_IPV4:
                await remote_reader.readexactly(4)
            elif batyp == ATYP_DOMAIN:
                blen = (await remote_reader.readexactly(1))[0]
                await remote_reader.readexactly(blen)
            elif batyp == ATYP_IPV6:
                await remote_reader.readexactly(16)
            await remote_reader.readexactly(2)  # port

            self._send_reply(writer, REP_SUCCESS)
            self._manager.mark_result(proxy.key, success=True)

            await asyncio.gather(
                self._relay(reader, remote_writer),
                self._relay(remote_reader, writer),
            )
        except Exception as e:
            self._manager.mark_result(proxy.key, success=False)
            self._send_reply(writer, REP_HOST_UNREACHABLE)

    def _send_reply(self, writer: asyncio.StreamWriter, rep: int) -> None:
        writer.write(struct.pack("!BBBB", SOCKS5_VERSION, rep, 0, ATYP_IPV4) + b"\x00\x00\x00\x00" + struct.pack("!H", 0))
        try:
            writer.drain()
        except Exception:
            pass

    async def _relay(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await asyncio.wait_for(reader.read(8192), timeout=300)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
```

- [ ] **Step 2: Update `src/proxy_vault/server/__init__.py`**

```python
from proxy_vault.server.http_proxy import HTTPProxyServer
from proxy_vault.server.socks5_proxy import SOCKS5Server

__all__ = ["HTTPProxyServer", "SOCKS5Server"]
```

- [ ] **Step 3: Verify imports**

Run: `python -c "from proxy_vault.server.socks5_proxy import SOCKS5Server; print('OK')"`
Expected: OK

- [ ] **Step 4: Commit**

```bash
git add src/proxy_vault/server/
git commit -m "feat: add SOCKS5 proxy server"
```

---

### Task 12: CLI Commands

**Files:**
- Create: `src/proxy_vault/cli/__init__.py`
- Create: `src/proxy_vault/cli/commands.py`
- Modify: `src/proxy_vault/main.py`

- [ ] **Step 1: Write `src/proxy_vault/cli/commands.py`**

```python
import asyncio
import click
from proxy_vault.core.proxy_manager import ProxyManager
from proxy_vault.server.http_proxy import HTTPProxyServer
from proxy_vault.server.socks5_proxy import SOCKS5Server
from proxy_vault.config import config

_manager = ProxyManager()
_http_server: HTTPProxyServer | None = None
_socks_server: SOCKS5Server | None = None


@click.group()
def cli():
    """Proxy Vault - IP-hiding proxy tool for security pentesting."""
    pass


@cli.command()
@click.option("--provider", default="free", type=click.Choice(["free", "paid", "tor", "self", "custom"]))
@click.option("--mode", default="pool", type=click.Choice(["single", "pool"]))
@click.option("--chain", default="", help="Custom relay chain, e.g. 'free,tor'")
@click.option("--proxy", "proxy_url", default="", help="Manual proxy URL for single mode")
@click.option("--port", default=0, help="Local proxy port (default from config)")
@click.option("--api-key", default="", help="Paid proxy API key")
def start(provider, mode, chain, proxy_url, port, api_key):
    """Start the proxy service."""
    async def _start():
        await _manager.start(
            provider=provider, mode=mode, chain=chain,
            proxy_url=proxy_url, port=port, api_key=api_key,
        )
        host = config.proxy_host
        listen_port = port or config.proxy_port
        global _http_server, _socks_server
        _http_server = HTTPProxyServer(_manager)
        _socks_server = SOCKS5Server(_manager, host=host, port=listen_port)
        await _http_server.start()
        await _socks_server.start()
        click.echo(f"Proxy server listening on {host}:{listen_port}")
        click.echo(f"Provider: {provider}, Mode: {mode}")
        if chain:
            click.echo(f"Chain: {chain}")
        try:
            while _manager.state.running:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            await _http_server.stop()
            await _socks_server.stop()
            await _manager.stop()
    asyncio.run(_start())


@cli.command()
def stop():
    """Stop the proxy service."""
    async def _stop():
        if _http_server:
            await _http_server.stop()
        if _socks_server:
            await _socks_server.stop()
        await _manager.stop()
        click.echo("Proxy service stopped")
    asyncio.run(_stop())


@cli.command()
def status():
    """Show current proxy status."""
    stats = _manager.get_stats()
    state = _manager.state
    click.echo(f"Running: {state.running}")
    click.echo(f"Provider: {state.provider}")
    click.echo(f"Mode: {state.mode}")
    if state.chain:
        click.echo(f"Chain: {' -> '.join(n.provider for n in state.chain)}")
    if state.running:
        click.echo(f"Pool size: {stats.get('total', 0)}")
        click.echo(f"Active: {stats.get('active', 0)}")
        click.echo(f"Avg score: {stats.get('avg_score', 0)}")
        click.echo(f"Uptime: {stats.get('uptime_seconds', 0)}s")
        if state.current_ip:
            click.echo(f"Current IP: {state.current_ip}")


@cli.command()
@click.argument("mode", type=click.Choice(["single", "pool"]))
def switch(mode):
    """Switch between single-IP and pool mode."""
    _manager.switch_mode(mode)
    click.echo(f"Switched to {mode} mode")


@cli.command()
@click.option("--set", "set_values", nargs=2, multiple=True, help="Set config key=value")
@click.option("--get", "get_key", default="", help="Get config value")
def config_cmd(set_values, get_key):
    """View or modify configuration."""
    if get_key:
        value = config.get(get_key)
        click.echo(f"{get_key} = {value}")
    for key, value in set_values:
        config.set(key, value)
        config.save()
        click.echo(f"Set {key} = {value}")
    if not get_key and not set_values:
        click.echo("proxy.host = " + str(config.proxy_host))
        click.echo("proxy.port = " + str(config.proxy_port))
        click.echo("webui.port = " + str(config.webui_port))


@cli.command()
@click.option("--port", default=0, help="Web UI port")
def web(port):
    """Start the Web management console."""
    from proxy_vault.webui.app import start_webui
    asyncio.run(start_webui(port or config.webui_port))
```

- [ ] **Step 2: Write `src/proxy_vault/main.py`**

```python
from proxy_vault.cli.commands import cli

if __name__ == "__main__":
    cli()
```

- [ ] **Step 3: Verify CLI loads**

Run: `python -m proxy_vault.main --help`
Expected: shows click help with start/stop/status/switch/config/web commands

- [ ] **Step 4: Write `src/proxy_vault/cli/__init__.py`** — empty file

- [ ] **Step 5: Commit**

```bash
git add src/proxy_vault/cli/ src/proxy_vault/main.py
git commit -m "feat: add CLI commands (start/stop/status/switch/config/web)"
```

---

### Task 13: Web UI (FastAPI + Templates)

**Files:**
- Create: `src/proxy_vault/webui/__init__.py`
- Create: `src/proxy_vault/webui/app.py`
- Create: `src/proxy_vault/webui/api.py`
- Create: `src/proxy_vault/webui/templates/index.html`
- Create: `src/proxy_vault/webui/templates/dashboard.html`
- Create: `src/proxy_vault/webui/templates/controls.html`
- Create: `src/proxy_vault/webui/templates/config.html`

- [ ] **Step 1: Write `src/proxy_vault/webui/app.py`**

```python
import uvicorn
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
from proxy_vault.webui.api import api_router, get_manager

templates_dir = Path(__file__).parent / "templates"
app = FastAPI(title="Proxy Vault", version="0.1.0")
templates = Jinja2Templates(directory=str(templates_dir))
app.include_router(api_router)


@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/dashboard")
async def dashboard(request: Request):
    stats = get_manager().get_stats()
    return templates.TemplateResponse("dashboard.html", {"request": request, **stats})


@app.get("/controls")
async def controls(request: Request):
    state = get_manager().state
    return templates.TemplateResponse("controls.html", {"request": request, "state": state})


@app.get("/config")
async def config_page(request: Request):
    from proxy_vault.config import config as cfg
    return templates.TemplateResponse("config.html", {"request": request, "config": cfg.data})


async def start_webui(port: int = 8080):
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()
```

- [ ] **Step 2: Write `src/proxy_vault/webui/api.py`**

```python
from fastapi import APIRouter
from pydantic import BaseModel
from proxy_vault.core.proxy_manager import ProxyManager
from proxy_vault.config import config

_manager = ProxyManager()
api_router = APIRouter(prefix="/api")


def get_manager() -> ProxyManager:
    return _manager


class StartRequest(BaseModel):
    provider: str = "free"
    mode: str = "pool"
    chain: str = ""
    proxy_url: str = ""
    port: int = 0
    api_key: str = ""


class ConfigSetRequest(BaseModel):
    key: str
    value: str


@api_router.get("/status")
async def get_status():
    return get_manager().get_stats()


@api_router.post("/start")
async def api_start(req: StartRequest):
    await get_manager().start(
        provider=req.provider, mode=req.mode,
        chain=req.chain, proxy_url=req.proxy_url,
        port=req.port, api_key=req.api_key,
    )
    return {"status": "started"}


@api_router.post("/stop")
async def api_stop():
    await get_manager().stop()
    return {"status": "stopped"}


@api_router.post("/switch")
async def api_switch(mode: str = "pool"):
    get_manager().switch_mode(mode)
    return {"status": "switched", "mode": mode}


@api_router.post("/rotate")
async def api_rotate():
    get_manager().rotate_ip()
    return {"status": "rotated"}


@api_router.get("/proxies")
async def api_proxies():
    proxies = get_manager().get_available_proxies()
    return {"proxies": [{"host": p.host, "port": p.port, "score": p.score,
            "latency": p.latency_ms, "status": p.status.value} for p in proxies[:50]]}


@api_router.get("/config")
async def api_get_config():
    return config.data


@api_router.post("/config")
async def api_set_config(req: ConfigSetRequest):
    config.set(req.key, req.value)
    config.save()
    return {"status": "ok", "key": req.key, "value": req.value}
```

- [ ] **Step 3: Write `src/proxy_vault/webui/templates/index.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Vault</title>
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #0d1117; color: #c9d1d9; min-height: 100vh; }
        .layout { display: flex; min-height: 100vh; }
        .sidebar { width: 220px; background: #161b22; padding: 20px 0; border-right: 1px solid #30363d; }
        .sidebar h1 { font-size: 18px; padding: 0 20px 20px; color: #58a6ff; }
        .sidebar a { display: block; padding: 10px 20px; color: #8b949e; text-decoration: none; font-size: 14px; }
        .sidebar a:hover, .sidebar a.active { color: #c9d1d9; background: #1c2129; }
        .main { flex: 1; padding: 30px; }
        h2 { font-size: 22px; margin-bottom: 20px; color: #58a6ff; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 15px; }
        .stat { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 15px; text-align: center; }
        .stat-value { font-size: 28px; font-weight: bold; color: #58a6ff; }
        .stat-label { font-size: 12px; color: #8b949e; margin-top: 4px; text-transform: uppercase; }
        .btn { padding: 8px 16px; border: 1px solid #30363d; border-radius: 6px; background: #21262d;
               color: #c9d1d9; cursor: pointer; font-size: 13px; margin-right: 8px; }
        .btn:hover { background: #30363d; }
        .btn-primary { background: #238636; border-color: #2ea043; color: white; }
        .btn-danger { background: #da3633; border-color: #f85149; color: white; }
        select, input { padding: 8px 12px; border: 1px solid #30363d; border-radius: 6px;
                        background: #0d1117; color: #c9d1d9; font-size: 13px; }
        .flex-row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 15px; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #21262d; }
        th { color: #8b949e; font-weight: 600; }
        .tag { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; }
        .tag-active { background: #23863633; color: #3fb950; }
        .tag-unstable { background: #d2992233; color: #d29922; }
        .tag-banned { background: #da363333; color: #f85149; }
    </style>
</head>
<body>
    <div class="layout">
        <div class="sidebar">
            <h1>Proxy Vault</h1>
            <a href="/dashboard" hx-get="/dashboard" hx-target="#content" hx-push-url="true" class="active">Dashboard</a>
            <a href="/controls" hx-get="/controls" hx-target="#content" hx-push-url="true">Controls</a>
            <a href="/config" hx-get="/config" hx-target="#content" hx-push-url="true">Configuration</a>
        </div>
        <div class="main" id="content" hx-get="/dashboard" hx-trigger="load">
        </div>
    </div>
</body>
</html>
```

- [ ] **Step 4: Write `src/proxy_vault/webui/templates/dashboard.html`**

```html
<h2>Dashboard</h2>
<div class="stat-grid">
    <div class="stat"><div class="stat-value">{{ running and 'ON' or 'OFF' }}</div><div class="stat-label">Status</div></div>
    <div class="stat"><div class="stat-value">{{ provider or '-' }}</div><div class="stat-label">Provider</div></div>
    <div class="stat"><div class="stat-value">{{ mode or '-' }}</div><div class="stat-label">Mode</div></div>
    <div class="stat"><div class="stat-value">{{ total or 0 }}</div><div class="stat-label">Pool Size</div></div>
    <div class="stat"><div class="stat-value">{{ active or 0 }}</div><div class="stat-label">Active</div></div>
    <div class="stat"><div class="stat-value">{{ avg_score or 0 }}</div><div class="stat-label">Avg Score</div></div>
    <div class="stat"><div class="stat-value">{{ uptime_seconds or 0 }}s</div><div class="stat-label">Uptime</div></div>
</div>
<div class="card" style="margin-top:20px;">
    <h3 style="margin-bottom:12px;">Proxy Pool</h3>
    <div hx-get="/api/proxies" hx-trigger="every 10s" hx-swap="innerHTML">
        <table><tr><th>Host</th><th>Port</th><th>Score</th><th>Latency</th><th>Status</th></tr></table>
    </div>
</div>
```

- [ ] **Step 5: Write `src/proxy_vault/webui/templates/controls.html`**

```html
<h2>Proxy Controls</h2>
<div class="card">
    <h3 style="margin-bottom:12px;">Service Control</h3>
    <div class="flex-row">
        <button class="btn btn-primary" hx-post="/api/start" hx-vals='{"provider":"free","mode":"pool"}'>Start Free Pool</button>
        <button class="btn btn-primary" hx-post="/api/start" hx-vals='{"provider":"tor","mode":"single"}'>Start Tor</button>
        <button class="btn btn-danger" hx-post="/api/stop">Stop</button>
    </div>
</div>
<div class="card">
    <h3 style="margin-bottom:12px;">Quick Actions</h3>
    <div class="flex-row">
        <button class="btn" hx-post="/api/switch?mode=pool">Switch to Pool Mode</button>
        <button class="btn" hx-post="/api/switch?mode=single">Switch to Single Mode</button>
        <button class="btn" hx-post="/api/rotate">Rotate IP</button>
    </div>
</div>
```

- [ ] **Step 6: Write `src/proxy_vault/webui/templates/config.html`**

```html
<h2>Configuration</h2>
<div class="card">
    <h3 style="margin-bottom:12px;">Current Settings</h3>
    <table>
        <tr><th>Key</th><th>Value</th></tr>
        <tr><td>proxy.host</td><td>{{ config.proxy.host if config.proxy else '-' }}</td></tr>
        <tr><td>proxy.port</td><td>{{ config.proxy.port if config.proxy else '-' }}</td></tr>
        <tr><td>webui.port</td><td>{{ config.webui.port if config.webui else '-' }}</td></tr>
        <tr><td>tor.host</td><td>{{ config.tor.host if config.tor else '-' }}</td></tr>
        <tr><td>tor.port</td><td>{{ config.tor.port if config.tor else '-' }}</td></tr>
    </table>
</div>
```

- [ ] **Step 7: Write `src/proxy_vault/webui/__init__.py`** — empty file

- [ ] **Step 8: Verify Web UI loads**

Run: `python -c "from proxy_vault.webui.app import app; print('OK')"`
Expected: OK

- [ ] **Step 9: Commit**

```bash
git add src/proxy_vault/webui/
git commit -m "feat: add Web UI with FastAPI and HTMX templates"
```

---

### Task 14: Integration & Final Polish

**Files:**
- Modify: `src/proxy_vault/server/http_proxy.py` (fix ProxyEntry.status reference)
- Modify: `src/proxy_vault/core/proxy_manager.py` (fix _validate_and_activate)

- [ ] **Step 1: Fix `proxy_manager.py` _validate_and_activate method**

Replace the `_validate_and_activate` method in `src/proxy_vault/core/proxy_manager.py`:

```python
    async def _validate_and_activate(self, proxy: ProxyEntry) -> None:
        from datetime import datetime
        from proxy_vault.models import ProxyStatus
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(proxy.host, proxy.port),
                timeout=5,
            )
            writer.close()
            await writer.wait_closed()
            proxy.status = ProxyStatus.ACTIVE
            proxy.last_checked = datetime.now()
        except Exception:
            pass
```

- [ ] **Step 2: Run full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: all tests PASS

- [ ] **Step 3: Install in development mode and test CLI**

Run:
```bash
pip install -e .
proxy --help
```
Expected: CLI help output

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat: integration fixes and final polish"
```
