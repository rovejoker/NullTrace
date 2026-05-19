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
