import asyncio
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
        unstable_threshold = config.get("free_pool.unstable_threshold", 2)
        banned_threshold = config.get("free_pool.banned_threshold", 5)
        if proxy.consecutive_fails >= banned_threshold:
            proxy.status = ProxyStatus.BANNED
        elif proxy.consecutive_fails >= unstable_threshold:
            proxy.status = ProxyStatus.UNSTABLE

    def remove(self, key: str) -> None:
        self._proxies.pop(key, None)

    def recheck_cooldown(self) -> list[ProxyEntry]:
        cooldown_minutes = config.get("free_pool.cooldown_minutes", 30)
        cutoff = datetime.now() - timedelta(minutes=cooldown_minutes)
        return [
            p for p in self._proxies.values()
            if p.status == ProxyStatus.BANNED
            and p.last_checked
            and p.last_checked < cutoff
        ]

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
