import asyncio
import logging
import time
import aiohttp
from proxy_vault.providers.free_pool import FreeProxyPool
from proxy_vault.models import ProxyEntry
from proxy_vault.config import config

logger = logging.getLogger("proxy-vault.health")

# Lightweight endpoints for proxy validation
TEST_URLS = [
    "http://httpbin.org/ip",
    "http://ip-api.com/json",
]


class HealthMonitor:
    def __init__(self, pool: FreeProxyPool, check_interval: float | None = None):
        self._pool = pool
        self._interval = check_interval or config.get("free_pool.health_check_interval", 30)
        self._running = False
        self._checks_done: int = 0
        self._checks_passed: int = 0
        self._alive_count: int = 0

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
        # Prioritize unchecked, check up to 50 per cycle (HTTP requests are slower than TCP)
        unchecked = [p for p in proxies if p.latency_ms == 0]
        to_check = unchecked[:50] if unchecked else [p for p in proxies if p.score >= 50][:50]
        if not to_check:
            to_check = proxies[:50]

        logger.info(f"Health checking {len(to_check)} proxies...")
        alive_before = self._alive_count
        semaphore = asyncio.Semaphore(20)

        async def check_one(p: ProxyEntry):
            async with semaphore:
                t0 = time.monotonic()
                try:
                    proxy_url = f"http://{p.host}:{p.port}"
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            TEST_URLS[0],
                            proxy=proxy_url,
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            if resp.status == 200:
                                elapsed = int((time.monotonic() - t0) * 1000)
                                self._pool.mark_success(p.key, latency=elapsed)
                                self._checks_passed += 1
                                self._alive_count += 1
                            else:
                                # 407, 403, etc = bad proxy
                                self._pool.mark_failure(p.key)
                except Exception:
                    self._pool.mark_failure(p.key)
                self._checks_done += 1

        await asyncio.gather(*[check_one(p) for p in to_check])
        alive_now = self._alive_count
        logger.info(f"Health check done: {self._checks_passed}/{len(to_check)} pass, {alive_now} total alive")

    async def check_single(self, proxy: ProxyEntry) -> bool:
        try:
            proxy_url = f"http://{proxy.host}:{proxy.port}"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    TEST_URLS[0],
                    proxy=proxy_url,
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False

    def stop(self) -> None:
        self._running = False
