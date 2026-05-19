import asyncio
import time
import logging
from datetime import datetime
from proxy_vault.models import ProxyState, ProxyEntry, ChainNode, ProxyStatus
from proxy_vault.core.relay_chain import RelayChain
from proxy_vault.core.ip_rotator import IPRotator
from proxy_vault.core.health_monitor import HealthMonitor
from proxy_vault.providers.free_pool import FreeProxyPool
from proxy_vault.providers.tor_relay import TorRelayProvider
from proxy_vault.providers.custom_proxy import CustomProxyProvider
from proxy_vault.providers.paid_adapter import PaidAdapterProvider
from proxy_vault.providers.collectors import ALL_COLLECTORS
from proxy_vault.config import config

logger = logging.getLogger("proxy-vault")


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
        self._collector_errors: dict[str, str] = {}
        self._collector_last_run: dict[str, float] = {}
        self._total_collected: int = 0

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
                logger.info(f"Collector {collector.name}: got {len(proxies)} proxies")
                self._collector_last_run[collector.name] = time.time()
                self._collector_errors.pop(collector.name, None)
                for p in proxies:
                    is_new = self._pool.add(p)
                    if is_new:
                        self._total_collected += 1
                min_size = config.get("free_pool.min_pool_size", 10)
                if self._pool.size < min_size:
                    await self._emergency_collect()
            except Exception as e:
                self._collector_errors[collector.name] = str(e)[:200]
                logger.warning(f"Collector {collector.name} failed: {e}")
            await asyncio.sleep(collector.interval)

    async def _validate_and_activate(self, proxy: ProxyEntry) -> None:
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

    def get_stats(self) -> dict:
        uptime = int(time.time() - self._start_time) if self._start_time > 0 else 0
        pool_stats = self._pool.stats if self._pool else {}
        return {
            **pool_stats,
            "uptime_seconds": uptime,
            "running": self._state.running,
            "provider": self._state.provider,
            "mode": self._state.mode,
            "collector_errors": dict(self._collector_errors),
            "collector_last_run": dict(self._collector_last_run),
            "total_collected": self._total_collected,
        }
