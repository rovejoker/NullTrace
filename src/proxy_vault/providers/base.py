import asyncio
from abc import ABC, abstractmethod
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
