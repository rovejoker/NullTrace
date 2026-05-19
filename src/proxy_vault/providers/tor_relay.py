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
