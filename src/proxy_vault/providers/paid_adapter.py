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
