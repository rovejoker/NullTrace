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

    def get_proxy_sync(self) -> ProxyEntry:
        """Synchronous access for tests and non-async contexts."""
        return ProxyEntry(
            host=self._parsed["host"],
            port=self._parsed["port"],
            types=[self._parsed["type"]],
            anonymity=AnonymityLevel.ELITE,
            sources={"custom"},
        )

    @property
    def proxy_url(self) -> str:
        return self._proxy_url
