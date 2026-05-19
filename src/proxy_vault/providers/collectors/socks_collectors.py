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
