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
