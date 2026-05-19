import aiohttp
from proxy_vault.models import ProxyEntry, ProxyType, AnonymityLevel
from proxy_vault.providers.base import BaseProvider


class TheSpeedXCollector(BaseProvider):
    @property
    def name(self) -> str:
        return "thespeedx"

    @property
    def interval(self) -> int:
        return 600

    async def fetch_proxies(self) -> list[ProxyEntry]:
        return await self.collect()

    async def collect(self) -> list[ProxyEntry]:
        proxies = []
        urls = [
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
            "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        ]
        type_map = {0: ProxyType.HTTP, 1: ProxyType.SOCKS4, 2: ProxyType.SOCKS5}
        async with aiohttp.ClientSession() as session:
            for i, url in enumerate(urls):
                try:
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
                                        types=[type_map[i]],
                                        anonymity=AnonymityLevel.ANONYMOUS,
                                        sources={self.name},
                                    ))
                except Exception:
                    pass
        return proxies


class MonosansCollector(BaseProvider):
    @property
    def name(self) -> str:
        return "monosans"

    @property
    def interval(self) -> int:
        return 600

    async def fetch_proxies(self) -> list[ProxyEntry]:
        return await self.collect()

    async def collect(self) -> list[ProxyEntry]:
        proxies = []
        url = "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    text = await resp.text()
                    for line in text.strip().split("\n"):
                        line = line.strip()
                        if ":" in line and not line.startswith("#"):
                            parts = line.split("|")[0].strip()
                            host, port = parts.rsplit(":", 1)
                            if port.isdigit():
                                proxies.append(ProxyEntry(
                                    host=host.strip(),
                                    port=int(port.strip()),
                                    types=[ProxyType.HTTP, ProxyType.SOCKS5],
                                    anonymity=AnonymityLevel.ANONYMOUS,
                                    sources={self.name},
                                ))
        except Exception:
            pass
        return proxies
