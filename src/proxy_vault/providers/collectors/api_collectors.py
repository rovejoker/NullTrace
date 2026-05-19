import aiohttp
from proxy_vault.models import ProxyEntry, ProxyType, AnonymityLevel
from proxy_vault.providers.base import BaseProvider


class GeonodeCollector(BaseProvider):
    @property
    def name(self) -> str:
        return "geonode"

    @property
    def interval(self) -> int:
        return 600

    async def fetch_proxies(self) -> list[ProxyEntry]:
        return await self.collect()

    async def collect(self) -> list[ProxyEntry]:
        proxies = []
        url = "https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc&filterUpTime=80&protocols=http,https,socks4,socks5"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    data = await resp.json()
                    for item in data.get("data", []):
                        protocols = item.get("protocols", [])
                        ptypes = []
                        for proto in protocols:
                            if proto == "http":
                                ptypes.append(ProxyType.HTTP)
                            elif proto == "https":
                                ptypes.append(ProxyType.HTTPS)
                            elif proto == "socks4":
                                ptypes.append(ProxyType.SOCKS4)
                            elif proto == "socks5":
                                ptypes.append(ProxyType.SOCKS5)
                        anonymity = AnonymityLevel.ELITE if item.get("anonymityLevel") == "elite" else AnonymityLevel.ANONYMOUS
                        proxies.append(ProxyEntry(
                            host=item["ip"],
                            port=int(item["port"]),
                            types=ptypes,
                            anonymity=anonymity,
                            country=item.get("country", ""),
                            latency_ms=int(item.get("responseTime", 0)),
                            sources={self.name},
                        ))
        except Exception:
            pass
        return proxies


class ProxyScrapeV2Collector(BaseProvider):
    @property
    def name(self) -> str:
        return "proxyscrape-v2"

    @property
    def interval(self) -> int:
        return 600

    async def fetch_proxies(self) -> list[ProxyEntry]:
        return await self.collect()

    async def collect(self) -> list[ProxyEntry]:
        proxies = []
        endpoints = [
            ("https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000", ProxyType.HTTP),
            ("https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000", ProxyType.SOCKS5),
        ]
        async with aiohttp.ClientSession() as session:
            for url, ptype in endpoints:
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
                                        types=[ptype],
                                        anonymity=AnonymityLevel.ANONYMOUS,
                                        sources={self.name},
                                    ))
                except Exception:
                    pass
        return proxies
