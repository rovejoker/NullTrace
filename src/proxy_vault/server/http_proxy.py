import asyncio
import aiohttp
from aiohttp import web
from proxy_vault.core.proxy_manager import ProxyManager
from proxy_vault.config import config


class HTTPProxyServer:
    def __init__(self, manager: ProxyManager):
        self._manager = manager
        self._app = web.Application()
        self._runner: web.AppRunner | None = None
        self._host = config.get("proxy.host", "127.0.0.1")
        self._port = config.get("proxy.port", 1080)

    async def handle_request(self, request: web.Request) -> web.Response:
        proxy = await self._manager.get_next_proxy()
        if proxy is None:
            return web.Response(status=502, text="No proxy available")

        target_url = str(request.url)
        method = request.method
        headers = dict(request.headers)
        headers.pop("Host", None)
        body = await request.read()

        retries = config.get("free_pool.max_retries", 3)
        timeout = config.get("free_pool.request_timeout", 10)
        last_error = None

        for attempt in range(retries):
            try:
                proxy_url = f"http://{proxy.host}:{proxy.port}"
                async with aiohttp.ClientSession() as session:
                    async with session.request(
                        method, target_url,
                        headers=headers,
                        data=body,
                        proxy=proxy_url,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                    ) as resp:
                        response_body = await resp.read()
                        response_headers = dict(resp.headers)
                        response_headers.pop("Transfer-Encoding", None)
                        self._manager.mark_result(proxy.key, success=True, latency=0)
                        return web.Response(
                            status=resp.status,
                            headers=response_headers,
                            body=response_body,
                        )
            except Exception as e:
                last_error = e
                self._manager.mark_result(proxy.key, success=False)
                if attempt < retries - 1:
                    proxy = await self._manager.get_next_proxy()
                    if proxy is None:
                        break

        return web.Response(status=502, text=f"Proxy error: {last_error}")

    async def start(self) -> None:
        self._app.router.add_route("*", "/{path:.*}", self.handle_request)
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self._host, self._port)
        await site.start()

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
