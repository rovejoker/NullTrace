import asyncio
from fastapi import APIRouter, Form
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from proxy_vault.core.proxy_manager import ProxyManager
from proxy_vault.server.http_proxy import HTTPProxyServer
from proxy_vault.server.socks5_proxy import SOCKS5Server
from proxy_vault.config import config

_manager = ProxyManager()
_http_server: HTTPProxyServer | None = None
_socks_server: SOCKS5Server | None = None
api_router = APIRouter(prefix="/api")


def get_manager() -> ProxyManager:
    return _manager


class ConfigSetRequest(BaseModel):
    key: str
    value: str


@api_router.get("/status")
async def get_status():
    s = get_manager().get_stats()
    errors = s.get("collector_errors", {})
    host = config.get("proxy.host", "127.0.0.1")
    port = config.get("proxy.port", 1080)
    html = ""
    if s["running"]:
        html += f'<span class="tag tag-active">RUNNING</span> '
        html += f'Proxy: {host}:{port} | pool: {s.get("total", 0)}, active: {s.get("active", 0)}'
        if errors:
            html += '<div style="margin-top:6px;font-size:12px;color:#f85149;">'
            for name, err in list(errors.items())[:2]:
                html += f'<div>{name}: {err[:80]}</div>'
            html += '</div>'
    else:
        html += '<span class="tag">STOPPED</span>'
    return html


@api_router.post("/start")
async def api_start(
    provider: str = Form("free"),
    mode: str = Form("pool"),
    chain: str = Form(""),
    proxy_url: str = Form(""),
    port: int = Form(0),
    api_key: str = Form(""),
):
    global _http_server, _socks_server
    # Stop existing servers if running
    if _http_server:
        await _http_server.stop()
    if _socks_server:
        await _socks_server.stop()

    await get_manager().start(
        provider=provider, mode=mode,
        chain=chain, proxy_url=proxy_url,
        port=port, api_key=api_key,
    )

    # Start HTTP + SOCKS5 proxy servers
    host = config.get("proxy.host", "127.0.0.1")
    listen_port = port or config.get("proxy.port", 1080)
    _http_server = HTTPProxyServer(get_manager())
    _socks_server = SOCKS5Server(get_manager(), host=host, port=listen_port)
    asyncio.create_task(_http_server.start())
    asyncio.create_task(_socks_server.start())

    return f'<span class="tag tag-active">RUNNING ({provider}) :{listen_port}</span>'


@api_router.post("/stop")
async def api_stop():
    global _http_server, _socks_server
    if _http_server:
        await _http_server.stop()
    if _socks_server:
        await _socks_server.stop()
    await get_manager().stop()
    return '<span class="tag">STOPPED</span>'


@api_router.post("/switch")
async def api_switch(mode: str = "pool"):
    get_manager().switch_mode(mode)
    return f'<span class="tag tag-active">Mode: {mode}</span>'


@api_router.post("/rotate")
async def api_rotate():
    get_manager().rotate_ip()
    return '<span class="tag tag-active">IP rotated</span>'


@api_router.get("/proxies")
async def api_proxies():
    proxies = get_manager().get_available_proxies()
    result = []
    for p in proxies[:50]:
        result.append({
            "host": p.host, "port": p.port, "score": p.score,
            "latency": p.latency_ms, "status": p.status.value,
        })
    # Return HTML table rows for HTMX
    rows = ""
    for p in result:
        tag_class = "tag-active" if p["status"] == "active" else ("tag-unstable" if p["status"] == "unstable" else "tag-banned")
        rows += f'<tr><td>{p["host"]}</td><td>{p["port"]}</td><td>{p["score"]}</td><td>{p["latency"]}ms</td><td><span class="tag {tag_class}">{p["status"]}</span></td></tr>'
    if not result:
        rows = '<tr><td colspan="5" style="text-align:center;color:#8b949e;">No proxies available</td></tr>'
    return HTMLResponse(content=rows)


@api_router.get("/config")
async def api_get_config():
    return config.data


@api_router.post("/config")
async def api_set_config(req: ConfigSetRequest):
    config.set(req.key, req.value)
    config.save()
    return {"status": "ok", "key": req.key, "value": req.value}
