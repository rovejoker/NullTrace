from fastapi import APIRouter, Form
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from proxy_vault.core.proxy_manager import ProxyManager
from proxy_vault.config import config

_manager = ProxyManager()
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
    last_run = s.get("collector_last_run", {})
    html = ""
    if s["running"]:
        html += '<span class="tag tag-active">RUNNING</span> '
        html += f'{s.get("total_collected", 0)} collected, pool: {s.get("total", 0)}'
        if errors:
            html += '<div style="margin-top:8px;font-size:12px;color:#f85149;">'
            for name, err in list(errors.items())[:3]:
                html += f'<div>❌ {name}: {err[:100]}</div>'
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
    await get_manager().start(
        provider=provider, mode=mode,
        chain=chain, proxy_url=proxy_url,
        port=port, api_key=api_key,
    )
    return f'<span class="tag tag-active">RUNNING ({provider})</span>'


@api_router.post("/stop")
async def api_stop():
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
