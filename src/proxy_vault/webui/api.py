from fastapi import APIRouter
from pydantic import BaseModel
from proxy_vault.core.proxy_manager import ProxyManager
from proxy_vault.config import config

_manager = ProxyManager()
api_router = APIRouter(prefix="/api")


def get_manager() -> ProxyManager:
    return _manager


class StartRequest(BaseModel):
    provider: str = "free"
    mode: str = "pool"
    chain: str = ""
    proxy_url: str = ""
    port: int = 0
    api_key: str = ""


class ConfigSetRequest(BaseModel):
    key: str
    value: str


@api_router.get("/status")
async def get_status():
    return get_manager().get_stats()


@api_router.post("/start")
async def api_start(req: StartRequest):
    await get_manager().start(
        provider=req.provider, mode=req.mode,
        chain=req.chain, proxy_url=req.proxy_url,
        port=req.port, api_key=req.api_key,
    )
    return {"status": "started"}


@api_router.post("/stop")
async def api_stop():
    await get_manager().stop()
    return {"status": "stopped"}


@api_router.post("/switch")
async def api_switch(mode: str = "pool"):
    get_manager().switch_mode(mode)
    return {"status": "switched", "mode": mode}


@api_router.post("/rotate")
async def api_rotate():
    get_manager().rotate_ip()
    return {"status": "rotated"}


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
    return rows


@api_router.get("/config")
async def api_get_config():
    return config.data


@api_router.post("/config")
async def api_set_config(req: ConfigSetRequest):
    config.set(req.key, req.value)
    config.save()
    return {"status": "ok", "key": req.key, "value": req.value}
