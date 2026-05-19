from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from pathlib import Path
from proxy_vault.webui.api import api_router, get_manager

templates_dir = Path(__file__).parent / "templates"
app = FastAPI(title="NullTrace", version="0.1.0")
templates = Jinja2Templates(directory=str(templates_dir))
app.include_router(api_router)


def _is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request") == "true"


@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/dashboard")
async def dashboard(request: Request):
    stats = get_manager().get_stats()
    if not _is_htmx(request):
        return templates.TemplateResponse(request=request, name="index.html")
    return templates.TemplateResponse(request=request, name="dashboard.html", context=stats)


@app.get("/controls")
async def controls(request: Request):
    m = get_manager()
    state = m.state
    stats = m.get_stats()
    if not _is_htmx(request):
        return templates.TemplateResponse(request=request, name="index.html")
    return templates.TemplateResponse(request=request, name="controls.html", context={
        "state": state,
        "running": stats.get("running", False),
        "provider": stats.get("provider", ""),
    })


@app.get("/config")
async def config_page(request: Request):
    if not _is_htmx(request):
        return templates.TemplateResponse(request=request, name="index.html")
    from proxy_vault.config import config as cfg
    return templates.TemplateResponse(request=request, name="config.html", context={"config": cfg.data})


async def start_webui(port: int = 8080):
    import uvicorn
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()
