import asyncio
import click
from proxy_vault.core.proxy_manager import ProxyManager
from proxy_vault.server.http_proxy import HTTPProxyServer
from proxy_vault.server.socks5_proxy import SOCKS5Server
from proxy_vault.config import config

_manager = ProxyManager()
_http_server: HTTPProxyServer | None = None
_socks_server: SOCKS5Server | None = None


@click.group()
def cli():
    """Proxy Vault - IP-hiding proxy tool for security pentesting."""
    pass


@cli.command()
@click.option("--provider", default="free", type=click.Choice(["free", "paid", "tor", "self", "custom"]))
@click.option("--mode", default="pool", type=click.Choice(["single", "pool"]))
@click.option("--chain", default="", help="Custom relay chain, e.g. 'free,tor'")
@click.option("--proxy", "proxy_url", default="", help="Manual proxy URL for single mode")
@click.option("--port", default=0, help="Local proxy port (default from config)")
@click.option("--api-key", default="", help="Paid proxy API key")
def start(provider, mode, chain, proxy_url, port, api_key):
    """Start the proxy service."""
    async def _start():
        await _manager.start(
            provider=provider, mode=mode, chain=chain,
            proxy_url=proxy_url, port=port, api_key=api_key,
        )
        host = config.get("proxy.host", "127.0.0.1")
        listen_port = port or config.get("proxy.port", 1080)
        global _http_server, _socks_server
        _http_server = HTTPProxyServer(_manager)
        _socks_server = SOCKS5Server(_manager, host=host, port=listen_port)
        await _http_server.start()
        await _socks_server.start()
        click.echo(f"Proxy server listening on {host}:{listen_port}")
        click.echo(f"Provider: {provider}, Mode: {mode}")
        if chain:
            click.echo(f"Chain: {chain}")
        try:
            while _manager.state.running:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            await _http_server.stop()
            await _socks_server.stop()
            await _manager.stop()
    asyncio.run(_start())


@cli.command()
def stop():
    """Stop the proxy service."""
    async def _stop():
        if _http_server:
            await _http_server.stop()
        if _socks_server:
            await _socks_server.stop()
        await _manager.stop()
        click.echo("Proxy service stopped")
    asyncio.run(_stop())


@cli.command()
def status():
    """Show current proxy status."""
    stats = _manager.get_stats()
    state = _manager.state
    click.echo(f"Running: {state.running}")
    click.echo(f"Provider: {state.provider}")
    click.echo(f"Mode: {state.mode}")
    if state.chain:
        click.echo(f"Chain: {' -> '.join(n.provider for n in state.chain)}")
    if state.running:
        click.echo(f"Pool size: {stats.get('total', 0)}")
        click.echo(f"Active: {stats.get('active', 0)}")
        click.echo(f"Avg score: {stats.get('avg_score', 0)}")
        click.echo(f"Uptime: {stats.get('uptime_seconds', 0)}s")
        if state.current_ip:
            click.echo(f"Current IP: {state.current_ip}")


@cli.command()
@click.argument("mode", type=click.Choice(["single", "pool"]))
def switch(mode):
    """Switch between single-IP and pool mode."""
    _manager.switch_mode(mode)
    click.echo(f"Switched to {mode} mode")


@cli.command(name="config")
@click.option("--set", "set_values", nargs=2, multiple=True, help="Set config key=value")
@click.option("--get", "get_key", default="", help="Get config value")
def config_cmd(set_values, get_key):
    """View or modify configuration."""
    if get_key:
        value = config.get(get_key)
        click.echo(f"{get_key} = {value}")
    for key, value in set_values:
        config.set(key, str(value))
        config.save()
        click.echo(f"Set {key} = {value}")
    if not get_key and not set_values:
        click.echo("proxy.host = " + str(config.get("proxy.host", "")))
        click.echo("proxy.port = " + str(config.get("proxy.port", "")))
        click.echo("webui.port = " + str(config.get("webui.port", "")))


@cli.command()
@click.option("--port", default=0, help="Web UI port")
def web(port):
    """Start the Web management console."""
    from proxy_vault.webui.app import start_webui
    asyncio.run(start_webui(port or config.get("webui.port", 8080)))
