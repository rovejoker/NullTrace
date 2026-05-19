import pytest
from proxy_vault.providers.custom_proxy import CustomProxyProvider


def test_custom_parse_http():
    p = CustomProxyProvider("http://1.2.3.4:8080")
    assert p.name == "custom"
    proxy = p.get_proxy_sync()
    assert proxy.host == "1.2.3.4"
    assert proxy.port == 8080


def test_custom_parse_socks5():
    p = CustomProxyProvider("socks5://5.6.7.8:1080")
    proxy = p.get_proxy_sync()
    assert proxy.port == 1080


def test_custom_parse_default_port():
    p = CustomProxyProvider("http://1.2.3.4")
    proxy = p.get_proxy_sync()
    assert proxy.port == 1080


def test_custom_proxy_url():
    p = CustomProxyProvider("socks5://1.2.3.4:9999")
    assert p.proxy_url == "socks5://1.2.3.4:9999"
