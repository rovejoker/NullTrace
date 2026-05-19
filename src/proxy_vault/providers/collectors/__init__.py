from proxy_vault.providers.collectors.http_collectors import ProxyScrapeCollector, FreeProxyListCollector
from proxy_vault.providers.collectors.socks_collectors import SocksProxyCollector, OpenProxySpaceCollector
from proxy_vault.providers.collectors.github_collectors import TheSpeedXCollector, MonosansCollector
from proxy_vault.providers.collectors.api_collectors import GeonodeCollector, ProxyScrapeV2Collector

ALL_COLLECTORS = [
    ProxyScrapeCollector,
    FreeProxyListCollector,
    SocksProxyCollector,
    OpenProxySpaceCollector,
    TheSpeedXCollector,
    MonosansCollector,
    GeonodeCollector,
    ProxyScrapeV2Collector,
]
