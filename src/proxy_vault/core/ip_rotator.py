from enum import Enum
import random
from proxy_vault.models import ProxyEntry


class RotationStrategy(Enum):
    ROUND_ROBIN = "round_robin"
    RANDOM = "random"
    WEIGHTED = "weighted"
    FIXED = "fixed"


class IPRotator:
    def __init__(self, strategy: RotationStrategy = RotationStrategy.WEIGHTED):
        self._strategy = strategy
        self._index = 0
        self._fixed_proxy: str | None = None

    @property
    def strategy(self) -> RotationStrategy:
        return self._strategy

    @strategy.setter
    def strategy(self, value: RotationStrategy) -> None:
        self._strategy = value
        self._index = 0

    def next(self, proxies: list[ProxyEntry]) -> ProxyEntry | None:
        if not proxies:
            return None
        match self._strategy:
            case RotationStrategy.ROUND_ROBIN:
                return self._round_robin(proxies)
            case RotationStrategy.RANDOM:
                return random.choice(proxies)
            case RotationStrategy.WEIGHTED:
                return self._weighted(proxies)
            case RotationStrategy.FIXED:
                return self._fixed(proxies)
        return None

    def _round_robin(self, proxies: list[ProxyEntry]) -> ProxyEntry:
        proxy = proxies[self._index % len(proxies)]
        self._index += 1
        return proxy

    def _weighted(self, proxies: list[ProxyEntry]) -> ProxyEntry:
        total = sum(p.score for p in proxies)
        if total == 0:
            return random.choice(proxies)
        r = random.uniform(0, total)
        cumulative = 0
        for p in proxies:
            cumulative += p.score
            if r <= cumulative:
                return p
        return proxies[-1]

    def _fixed(self, proxies: list[ProxyEntry]) -> ProxyEntry:
        if self._fixed_proxy is None or not any(p.key == self._fixed_proxy for p in proxies):
            self._fixed_proxy = proxies[0].key
        for p in proxies:
            if p.key == self._fixed_proxy:
                return p
        self._fixed_proxy = proxies[0].key
        return proxies[0]

    def reset(self) -> None:
        self._index = 0
        self._fixed_proxy = None
