import pytest
from proxy_vault.core.ip_rotator import IPRotator, RotationStrategy
from proxy_vault.models import ProxyEntry, ProxyType


def make_proxy(host):
    return ProxyEntry(host=host, port=80, types=[ProxyType.HTTP])


class TestRoundRobin:
    def test_round_robin_cycles(self):
        proxies = [make_proxy(f"1.1.1.{i}") for i in range(1, 4)]
        rotator = IPRotator(RotationStrategy.ROUND_ROBIN)
        assert rotator.next(proxies).host == "1.1.1.1"
        assert rotator.next(proxies).host == "1.1.1.2"
        assert rotator.next(proxies).host == "1.1.1.3"
        assert rotator.next(proxies).host == "1.1.1.1"

    def test_round_robin_empty(self):
        rotator = IPRotator(RotationStrategy.ROUND_ROBIN)
        assert rotator.next([]) is None


class TestRandom:
    def test_random_returns_from_pool(self):
        proxies = [make_proxy(f"1.1.1.{i}") for i in range(10)]
        rotator = IPRotator(RotationStrategy.RANDOM)
        for _ in range(20):
            p = rotator.next(proxies)
            assert p is not None
            assert p.host.startswith("1.1.1.")


class TestWeighted:
    def test_weighted_prefers_high_score(self):
        proxies = [
            ProxyEntry(host="1.1.1.1", port=80, score=10, types=[ProxyType.HTTP]),
            ProxyEntry(host="2.2.2.2", port=80, score=90, types=[ProxyType.HTTP]),
        ]
        rotator = IPRotator(RotationStrategy.WEIGHTED)
        counts = {"1.1.1.1": 0, "2.2.2.2": 0}
        for _ in range(100):
            p = rotator.next(proxies)
            counts[p.host] += 1
        assert counts["2.2.2.2"] > counts["1.1.1.1"]


class TestFixed:
    def test_fixed_returns_same(self):
        proxies = [make_proxy(f"1.1.1.{i}") for i in range(5)]
        rotator = IPRotator(RotationStrategy.FIXED)
        first = rotator.next(proxies)
        for _ in range(10):
            assert rotator.next(proxies).host == first.host
