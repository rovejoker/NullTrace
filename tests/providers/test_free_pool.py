import pytest
from proxy_vault.providers.free_pool import FreeProxyPool
from proxy_vault.models import ProxyEntry, ProxyType, ProxyStatus, AnonymityLevel


@pytest.fixture
def pool():
    return FreeProxyPool()


def make_proxy(host, port, score=50, status=ProxyStatus.ACTIVE, sources=None):
    return ProxyEntry(
        host=host, port=port,
        types=[ProxyType.HTTP],
        anonymity=AnonymityLevel.ELITE,
        status=status, score=score,
        sources=sources or {"test"},
    )


def test_pool_starts_empty(pool):
    assert pool.size == 0
    assert len(pool.get_available()) == 0


def test_add_proxy_increases_size(pool):
    pool.add(make_proxy("1.1.1.1", 80))
    assert pool.size == 1


def test_add_duplicate_ignored(pool):
    p1 = make_proxy("1.1.1.1", 80)
    p2 = make_proxy("1.1.1.1", 80)
    pool.add(p1)
    pool.add(p2)
    assert pool.size == 1


def test_add_duplicate_merges_sources(pool):
    p1 = make_proxy("1.1.1.1", 80, sources={"src_a"})
    p2 = make_proxy("1.1.1.1", 80, sources={"src_b"})
    pool.add(p1)
    pool.add(p2)
    proxy = pool.get_available()[0]
    assert "src_a" in proxy.sources
    assert "src_b" in proxy.sources
    assert proxy.score >= 70  # cross-validation bonus +20


def test_get_available_returns_active_only(pool):
    pool.add(make_proxy("1.1.1.1", 80, status=ProxyStatus.ACTIVE))
    pool.add(make_proxy("2.2.2.2", 80, status=ProxyStatus.BANNED))
    pool.add(make_proxy("3.3.3.3", 80, status=ProxyStatus.UNSTABLE))
    available = pool.get_available()
    assert len(available) == 2


def test_get_best_returns_highest_score(pool):
    pool.add(make_proxy("1.1.1.1", 80, score=30))
    pool.add(make_proxy("2.2.2.2", 80, score=90))
    pool.add(make_proxy("3.3.3.3", 80, score=60))
    best = pool.get_best()
    assert best.host == "2.2.2.2"


def test_get_best_empty_pool(pool):
    assert pool.get_best() is None


def test_mark_failure_increases_consecutive(pool):
    p = make_proxy("1.1.1.1", 80, status=ProxyStatus.ACTIVE)
    pool.add(p)
    pool.mark_failure("1.1.1.1:80")
    proxy = pool._proxies["1.1.1.1:80"]
    assert proxy.consecutive_fails == 1
    assert proxy.fail_count == 1


def test_mark_failure_triggers_unstable(pool):
    p = make_proxy("1.1.1.1", 80, status=ProxyStatus.ACTIVE, score=60)
    p.consecutive_fails = 3
    pool.add(p)
    pool._check_thresholds(pool._proxies["1.1.1.1:80"])
    assert pool._proxies["1.1.1.1:80"].status == ProxyStatus.UNSTABLE


def test_mark_success_resets_consecutive(pool):
    p = make_proxy("1.1.1.1", 80, status=ProxyStatus.UNSTABLE)
    p.consecutive_fails = 3
    pool.add(p)
    pool.mark_success("1.1.1.1:80", latency=100)
    proxy = pool._proxies["1.1.1.1:80"]
    assert proxy.consecutive_fails == 0
    assert proxy.success_count == 1


def test_remove_banned(pool):
    p = make_proxy("1.1.1.1", 80, status=ProxyStatus.BANNED)
    pool.add(p)
    pool.remove("1.1.1.1:80")
    assert pool.size == 0


def test_size_property(pool):
    for i in range(5):
        pool.add(make_proxy(f"1.1.1.{i}", 80))
    assert pool.size == 5


def test_get_stats(pool):
    pool.add(make_proxy("1.1.1.1", 80, status=ProxyStatus.ACTIVE, score=70))
    pool.add(make_proxy("2.2.2.2", 80, status=ProxyStatus.UNSTABLE, score=30))
    stats = pool.stats
    assert stats["total"] == 2
    assert stats["active"] == 1
    assert stats["unstable"] == 1
    assert "avg_score" in stats
