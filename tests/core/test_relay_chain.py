import pytest
from proxy_vault.core.relay_chain import RelayChain
from proxy_vault.models import ChainNode


def test_relay_chain_parses_chain_string():
    chain = RelayChain.parse_chain("free,tor,self-relay")
    assert len(chain) == 3
    assert chain[0].provider == "free"
    assert chain[1].provider == "tor"
    assert chain[2].provider == "self-relay"


def test_relay_chain_parses_single():
    chain = RelayChain.parse_chain("tor")
    assert len(chain) == 1
    assert chain[0].provider == "tor"


def test_relay_chain_parses_empty():
    chain = RelayChain.parse_chain("")
    assert len(chain) == 0


def test_relay_chain_validates_hops():
    chain = RelayChain.parse_chain("free,tor,self-relay")
    assert RelayChain.validate_hops(chain, {"free": 1, "tor": 3, "self-relay": 5}) is True


def test_relay_chain_validates_hops_exceeded():
    chain = RelayChain.parse_chain("free,free,free")  # free only allows 1 hop
    assert RelayChain.validate_hops(chain, {"free": 1, "tor": 3}) is False


def test_relay_chain_to_list():
    chain = RelayChain.parse_chain("free,tor")
    result = RelayChain.to_provider_list(chain)
    assert result == ["free", "tor"]


def test_relay_chain_build_chain():
    chain = RelayChain.parse_chain("free,tor")
    nodes = RelayChain.build_chain(chain, target_host="example.com", target_port=443)
    assert len(nodes) == 2
    assert nodes[0]["provider"] == "free"
    assert nodes[1]["provider"] == "tor"
    assert nodes[1]["config"]["target_host"] == "example.com"
    assert nodes[1]["config"]["target_port"] == 443
