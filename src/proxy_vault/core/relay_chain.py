from proxy_vault.models import ChainNode


class RelayChain:
    @staticmethod
    def parse_chain(chain_str: str) -> list[ChainNode]:
        if not chain_str.strip():
            return []
        providers = [p.strip() for p in chain_str.split(",") if p.strip()]
        return [ChainNode(provider=p) for p in providers]

    @staticmethod
    def validate_hops(chain: list[ChainNode], max_hops_map: dict[str, int]) -> bool:
        provider_counts: dict[str, int] = {}
        for node in chain:
            provider_counts[node.provider] = provider_counts.get(node.provider, 0) + 1
            if provider_counts[node.provider] > max_hops_map.get(node.provider, 1):
                return False
        return True

    @staticmethod
    def to_provider_list(chain: list[ChainNode]) -> list[str]:
        return [node.provider for node in chain]

    @staticmethod
    def build_chain(chain: list[ChainNode], target_host: str, target_port: int) -> list[dict]:
        nodes = []
        for i, node in enumerate(chain):
            is_last = (i == len(chain) - 1)
            config = {}
            if is_last:
                config["target_host"] = target_host
                config["target_port"] = target_port
            nodes.append({"provider": node.provider, "config": config})
        return nodes

    @staticmethod
    def resolve_entry(chain: list[ChainNode]) -> str | None:
        if not chain:
            return None
        return chain[0].provider

    @staticmethod
    def resolve_exit(chain: list[ChainNode]) -> str | None:
        if not chain:
            return None
        return chain[-1].provider
