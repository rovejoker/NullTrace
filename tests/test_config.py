import yaml


def test_config_has_required_sections():
    with open("config.yaml") as f:
        config = yaml.safe_load(f)
    assert "proxy" in config
    assert "defaults" in config
    assert "free_pool" in config
    assert "tor" in config
    assert "webui" in config


def test_proxy_defaults():
    with open("config.yaml") as f:
        config = yaml.safe_load(f)
    assert config["proxy"]["host"] == "127.0.0.1"
    assert config["proxy"]["port"] == 1080
    assert config["defaults"]["provider"] == "free"
