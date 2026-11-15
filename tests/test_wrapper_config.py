"""Tests for wrapper configuration."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from p4_1_home_rc_guard import guard_primary_home_rc
from src.wrapper.config import WrapperConfig, load_config


class TestWrapperConfigDefaults:
    """Tests for default configuration values."""

    def test_default_enabled_shells(self):
        config = WrapperConfig()
        assert config.enabled_shells == ["bash", "zsh", "fish"]

    def test_default_wrapper_dir(self):
        config = WrapperConfig()
        assert "linuxsecmonitor" in config.wrapper_dir or ".local/bin" in config.wrapper_dir

    def test_default_wrapper_commands(self):
        config = WrapperConfig()
        assert "git" in config.wrapper_commands
        assert "npm" in config.wrapper_commands
        assert "python" in config.wrapper_commands

    def test_default_tier1_commands(self):
        config = WrapperConfig()
        assert "checkout" in config.tier1_commands
        assert "install" in config.tier1_commands

    def test_default_tier2_commands(self):
        config = WrapperConfig()
        assert "status" in config.tier2_commands
        assert "test" in config.tier2_commands

    def test_default_cache_settings(self):
        config = WrapperConfig()
        assert config.cache_enabled is True
        assert config.cache_ttl_seconds == 300
        assert config.cache_max_entries == 1000

    def test_default_security_settings(self):
        config = WrapperConfig()
        assert config.fail_closed_on_scan_error is True
        assert config.fail_closed_on_malware_detection is True
        assert config.fail_closed_on_critical_finding is True
        assert config.require_tty_for_approval is True


class TestWrapperConfigLoad:
    """Tests for loading configuration from TOML."""

    def test_load_nonexistent_file_returns_defaults(self):
        config = load_config(Path("/nonexistent/path/wrapper.toml"))
        assert isinstance(config, WrapperConfig)
        assert config.enabled_shells == ["bash", "zsh", "fish"]

    def test_load_valid_toml(self, tmp_path):
        config_file = tmp_path / "wrapper.toml"
        config_file.write_text("""
enabled_shells = ["bash"]
cache_ttl_seconds = 600
fail_closed_on_scan_error = true
""")
        config = load_config(config_file)
        assert config.enabled_shells == ["bash"]
        assert config.cache_ttl_seconds == 600
        assert config.fail_closed_on_scan_error is True

    def test_load_invalid_toml_raises(self, tmp_path):
        config_file = tmp_path / "wrapper.toml"
        config_file.write_text("invalid toml [")
        with pytest.raises(ValueError, match="Invalid TOML"):
            load_config(config_file)

    def test_load_partial_config_uses_defaults(self, tmp_path):
        config_file = tmp_path / "wrapper.toml"
        config_file.write_text("cache_ttl_seconds = 100")
        config = load_config(config_file)
        assert config.cache_ttl_seconds == 100
        # Other values should be defaults
        assert config.enabled_shells == ["bash", "zsh", "fish"]
        assert config.cache_max_entries == 1000


class TestWrapperConfigFromDict:
    """Tests for creating configuration from dictionary."""

    def test_from_dict_valid(self):
        data = {
            "enabled_shells": ["bash", "zsh"],
            "cache_ttl_seconds": 200,
        }
        config = WrapperConfig.from_dict(data)
        assert config.enabled_shells == ["bash", "zsh"]
        assert config.cache_ttl_seconds == 200
        assert config.cache_max_entries == 1000  # default

    def test_from_dict_ignores_unknown_keys(self):
        data = {
            "enabled_shells": ["bash"],
            "unknown_key": "should be ignored",
        }
        config = WrapperConfig.from_dict(data)
        assert config.enabled_shells == ["bash"]
        assert not hasattr(config, "unknown_key")


class TestWrapperConfigToDict:
    """Tests for serializing configuration to dictionary."""

    def test_to_dict_contains_all_fields(self):
        config = WrapperConfig()
        data = config.to_dict()
        assert "enabled_shells" in data
        assert "wrapper_dir" in data
        assert "cache_ttl_seconds" in data
        assert "fail_closed_on_scan_error" in data

    def test_to_dict_roundtrip(self):
        config = WrapperConfig(cache_ttl_seconds=400)
        data = config.to_dict()
        config2 = WrapperConfig.from_dict(data)
        assert config2.cache_ttl_seconds == 400


class TestWrapperConfigValidation:
    """Tests for configuration validation."""

    def test_valid_config_passes(self):
        config = WrapperConfig()
        errors = config.validate()
        assert errors == []

    def test_invalid_fail_closed_settings(self):
        config = WrapperConfig(
            fail_closed_on_scan_error=False,
            fail_closed_on_malware_detection=False,
            fail_closed_on_critical_finding=False,
        )
        errors = config.validate()
        assert len(errors) == 3
        assert any("fail_closed_on_scan_error" in e for e in errors)
        assert any("fail_closed_on_malware_detection" in e for e in errors)
        assert any("fail_closed_on_critical_finding" in e for e in errors)

    def test_invalid_timeouts(self):
        config = WrapperConfig(
            scan_timeout_seconds=0,
            approval_timeout_seconds=-1,
            staging_timeout_seconds=0,
        )
        errors = config.validate()
        assert any("scan_timeout_seconds" in e for e in errors)
        assert any("approval_timeout_seconds" in e for e in errors)
        assert any("staging_timeout_seconds" in e for e in errors)

    def test_invalid_cache_settings(self):
        config = WrapperConfig(
            cache_ttl_seconds=0,
            cache_max_entries=0,
            cache_max_size_mb=0,
        )
        errors = config.validate()
        assert any("cache_ttl_seconds" in e for e in errors)
        assert any("cache_max_entries" in e for e in errors)
        assert any("cache_max_size_mb" in e for e in errors)

    def test_invalid_log_level(self):
        config = WrapperConfig(log_level="INVALID")
        errors = config.validate()
        assert any("log_level" in e for e in errors)

    def test_invalid_path_traversal(self):
        config = WrapperConfig(wrapper_dir="/tmp/../../etc")
        errors = config.validate()
        assert any("wrapper_dir" in e for e in errors)


class TestWrapperConfigSave:
    """Tests for saving configuration to TOML."""

    def test_save_creates_file(self, tmp_path):
        try:
            import tomli_w
        except ImportError:
            pytest.skip("tomli_w not available")

        config = WrapperConfig(cache_ttl_seconds=500)
        config_file = tmp_path / "wrapper.toml"
        config.save(config_file)

        assert config_file.exists()
        loaded = load_config(config_file)
        assert loaded.cache_ttl_seconds == 500

    def test_save_creates_parent_directories(self, tmp_path):
        try:
            import tomli_w
        except ImportError:
            pytest.skip("tomli_w not available")

        config = WrapperConfig()
        config_file = tmp_path / "subdir" / "wrapper.toml"
        config.save(config_file)
        assert config_file.exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])