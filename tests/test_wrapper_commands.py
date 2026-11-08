"""Tests for command definitions and tier classification."""

from __future__ import annotations

from src.wrapper.commands import CommandClassifier, Tier


class TestTier1Commands:
    """Tests for Tier 1 (dangerous) command classification."""

    def setup_method(self):
        self.classifier = CommandClassifier()

    def test_git_checkout_tier1(self):
        tier, reason = self.classifier.classify("git", ["git", "checkout", "main"])
        assert tier == Tier.TIER_1_DANGEROUS
        assert reason is None

    def test_git_switch_tier1(self):
        tier, reason = self.classifier.classify("git", ["git", "switch", "feature"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_git_merge_tier1(self):
        tier, reason = self.classifier.classify("git", ["git", "merge", "feature"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_git_pull_tier1(self):
        tier, reason = self.classifier.classify("git", ["git", "pull"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_git_rebase_tier1(self):
        tier, reason = self.classifier.classify("git", ["git", "rebase", "main"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_git_clone_tier1(self):
        tier, reason = self.classifier.classify("git", ["git", "clone", "https://example.com/repo.git"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_npm_install_tier1(self):
        tier, reason = self.classifier.classify("npm", ["npm", "install"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_npm_ci_tier1(self):
        tier, reason = self.classifier.classify("npm", ["npm", "ci"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_pip_install_tier1(self):
        tier, reason = self.classifier.classify("pip", ["pip", "install", "requests"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_pip3_install_tier1(self):
        tier, reason = self.classifier.classify("pip3", ["pip3", "install", "requests"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_cargo_install_tier1(self):
        tier, reason = self.classifier.classify("cargo", ["cargo", "install", "ripgrep"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_cargo_add_tier1(self):
        tier, reason = self.classifier.classify("cargo", ["cargo", "add", "serde"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_go_get_tier1(self):
        tier, reason = self.classifier.classify("go", ["go", "get", "github.com/foo/bar"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_make_install_tier1(self):
        tier, reason = self.classifier.classify("make", ["make", "install"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_docker_build_tier1(self):
        tier, reason = self.classifier.classify("docker", ["docker", "build", "."])
        assert tier == Tier.TIER_1_DANGEROUS


class TestTier2Commands:
    """Tests for Tier 2 (warn) command classification."""

    def setup_method(self):
        self.classifier = CommandClassifier()

    def test_git_status_tier2(self):
        tier, reason = self.classifier.classify("git", ["git", "status"])
        assert tier == Tier.TIER_2_WARN

    def test_git_diff_tier2(self):
        tier, reason = self.classifier.classify("git", ["git", "diff"])
        assert tier == Tier.TIER_2_WARN

    def test_git_log_tier2(self):
        tier, reason = self.classifier.classify("git", ["git", "log"])
        assert tier == Tier.TIER_2_WARN

    def test_npm_test_tier2(self):
        tier, reason = self.classifier.classify("npm", ["npm", "test"])
        assert tier == Tier.TIER_2_WARN

    def test_npm_run_tier2(self):
        tier, reason = self.classifier.classify("npm", ["npm", "run", "build"])
        assert tier == Tier.TIER_2_WARN

    def test_pip_list_tier2(self):
        tier, reason = self.classifier.classify("pip", ["pip", "list"])
        assert tier == Tier.TIER_2_WARN

    def test_cargo_build_tier1(self):
        tier, reason = self.classifier.classify("cargo", ["cargo", "build"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_cargo_test_tier1(self):
        tier, reason = self.classifier.classify("cargo", ["cargo", "test"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_go_build_tier1(self):
        tier, reason = self.classifier.classify("go", ["go", "build"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_go_test_tier1(self):
        tier, reason = self.classifier.classify("go", ["go", "test"])
        assert tier == Tier.TIER_1_DANGEROUS

    def test_make_tier2(self):
        tier, reason = self.classifier.classify("make", ["make"])
        assert tier == Tier.TIER_2_WARN

    def test_python_script_tier2(self):
        tier, reason = self.classifier.classify("python", ["python", "script.py"])
        assert tier == Tier.TIER_2_WARN

    def test_node_script_tier2(self):
        tier, reason = self.classifier.classify("node", ["node", "script.js"])
        assert tier == Tier.TIER_2_WARN

    def test_bash_tier2(self):
        tier, reason = self.classifier.classify("bash", ["bash", "script.sh"])
        assert tier == Tier.TIER_2_WARN


class TestTier3Commands:
    """Tests for Tier 3 (passthrough) command classification."""

    def setup_method(self):
        self.classifier = CommandClassifier()

    def test_git_version_tier3(self):
        tier, reason = self.classifier.classify("git", ["git", "--version"])
        assert tier == Tier.TIER_3_PASSTHROUGH

    def test_git_help_tier3(self):
        tier, reason = self.classifier.classify("git", ["git", "--help"])
        assert tier == Tier.TIER_3_PASSTHROUGH

    def test_npm_version_tier3(self):
        tier, reason = self.classifier.classify("npm", ["npm", "--version"])
        assert tier == Tier.TIER_3_PASSTHROUGH


class TestBypassDetection:
    """Tests for bypass detection."""

    def setup_method(self):
        self.classifier = CommandClassifier()

    def test_absolute_path_bypass(self):
        tier, reason = self.classifier.classify("/usr/bin/git", ["/usr/bin/git", "checkout", "main"])
        assert tier == Tier.BYPASS
        assert reason == "absolute_path"

    def test_shell_builtin_source_bypass(self):
        tier, reason = self.classifier.classify("source", ["source", "script.sh"])
        assert tier == Tier.BYPASS
        assert reason == "shell_builtin"

    def test_shell_builtin_eval_bypass(self):
        tier, reason = self.classifier.classify("eval", ["eval", "echo hello"])
        assert tier == Tier.BYPASS
        assert reason == "shell_builtin"

    def test_inline_bash_c_bypass(self):
        tier, reason = self.classifier.classify("bash", ["bash", "-c", "echo hello"])
        assert tier == Tier.BYPASS
        assert reason == "inline_interpreter"

    def test_inline_python_c_bypass(self):
        tier, reason = self.classifier.classify("python", ["python", "-c", "print('hello')"])
        assert tier == Tier.BYPASS
        assert reason == "inline_interpreter"

    def test_inline_node_c_bypass(self):
        tier, reason = self.classifier.classify("node", ["node", "-c", "console.log('hello')"])
        assert tier == Tier.BYPASS
        assert reason == "inline_interpreter"

    def test_sudo_bypass(self):
        tier, reason = self.classifier.classify("sudo", ["sudo", "npm", "install"])
        assert tier == Tier.BYPASS
        assert reason == "sudo_environment"

    def test_doas_bypass(self):
        tier, reason = self.classifier.classify("doas", ["doas", "npm", "install"])
        assert tier == Tier.BYPASS
        assert reason == "sudo_environment"


class TestArgumentPreservation:
    """Tests that arguments are preserved exactly."""

    def setup_method(self):
        self.classifier = CommandClassifier()

    def test_argv_structure_preserved(self):
        argv = ["git", "checkout", "-b", "feature/branch-name"]
        tier, reason = self.classifier.classify("git", argv)
        assert tier == Tier.TIER_1_DANGEROUS

    def test_complex_args_preserved(self):
        argv = ["npm", "install", "--save-dev", "@types/node@latest"]
        tier, reason = self.classifier.classify("npm", argv)
        assert tier == Tier.TIER_1_DANGEROUS

    def test_args_with_special_chars(self):
        argv = ["git", "commit", "-m", "feat: add 'quotes' and \"double\""]
        tier, reason = self.classifier.classify("git", argv)
        assert tier == Tier.TIER_1_DANGEROUS


class TestUnknownCommands:
    """Tests for unknown command handling."""

    def setup_method(self):
        self.classifier = CommandClassifier()

    def test_unknown_command_tier3_default(self):
        """Test unknown command not in dangerous list defaults to Tier 3."""
        tier, reason = self.classifier.classify("unknown_tool", ["unknown_tool", "dangerous"])
        assert tier == Tier.TIER_3_PASSTHROUGH

    def test_unknown_benign_command(self):
        tier, reason = self.classifier.classify("ls", ["ls", "-la"])
        assert tier == Tier.TIER_3_PASSTHROUGH

    def test_empty_argv(self):
        tier, reason = self.classifier.classify("git", ["git"])
        assert tier == Tier.TIER_2_WARN


class TestConfigHash:
    """Tests for configuration hashing."""

    def test_config_hash_consistent(self):
        classifier1 = CommandClassifier()
        classifier2 = CommandClassifier()
        assert classifier1.get_config_hash() == classifier2.get_config_hash()

    def test_scanner_version(self):
        classifier = CommandClassifier()
        assert classifier.get_scanner_version() == "1.0.0"

    def test_malware_db_version(self):
        classifier = CommandClassifier()
        assert classifier.get_malware_db_version() == "1.0.0"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])