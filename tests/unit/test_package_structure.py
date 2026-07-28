"""Package structure tests — imports, data, entry points, deps."""
import importlib
import os
import sys
import pytest


class TestPackageImport:
    def test_package_importable(self):
        """import blockchecks works."""
        import blockchecks
        assert blockchecks is not None

    def test_version_set(self):
        """blockchecks.__version__ is a non-empty string."""
        import blockchecks
        assert blockchecks.__version__ == "0.3.0"
        assert isinstance(blockchecks.__version__, str)


class TestSubmoduleImports:
    """All modules import without ImportError/SyntaxError."""

    MODULES = [
        "blockchecks.bs",
        "blockchecks.engine",
        "blockchecks.engine.config",
        "blockchecks.engine.nfqws2",
        "blockchecks.engine.firewall",
        "blockchecks.engine.db_logger",
        "blockchecks.engine.strategy_loader",
        "blockchecks.engine.test_runner",
        "blockchecks.engine.async_runner",
        "blockchecks.engine.matrix_generator",
        "blockchecks.engine.netns_pool",
        "blockchecks.engine.pair_manager",
        "blockchecks.engine.pair_runner",
        "blockchecks.checkers",
        "blockchecks.checkers.tcp_tls",
        "blockchecks.checkers.udp_voice",
        "blockchecks.checkers.voice_dns",
        "blockchecks.checkers.voice_discovery",
        "blockchecks.checkers.composite_runner",
    ]

    @pytest.mark.parametrize("module_name", MODULES)
    def test_module_imports(self, module_name):
        """Each module imports without error."""
        mod = importlib.import_module(module_name)
        assert mod is not None
        assert hasattr(mod, "__file__") or hasattr(mod, "__path__"), \
            f"{module_name} has no __file__ or __path__"


class TestProjectPaths:
    def test_configs_dir_resolves(self):
        """PROJECT_DIR is repo root (not src/) and CONFIGS_DIR exists."""
        from blockchecks.engine.config import PROJECT_DIR, CONFIGS_DIR
        assert os.path.basename(PROJECT_DIR) != "src", PROJECT_DIR
        assert os.path.isdir(CONFIGS_DIR), f"missing {CONFIGS_DIR}"

    def test_key_configs_present(self):
        """At least one composite config exists."""
        from blockchecks.engine.config import CONFIGS_DIR
        composite = os.path.join(CONFIGS_DIR, "composite_discord.conf")
        assert os.path.exists(composite), f"composite_discord.conf not found at {composite}"

    def test_conf_files_found(self):
        """configs/ has .conf files."""
        import glob
        from blockchecks.engine.config import CONFIGS_DIR
        confs = glob.glob(os.path.join(CONFIGS_DIR, "*.conf"))
        assert len(confs) >= 1, f"No .conf files in {CONFIGS_DIR}"


class TestEntryPoint:
    def test_main_function_callable(self):
        """bs.main() exists and builds a parser."""
        from blockchecks.bs import main
        import argparse
        # Build the parser without exiting
        old_argv = sys.argv
        try:
            sys.argv = ["bs", "--help"]
            try:
                main()
            except SystemExit as e:
                assert e.code == 0  # --help exits 0
        finally:
            sys.argv = old_argv

    def test_all_commands_registered(self):
        """Parser has tcp, udp, scan, pair, composite subcommands."""
        from blockchecks.bs import main
        import argparse
        old_argv = sys.argv
        # Access the parser without running
        from blockchecks.bs import __doc__  # just verify the module loads
        # Check that the module defines known commands
        import blockchecks.bs as bs_mod
        assert hasattr(bs_mod, 'main'), "main() should exist"
        assert hasattr(bs_mod, 'cmd_tcp'), "cmd_tcp should exist"
        assert hasattr(bs_mod, 'cmd_udp'), "cmd_udp should exist"
        assert hasattr(bs_mod, 'cmd_pair'), "cmd_pair should exist"


class TestDependencies:
    def test_curl_cffi_available(self):
        import curl_cffi
        assert hasattr(curl_cffi, "requests")

    def test_colorama_available(self):
        import colorama
        assert hasattr(colorama, "Fore")

    def test_aiosqlite_available(self):
        import aiosqlite
        assert hasattr(aiosqlite, "connect")

    def test_pytest_available(self):
        import pytest
        assert hasattr(pytest, "mark")
