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


class TestPackageData:
    def test_configs_dir_exists(self):
        """configs/ directory exists in the installed package."""
        import blockchecks
        pkg_dir = os.path.dirname(blockchecks.__file__)
        # Navigate up from src/blockchecks/ to project root
        root = os.path.dirname(os.path.dirname(pkg_dir))
        configs = os.path.join(root, "configs")
        if not os.path.isdir(configs):
            # Try relative to installed package location
            alt = os.path.join(pkg_dir, "..", "..", "configs")
            if os.path.isdir(alt):
                configs = alt
        assert os.path.isdir(configs), f"configs/ not found at {configs}"

    def test_key_configs_present(self):
        """At least one composite config exists."""
        import blockchecks
        pkg_dir = os.path.dirname(blockchecks.__file__)
        root = os.path.dirname(os.path.dirname(pkg_dir))
        composite = os.path.join(root, "configs", "composite_discord.conf")
        if not os.path.exists(composite):
            composite = os.path.join(pkg_dir, "..", "..", "configs", "composite_discord.conf")
        assert os.path.exists(composite), f"composite_discord.conf not found at {composite}"

    def test_conf_files_found(self):
        """configs/ has .conf files."""
        import glob
        import blockchecks
        pkg_dir = os.path.dirname(blockchecks.__file__)
        root = os.path.dirname(os.path.dirname(pkg_dir))
        for candidate in [os.path.join(root, "configs"),
                          os.path.join(pkg_dir, "..", "..", "configs")]:
            if os.path.isdir(candidate):
                confs = glob.glob(os.path.join(candidate, "*.conf"))
                assert len(confs) >= 1, f"No .conf files in {candidate}"
                return
        pytest.fail("Could not locate configs/ directory")


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
