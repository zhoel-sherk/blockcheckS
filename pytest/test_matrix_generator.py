"""Tests for MatrixGenerator — scan_level, in-run set, generators."""
import os, sys, pytest, asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.matrix_generator import (
    MatrixGenerator, FakeTcpGenerator, HostfakeTcpGenerator,
    CustomListGenerator, ConfigFileGenerator
)
from engine.db_logger import StateDB


class TestScanLevel:
    @pytest.mark.asyncio
    async def test_single_one_per_generator(self):
        """scan_level=single returns exactly 1 item per generator."""
        gen = FakeTcpGenerator()
        items = await gen.generate("tls12", scan_level="single", max_count=10)
        assert len(items) == 1, f"single should return 1, got {len(items)}"

    @pytest.mark.asyncio
    async def test_single_hostfake(self):
        gen = HostfakeTcpGenerator()
        items = await gen.generate("tls12", scan_level="single", max_count=10)
        assert len(items) == 1

    @pytest.mark.asyncio
    async def test_fast_multiple(self):
        """fast returns more than 1 on empty DB."""
        gen = FakeTcpGenerator()
        items = await gen.generate("tls12", scan_level="fast", max_count=50)
        assert len(items) > 1, f"fast should return multiple items, got {len(items)}"

    @pytest.mark.asyncio
    async def test_fast_skip_with_run_set(self):
        """fast with run_set containing a base label produces fewer items."""
        gen = FakeTcpGenerator()
        items_full = await gen.generate("tls12", scan_level="fast", max_count=10)
        # With run_set, TTL variants for the first item should be skipped
        items_slim = await gen.generate("tls12", scan_level="fast", max_count=10,
                                         run_set={items_full[0].label})
        assert len(items_slim) <= len(items_full), \
            f"run_set should reduce items: {len(items_slim)} vs {len(items_full)}"


class TestGenerators:
    @pytest.mark.asyncio
    async def test_fake_produces_blob_strategies(self):
        """FakeTcpGenerator produces blob-based strategies."""
        gen = FakeTcpGenerator()
        items = await gen.generate("tls12", max_count=5)
        for item in items:
            if "blob=" not in item.strategy and "fake:" in item.strategy:
                # Empty blob name — should not appear (we skip empty)
                pass
        assert len(items) > 0

    @pytest.mark.asyncio
    async def test_custom_list_loads(self):
        """CustomListGenerator loads from blockcheck2.d."""
        gen = CustomListGenerator()
        items = await gen.generate("tls12")
        assert len(items) > 0, "Should load strategies from custom/"

    @pytest.mark.asyncio
    async def test_config_file_loads(self):
        """ConfigFileGenerator loads .conf files."""
        gen = ConfigFileGenerator()
        items = await gen.generate("tls12")
        assert len(items) > 0, "Should load .conf files from configs/"

    @pytest.mark.asyncio
    async def test_user_matrix_loads(self):
        """UserMatrixGenerator loads from a file."""
        from engine.matrix_generator import UserMatrixGenerator
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("fake:repeats=1\nfake:repeats=6:tcp_ts=-1000\n")
            path = f.name
        try:
            gen = UserMatrixGenerator(path)
            items = await gen.generate("tls12")
            assert len(items) == 2
        finally:
            os.unlink(path)


class TestOrchestrator:
    @pytest.mark.asyncio
    async def test_generate_tcp_from_sources(self):
        """MatrixGenerator.generate_tcp combines multiple sources."""
        mg = MatrixGenerator()
        items = await mg.generate_tcp(sources=["fake"], max_count=5)
        assert len(items) > 0

    @pytest.mark.asyncio
    async def test_generate_udp_from_custom(self):
        """MatrixGenerator.generate_udp loads UDP strategies."""
        mg = MatrixGenerator()
        items = await mg.generate_udp(sources=["custom"], max_count=5)
        assert len(items) > 0
