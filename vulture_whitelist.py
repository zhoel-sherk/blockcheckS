"""Vulture whitelist — names referenced dynamically / via entry points.

Included in [tool.vulture] paths so these symbols count as used.
"""

# CLI / console_scripts entry points
from blockchecks.bs import main as bs_main  # noqa: F401
from blockchecks.engine.domain_loader import (  # noqa: F401
    RESERVED_DOMAIN_FILES,
    preset_path,
)

# Re-exports used by tests / external callers
from blockchecks.engine.preset_paths import (  # noqa: F401
    PresetPathError,
    normalize_preset_name,
    resolve_domain_preset,
    resolve_strategy_preset,
)
from blockchecks.main import main as bc_main  # noqa: F401
from blockchecks.nfconf import main as nfconf_main  # noqa: F401
