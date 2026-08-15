"""Strategy-family expansion modules for ``standard.StandardGenerator``.

Each module provides a mixin with ``_fam_*`` expanders; ``StandardGenerator``
combines them into its full pipeline. Pure helpers live in ``_helpers``.
"""

from blockchecks.engine.generators.families.fake import FakeFamiliesMixin
from blockchecks.engine.generators.families.split import SplitFamiliesMixin
from blockchecks.engine.generators.families.tamper import TamperFamiliesMixin

__all__ = ["FakeFamiliesMixin", "SplitFamiliesMixin", "TamperFamiliesMixin"]
