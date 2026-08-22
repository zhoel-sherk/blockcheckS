"""Optional DPI diagnostics borrowed from dpi-checkers / dpi-detector.

Off by default. Enable with ``--dpi-diag`` on ``bs preflight`` / scan / pair / full.
Does not change the default preflight chain or FailPhase taxonomy.
"""

from blockchecks.checkers.dpi_diag.runner import DpiDiagReport, apply_overlay, run_dpi_diag

__all__ = ["DpiDiagReport", "apply_overlay", "run_dpi_diag"]
