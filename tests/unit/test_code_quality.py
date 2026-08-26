"""AST checks for nesting, elif chains, any/all, mutable defaults, bare except, and swallow.

Skip with ``# noqa: CQ001`` or ``# noqa: CQ`` on the line (or the previous line).
generators/ expanders skip nest/elif. Run: ``pytest -m quality``.
"""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from tests.unit._quality_config import PROJECT_ROOT, tool_section

_AST_CFG = tool_section("tool", "blockchecks", "ast_quality")
TARGET_DIRS = tuple(_AST_CFG.get("target_dirs") or ["src"])
IGNORE_NAMES = frozenset({"__init__.py"})
MAX_NESTING = int(_AST_CFG.get("max_nesting", 5))
MAX_ELIF = int(_AST_CFG.get("max_elif", 3))
_NEST_EXEMPT_PARTS = tuple(_AST_CFG.get("nest_exempt_parts") or ["/generators/"])

CQ_NEST = "CQ001"
CQ_ELIF = "CQ002"
CQ_COLLAPSE = "CQ004"
CQ_ANYALL = "CQ007"
CQ_MUTABLE = "CQ008"
CQ_BARE_EXC = "CQ009"
CQ_SWALLOW = "CQ016"
CQ_NEEDLESS_BOOL = "CQ010"
CQ_FLAG_LOOP = "CQ011"
CQ_PRINT = "CQ015"

_LOG_CALL_ATTRS = frozenset(
    {"debug", "info", "warning", "warn", "error", "critical", "exception", "log"}
)

_PRINT_ALLOW_NAMES = frozenset(
    {
        "_probe_worker.py",
        "_curl_probe_worker.py",
        "in_ns_workers.py",
    }
)

_NOQA_RE = re.compile(r"\bnoqa\s*:\s*([A-Z0-9,\s]+)", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    code: str
    lineno: int
    message: str


def _is_nest_exempt(path: Path) -> bool:
    posix = path.as_posix()
    return any(part in posix for part in _NEST_EXEMPT_PARTS)


@dataclass
class CodeQualityVisitor(ast.NodeVisitor):
    """Detect deep / branched control flow that hurts readability."""

    source: str
    file_path: Path
    findings: list[Finding] = field(default_factory=list)
    _lines: list[str] = field(default_factory=list, init=False, repr=False)
    _depth: int = field(default=0, init=False, repr=False)
    _in_func: int = field(default=0, init=False, repr=False)
    _func_flags: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _nest_exempt: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        self._lines = self.source.splitlines()
        self._nest_exempt = _is_nest_exempt(self.file_path)

    def _emit(self, code: str, node: ast.AST, message: str) -> None:
        lineno = getattr(node, "lineno", 1) or 1
        if self._noqa(lineno, code):
            return
        self.findings.append(Finding(code, lineno, message))

    def _noqa(self, lineno: int, code: str) -> bool:
        for idx in (lineno - 1, lineno - 2):
            if idx < 0 or idx >= len(self._lines):
                continue
            m = _NOQA_RE.search(self._lines[idx])
            if not m:
                continue
            codes = {c.strip().upper() for c in m.group(1).split(",") if c.strip()}
            if "CQ" in codes or code in codes:
                return True
        return False

    def _enter_block(self, node: ast.AST) -> None:
        if self._in_func <= 0 or self._nest_exempt:
            return
        self._depth += 1
        if self._depth > MAX_NESTING:
            self._emit(
                CQ_NEST,
                node,
                f"nesting depth {self._depth}/{MAX_NESTING} — use guard clauses or extract a function",
            )

    def _leave_block(self) -> None:
        if self._in_func <= 0 or self._nest_exempt:
            return
        self._depth = max(0, self._depth - 1)

    def _visit_stmts(self, stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            self.visit(stmt)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scan_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._scan_function(node)

    def _scan_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._check_mutable_defaults(node)
        prev_flags = self._func_flags
        self._func_flags = {}
        self._in_func += 1
        for deco in node.decorator_list:
            self.visit(deco)
        self._visit_stmts(node.body)
        self._in_func -= 1
        self._func_flags = prev_flags

    def visit_If(self, node: ast.If) -> None:
        """if/elif/else = one nesting level (do not double-count elif)."""
        self._check_elif_chain(node)
        self._check_collapsible_if(node)
        self._check_needless_bool(node)

        self._enter_block(node)
        self._visit_stmts(node.body)

        current: ast.If | None = node
        while current is not None:
            orelse = current.orelse
            if len(orelse) == 1 and isinstance(orelse[0], ast.If):
                current = orelse[0]
                self._visit_stmts(current.body)
            else:
                self._visit_stmts(orelse)
                current = None
        self._leave_block()

    def visit_For(self, node: ast.For) -> None:
        self._check_any_all_loop(node)
        self._check_flag_loop(node)
        self._enter_block(node)
        self._visit_stmts(node.body)
        self._visit_stmts(node.orelse)
        self._leave_block()

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._enter_block(node)
        self._visit_stmts(node.body)
        self._visit_stmts(node.orelse)
        self._leave_block()

    def visit_While(self, node: ast.While) -> None:
        self._check_any_all_loop(node)
        self._check_flag_loop(node)
        self._enter_block(node)
        self._visit_stmts(node.body)
        self._visit_stmts(node.orelse)
        self._leave_block()

    def visit_With(self, node: ast.With) -> None:
        # Resource managers do not count toward arrow depth.
        self._visit_stmts(node.body)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._visit_stmts(node.body)

    def visit_Try(self, node: ast.Try) -> None:
        self._check_bare_except(node)
        self._check_exception_swallow(node)
        # Nested try is often intentional cleanup — not counted.
        self._visit_stmts(node.body)
        for handler in node.handlers:
            self._visit_stmts(handler.body)
        self._visit_stmts(node.orelse)
        self._visit_stmts(node.finalbody)

    def visit_Match(self, node: ast.Match) -> None:
        self._enter_block(node)
        for case in node.cases:
            self._visit_stmts(case.body)
        self._leave_block()

    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)
        if not isinstance(node.func, ast.Name) or node.func.id != "print":
            return
        if self.file_path.name in _PRINT_ALLOW_NAMES:
            return
        if self._noqa(node.lineno, "PRINT"):
            return
        self._emit(
            CQ_PRINT,
            node,
            "operator print() — use logging.getLogger(__name__) or `# noqa: print`",
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        self._track_bool_flag(node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None and isinstance(node.target, ast.Name):
            fake = ast.Assign(
                targets=[node.target],
                value=node.value,
                lineno=node.lineno,
                col_offset=node.col_offset,
            )
            self._track_bool_flag(fake)
        self.generic_visit(node)

    def _check_elif_chain(self, node: ast.If) -> None:
        if self._nest_exempt:
            return
        elif_count = 0
        current = node
        while current.orelse and len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
            elif_count += 1
            current = current.orelse[0]
        if elif_count > MAX_ELIF:
            self._emit(
                CQ_ELIF,
                node,
                f"if/elif chain of {elif_count + 1} branches — use match/case or a mapping",
            )

    def _check_collapsible_if(self, node: ast.If) -> None:
        """SIM102 — flatten nested guards (core horizontality micro-rule)."""
        if node.orelse:
            return
        if len(node.body) != 1 or not isinstance(node.body[0], ast.If):
            return
        if node.body[0].orelse:
            return
        self._emit(
            CQ_COLLAPSE,
            node,
            "nested if without else — collapse to `if a and b`",
        )

    def _check_needless_bool(self, node: ast.If) -> None:
        if len(node.body) != 1 or len(node.orelse) != 1:
            return
        body, orelse = node.body[0], node.orelse[0]
        if not isinstance(body, ast.Return) or not isinstance(orelse, ast.Return):
            return
        if not isinstance(body.value, ast.Constant) or not isinstance(orelse.value, ast.Constant):
            return
        if {body.value.value, orelse.value.value} != {True, False}:
            return
        self._emit(CQ_NEEDLESS_BOOL, node, "return the condition directly: `return <cond>`")

    def _check_any_all_loop(self, node: ast.For | ast.While) -> None:
        if len(node.body) != 1 or not isinstance(node.body[0], ast.If):
            return
        inner = node.body[0]
        if inner.orelse or len(inner.body) != 1 or not isinstance(inner.body[0], ast.Return):
            return
        ret = inner.body[0].value
        if isinstance(ret, ast.Constant) and ret.value is True:
            self._emit(CQ_ANYALL, node, "replace the loop with `return any(...)`")
        elif isinstance(ret, ast.Constant) and ret.value is False:
            self._emit(CQ_ANYALL, node, "replace the loop with `all(...)` / inverted any")

    def _check_flag_loop(self, node: ast.For | ast.While) -> None:
        if not self._func_flags:
            return
        for child in ast.walk(node):
            if isinstance(child, ast.Assign) and len(child.targets) == 1:
                t = child.targets[0]
                if isinstance(t, ast.Name) and t.id in self._func_flags:
                    self._emit(
                        CQ_FLAG_LOOP,
                        node,
                        f"flag `{t.id}` plus a loop — use `any()`/`all()`",
                    )
                    return

    def _check_bare_except(self, node: ast.Try) -> None:
        for handler in node.handlers:
            if handler.type is None:
                self._emit(CQ_BARE_EXC, handler, "bare `except:` — name the exception type")

    def _check_exception_swallow(self, node: ast.Try) -> None:
        for handler in node.handlers:
            if handler.type is None:
                continue
            has_log_or_raise = _body_has_log_or_raise(handler.body)
            if has_log_or_raise:
                continue
            if not _is_swallow_body(handler.body):
                continue
            catches_base = _type_includes_name(handler.type, "BaseException")
            catches_exc = _type_includes_name(handler.type, "Exception")
            catches_cancelled = _type_includes_name(handler.type, "CancelledError")
            if catches_base:
                self._emit(
                    CQ_SWALLOW,
                    handler,
                    "silent `except BaseException` — re-raise asyncio.CancelledError",
                )
            elif catches_cancelled:
                self._emit(
                    CQ_SWALLOW,
                    handler,
                    "swallowed asyncio.CancelledError — must re-raise",
                )
            elif catches_exc:
                self._emit(
                    CQ_SWALLOW,
                    handler,
                    "silent `except Exception` — log or narrow the type",
                )

    def _check_mutable_defaults(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is None:
                continue
            if isinstance(default, (ast.List, ast.Dict, ast.Set)) or (
                isinstance(default, ast.Call)
                and isinstance(default.func, ast.Name)
                and default.func.id in {"list", "dict", "set"}
            ):
                self._emit(CQ_MUTABLE, node, "mutable default arg — None + guard (B006)")

    def _track_bool_flag(self, node: ast.Assign) -> None:
        if self._in_func <= 0:
            return
        if not isinstance(node.value, ast.Constant) or node.value.value is not False:
            return
        for t in node.targets:
            if isinstance(t, ast.Name) and (
                t.id.startswith(("has_", "found")) or t.id.endswith("_found")
            ):
                self._func_flags[t.id] = node.lineno


def _type_includes_name(node: ast.expr, name: str) -> bool:
    if isinstance(node, ast.Name):
        return node.id == name
    if isinstance(node, ast.Attribute):
        return node.attr == name
    if isinstance(node, ast.Tuple):
        return any(_type_includes_name(elt, name) for elt in node.elts)
    return False


def _is_swallow_body(stmts: list[ast.stmt]) -> bool:
    if not stmts:
        return True
    if len(stmts) != 1:
        return False
    stmt = stmts[0]
    if isinstance(stmt, ast.Pass):
        return True
    if isinstance(stmt, ast.Continue):
        return True
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and stmt.value.value is Ellipsis
    )


def _is_logging_call(node: ast.Call) -> bool:
    func = node.func
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr not in _LOG_CALL_ATTRS:
        return False
    if isinstance(func.value, ast.Name):
        return True
    return isinstance(func.value, ast.Attribute) and func.value.attr == "logging"


def _body_has_log_or_raise(stmts: list[ast.stmt]) -> bool:
    for stmt in stmts:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Raise):
                return True
            if isinstance(node, ast.Call) and _is_logging_call(node):
                return True
    return False


def iter_python_files() -> list[Path]:
    files: list[Path] = []
    for dirname in TARGET_DIRS:
        root = PROJECT_ROOT / dirname
        if not root.is_dir():
            continue
        files.extend(
            sorted(p for p in root.rglob("*.py") if p.name not in IGNORE_NAMES and p.is_file())
        )
    return files


def analyze_file(path: Path) -> list[Finding]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    visitor = CodeQualityVisitor(source=source, file_path=path)
    visitor.visit(tree)
    return sorted(visitor.findings, key=lambda f: (f.lineno, f.code))


@pytest.mark.unit
@pytest.mark.quality
@pytest.mark.parametrize(
    "file_path",
    iter_python_files(),
    ids=lambda p: str(p.relative_to(PROJECT_ROOT)),
)
def test_ast_code_quality(file_path: Path) -> None:
    """Fail on deep nesting, long elif trees, and flattenable guards."""
    try:
        findings = analyze_file(file_path)
    except SyntaxError as exc:
        pytest.fail(f"SyntaxError in {file_path.relative_to(PROJECT_ROOT)}: {exc}")

    findings = [f for f in findings if f.code != CQ_SWALLOW]
    if not findings:
        return

    rel = file_path.relative_to(PROJECT_ROOT)
    report = "\n".join(
        [
            f"\n{rel}: {len(findings)} readability finding(s):",
            *(f"  L{f.lineno} [{f.code}] {f.message}" for f in findings),
            "\nFlatten control flow or `# noqa: CQxxx` on the offending line.",
        ]
    )
    pytest.fail(report)


@pytest.mark.unit
@pytest.mark.quality
def test_cq016_swallow_baseline_cap() -> None:
    """CQ016 is capped — fail only when new silent Exception/BaseException handlers appear."""
    cap = int(_AST_CFG.get("cq016_baseline", 0))
    total = 0
    samples: list[str] = []
    for path in iter_python_files():
        try:
            findings = [f for f in analyze_file(path) if f.code == CQ_SWALLOW]
        except SyntaxError as exc:
            pytest.fail(f"SyntaxError in {path.relative_to(PROJECT_ROOT)}: {exc}")
        if not findings:
            continue
        total += len(findings)
        rel = path.relative_to(PROJECT_ROOT)
        for f in findings:
            samples.append(f"  {rel}:L{f.lineno} {f.message}")

    if total > cap:
        report = "\n".join(
            [
                f"CQ016 baseline exceeded: {total} finding(s) > cap {cap}",
                *samples[:40],
                *(["  ..."] if len(samples) > 40 else []),
                "Log the exception, narrow the type, re-raise CancelledError, or `# noqa: CQ016`.",
            ]
        )
        pytest.fail(report)


@pytest.mark.unit
@pytest.mark.quality
def test_cq016_detector_fires_on_samples() -> None:
    """Synthetic fixture proves CQ016 detects swallow patterns and respects noqa."""
    fixture = Path(__file__).with_name("fixtures") / "cq016_detector_samples.py"
    findings = [f for f in analyze_file(fixture) if f.code == CQ_SWALLOW]
    messages = {f.message for f in findings}
    assert any("except Exception" in m for m in messages)
    assert any("CancelledError" in m for m in messages)
    noqa_lines = {f.lineno for f in findings}
    assert 33 not in noqa_lines, "noqa: CQ016 should suppress the handler"


@pytest.mark.unit
@pytest.mark.quality
def test_ruff_skill_gate() -> None:
    """Ruff SIM + McCabe + narrow bugbear/UP — select list from pyproject.toml."""
    ruff = shutil.which("ruff") or str(PROJECT_ROOT / ".venv" / "bin" / "ruff")
    if not Path(ruff).is_file():
        pytest.skip("ruff not installed (pip install -e '.[dev]')")

    cfg = tool_section("tool", "blockchecks", "ruff_quality")
    select = ",".join(cfg.get("select") or ["SIM", "C90"])
    ignore = ",".join(cfg.get("ignore") or [])
    cmd = [
        ruff,
        "check",
        "src",
        "--config",
        str(PROJECT_ROOT / "pyproject.toml"),
        "--select",
        select,
    ]
    if ignore:
        cmd.extend(["--ignore", ignore])
    proc = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True, check=False)
    if proc.returncode == 0:
        return
    out = (proc.stdout or "") + (proc.stderr or "")
    pytest.fail(f"ruff quality gate failed ({proc.returncode}):\n{out}")
