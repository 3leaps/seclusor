#!/usr/bin/env python3
"""Closed callsite inventory for child-environment construction (008-A).

Load-bearing proof: every production **spawn** (`Command::new`) and every
production **env mutation** (`env` / `envs` / `env_clear` / `env_remove`, method
or UFCS, including type/import aliases of `Command`) lives only at the reviewed
chokepoint sites. Pattern matches SC-TASK-006's closed inventory:

1. Each allowed callsite carries a stable `// child-env-callsite: <id>` marker
   directly above the line, in the inventoried file only.
2. Discovered markers across *all* production sources must EQUAL the inventory
   (unknown / misplaced / duplicated fail closed).
3. A denylist scan rejects unscoped spawn and env mutation (including aliases).
4. `--scan <file>` exercises the denylist against a fixture (negative-control mode).

This inventory proves **spawn + env-mutation monopoly** for credential-consuming
children. `ChildEnv::apply` remains the only env mutator; `handlers/run.rs` is
the only production process constructor for that path.

Exit 1 on any violation; 0 when the inventory holds.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (id, relative path, exact next non-blank code line after strip of trailing comment)
CHILD_ENV_CALLSITES = [
    (
        "apply-env-clear",
        "crates/seclusor/src/child_env.rs",
        "command.env_clear();",
    ),
    (
        "apply-env-set",
        "crates/seclusor/src/child_env.rs",
        "command.env(key, value);",
    ),
    (
        "run-spawn",
        "crates/seclusor/src/handlers/run.rs",
        "let mut command = Command::new(&args.command[0]);",
    ),
]

# Marker ids that are env mutations vs spawns (for clearer diagnostics).
ENV_MUTATION_IDS = {"apply-env-clear", "apply-env-set"}
SPAWN_IDS = {"run-spawn"}

MARKER_RE = re.compile(r"^\s*//\s*child-env-callsite:\s*(\S+)\s*$")
_TURBO = r"(?:::\s*<[^>]*>)?"
ENV_METHOD_RE = re.compile(rf"\.(?:env|envs|env_clear|env_remove){_TURBO}\s*\(")
# Literal Command / std::process::Command UFCS env forms.
ENV_UFCS_LITERAL_RE = re.compile(
    rf"(?:std::process::)?Command\s*::\s*(?:env|envs|env_clear|env_remove){_TURBO}\s*\("
)
# Command::new / std::process::Command::new (spawn construction).
SPAWN_LITERAL_RE = re.compile(r"(?:std::process::)?Command\s*::\s*new\s*\(")

# Alias collection.
USE_COMMAND_AS = re.compile(r"\buse\s+(?:std::process::)?Command\s+as\s+(\w+)\s*;")
USE_GROUP_COMMAND_AS = re.compile(
    r"\buse\s+std::process\s*\{[^}]*\bCommand\s+as\s+(\w+)[^}]*\}\s*;"
)
TYPE_COMMAND_ALIAS = re.compile(r"\btype\s+(\w+)\s*=\s*(?:std::process::)?Command\s*;")

MOD_OPEN_RE = re.compile(r"\bmod\s+\w+\s*\{")
CFG_ATTR_RE = re.compile(r"#\[cfg\((.*)\)\]")


def note(msg: str) -> None:
    print(f"[child-env-guard] {msg}", file=sys.stderr)


def strip_line_comment(line: str) -> str:
    if "//" in line:
        return line[: line.index("//")].rstrip()
    return line.rstrip()


def _split_cfg_top_level(inner: str) -> list[str]:
    """Split cfg predicate args on top-level commas (paren-aware)."""
    parts: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(inner):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(inner[start:i].strip())
            start = i + 1
    parts.append(inner[start:].strip())
    return [p for p in parts if p]


def is_test_only_cfg(inner: str) -> bool:
    """True when the cfg only compiles under `cfg(test)` (never production).

    Accepts `test`, `all(test, …)`. Rejects `not(test)`, `feature = "…"`,
    `any(test, feature = "x")`, and feature names that merely contain the
    substring "test" / "latest".
    """
    s = re.sub(r"\s+", "", inner)
    if s == "test":
        return True
    if s.startswith("all(") and s.endswith(")"):
        args = _split_cfg_top_level(s[4:-1])
        return any(a == "test" for a in args)
    if s.startswith("any(") and s.endswith(")"):
        args = _split_cfg_top_level(s[4:-1])
        # any(test) alone is test-only; any(test, feature=…) is not.
        return args == ["test"]
    return False


def strip_test_modules(text: str) -> str:
    """Remove test-only `#[cfg(…)] mod … { … }` blocks (brace-balanced).

    Only strips when the cfg is test-only (see `is_test_only_cfg`). Production
    `#[cfg(not(test))]` and feature cfgs are retained.
    """
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        m = CFG_ATTR_RE.search(lines[i])
        if m and is_test_only_cfg(m.group(1)):
            j = i
            found_mod = False
            while j < n and j < i + 5:
                if MOD_OPEN_RE.search(lines[j]) and "{" in lines[j]:
                    found_mod = True
                    break
                if lines[j].strip() and not lines[j].strip().startswith("#["):
                    break
                j += 1
            if found_mod:
                depth = 0
                started = False
                k = i
                while k < n:
                    for ch in lines[k]:
                        if ch == "{":
                            depth += 1
                            started = True
                        elif ch == "}":
                            depth -= 1
                    k += 1
                    if started and depth == 0:
                        break
                i = k
                continue
        out.append(lines[i])
        i += 1
    return "".join(out)


def collect_command_aliases(text: str) -> set[str]:
    """Names that alias `Command` via `use … as` or `type … = Command`."""
    aliases: set[str] = set()
    for rx in (USE_COMMAND_AS, USE_GROUP_COMMAND_AS, TYPE_COMMAND_ALIAS):
        for m in rx.finditer(text):
            aliases.add(m.group(1))
    return aliases


def is_env_mutation(code: str, aliases: set[str]) -> bool:
    if ENV_METHOD_RE.search(code) or ENV_UFCS_LITERAL_RE.search(code):
        return True
    for alias in aliases:
        if re.search(
            rf"\b{re.escape(alias)}\s*::\s*(?:env|envs|env_clear|env_remove){_TURBO}\s*\(",
            code,
        ):
            return True
    return False


def is_spawn(code: str, aliases: set[str]) -> bool:
    if SPAWN_LITERAL_RE.search(code):
        return True
    for alias in aliases:
        if re.search(rf"\b{re.escape(alias)}\s*::\s*new\s*\(", code):
            return True
    return False


def production_rs_files() -> list[Path]:
    crates = ROOT / "crates"
    files: list[Path] = []
    for path in crates.rglob("*.rs"):
        rel = path.relative_to(ROOT).as_posix()
        if "/tests/" in f"/{rel}":
            continue
        if rel.endswith("/build.rs"):
            continue
        files.append(path)
    return sorted(files)


def discover_markers(paths: list[Path]) -> list[tuple[str, str, int, list[str]]]:
    found = []
    for path in paths:
        rel = path.relative_to(ROOT).as_posix()
        try:
            lines = path.read_text().splitlines()
        except OSError:
            continue
        for i, ln in enumerate(lines):
            m = MARKER_RE.match(ln)
            if m:
                found.append((m.group(1), rel, i, lines))
    return found


def check_callsite_invariant() -> list[tuple[str, str]]:
    """Markers anywhere under production crates must equal the inventory."""
    inv_pairs = {(cid, path) for cid, path, _ in CHILD_ENV_CALLSITES}
    inv_ids = {cid for cid, _, _ in CHILD_ENV_CALLSITES}
    discovered = discover_markers(production_rs_files())
    violations: list[tuple[str, str]] = []

    for cid, path, _, _ in discovered:
        if (cid, path) in inv_pairs:
            continue
        if cid in inv_ids:
            violations.append(
                (path, f"child-env-callsite marker '{cid}' in unexpected file")
            )
        else:
            violations.append(
                (
                    path,
                    f"unrecognized child-env-callsite marker '{cid}' "
                    f"(not in the reviewed inventory)",
                )
            )

    by_key: dict[tuple[str, str], list[tuple[int, list[str]]]] = {}
    for cid, path, idx, lines in discovered:
        by_key.setdefault((cid, path), []).append((idx, lines))

    for cid, path, expected in CHILD_ENV_CALLSITES:
        entries = by_key.get((cid, path), [])
        if len(entries) != 1:
            seen = "missing" if not entries else f"appears {len(entries)} times"
            violations.append(
                (path, f"callsite '{cid}': marker must appear exactly once ({seen})")
            )
            continue
        idx, lines = entries[0]
        j = idx + 1
        while j < len(lines) and lines[j].strip() == "":
            j += 1
        actual = (
            strip_line_comment(lines[j]).strip() if j < len(lines) else "<end of file>"
        )
        if actual != expected:
            violations.append(
                (
                    path,
                    f"callsite '{cid}': command must be exactly "
                    f"'{expected}'; found: {actual}",
                )
            )
    return violations


def scan_text_for_unscoped(text: str, path: str) -> list[tuple[str, str]]:
    """Reject spawn/env mutations outside inventoried marker-next lines."""
    production = strip_test_modules(text)
    aliases = collect_command_aliases(production)
    lines = production.splitlines()
    inv_by_id = {cid: (p, expected) for cid, p, expected in CHILD_ENV_CALLSITES}
    violations: list[tuple[str, str]] = []

    for i, ln in enumerate(lines):
        code = strip_line_comment(ln).strip()
        if not code:
            continue
        kind = None
        if is_spawn(code, aliases):
            kind = "spawn"
        elif is_env_mutation(code, aliases):
            kind = "env mutation"
        else:
            continue

        j = i - 1
        while j >= 0 and lines[j].strip() == "":
            j -= 1
        marker_id = None
        if j >= 0:
            m = MARKER_RE.match(lines[j])
            if m:
                marker_id = m.group(1)
        if marker_id is None:
            violations.append(
                (
                    path,
                    f"unscoped {kind} (no child-env-callsite marker): {code}",
                )
            )
            continue
        if marker_id not in inv_by_id:
            violations.append(
                (path, f"{kind} under unrecognized marker '{marker_id}': {code}")
            )
            continue
        # Kind must match marker class.
        if kind == "spawn" and marker_id not in SPAWN_IDS:
            violations.append(
                (
                    path,
                    f"spawn under env-mutation marker '{marker_id}': {code}",
                )
            )
            continue
        if kind == "env mutation" and marker_id not in ENV_MUTATION_IDS:
            violations.append(
                (
                    path,
                    f"env mutation under spawn marker '{marker_id}': {code}",
                )
            )
            continue
        inv_path, expected = inv_by_id[marker_id]
        if path != inv_path:
            violations.append(
                (
                    path,
                    f"marker '{marker_id}' only permitted in '{inv_path}', found in '{path}'",
                )
            )
            continue
        if code != expected:
            violations.append(
                (
                    path,
                    f"marker '{marker_id}' line mismatch: expected "
                    f"'{expected}', found '{code}'",
                )
            )
    return violations


def scan_file(path: Path) -> list[tuple[str, str]]:
    try:
        text = path.read_text()
    except OSError as e:
        return [(str(path), f"unreadable: {e}")]
    if path.is_absolute() and ROOT in path.parents:
        rel = path.relative_to(ROOT).as_posix()
    else:
        rel = str(path)
    return scan_text_for_unscoped(text, rel)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--scan",
        help="scan a single file (fixture mode for negative controls) and exit",
    )
    args = ap.parse_args()

    violations: list[tuple[str, str]] = []
    if args.scan:
        violations += scan_file(Path(args.scan))
    else:
        violations += check_callsite_invariant()
        for path in production_rs_files():
            violations += scan_file(path)

    if violations:
        note("FAIL: child-env chokepoint inventory violated:")
        for path, detail in violations:
            note(f"  {path}: {detail}")
        return 1
    note("child-env chokepoint inventory holds (spawn + env monopoly) [PASS]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
