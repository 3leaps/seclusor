#!/usr/bin/env python3
"""Static guard (EPR-0001 §2): every published-artifact build is proven to route
through the canonical --locked entrypoint.

The load-bearing proof is a CLOSED POSITIVE INVARIANT, not an open denylist. Each
known artifact-producing callsite — the release CLI build, every go-bindings FFI
build, and the Makefile artifact targets — carries a stable `# artifact-callsite:
<id>` marker (exact comment grammar) directly above its command, and the inventory
records that command verbatim. This guard asserts, per inventoried id, that the
marker appears EXACTLY once and the command it introduces EQUALS the inventoried
`./scripts/cargo-artifact-build.sh …` line (leading indent + trailing comment
removed). Because it is an invocation invariant rather than a token search, the
wrapper token used as data (`echo …`), a same-basename wrong path
(`./evil/cargo-artifact-build.sh`), the token passed as an argument to another
builder, and a second chained command (`… && bash other`) all fail and name the
callsite. Discovered markers must EQUAL the inventory, so an unknown id or an id in
the wrong file fails closed. The TS native `.node` build is proven separately via its
own tracked `--locked` invocation, and the wrapper itself is checked to still inject
`--locked`.

A raw `cargo [+toolchain] build|zigbuild --release` denylist scan runs over the
workflow/Makefile files as DEFENSE-IN-DEPTH (comments stripped, backslash
continuations joined, YAML folded block scalars folded, `+toolchain` recognized) —
it catches a raw unlocked build that skips the wrapper, but it is NOT the proof that
every known callsite uses the wrapper; the closed inventory is. `--scan <file>`
exercises only this denylist scan against an arbitrary fixture.

Exit 1 on any violation; 0 when every inventoried callsite routes through the wrapper
and no raw bypass is present.
"""

import argparse
import re
import sys

DEFAULT_FILES = [
    ".github/workflows/ci.yml",
    ".github/workflows/release.yml",
    ".github/workflows/go-bindings.yml",
    "Makefile",
]
WRAPPER = "scripts/cargo-artifact-build.sh"
NATIVE_BUILD = "bindings/typescript/scripts/build-native.js"

# --- closed positive callsite invariant (the load-bearing AC-2 proof) ---
# An explicit inventory of EVERY artifact-producing callsite, each pinned to a stable
# marker AND its exact canonical command. The proof is an INVOCATION invariant, not a
# token search: the marker must occur exactly once, and the command it introduces
# must equal the inventoried `./scripts/cargo-artifact-build.sh …` line verbatim —
# so the wrapper token as data (`echo …`), a same-basename wrong path
# (`./evil/cargo-artifact-build.sh`), the token as an argument to another builder, or
# a second chained command (`… && bash other`) all fail. Discovered markers must also
# EQUAL this inventory, so an unknown id or an id in the wrong file fails closed.
# Changing a callsite requires a reviewed edit here. TS native is intentionally absent
# (separate direct `--locked` assertion + runtime stale-lock control, not the wrapper).
#
# Each entry: (id, file, exact canonical command as it appears lstripped, comment-free).
ARTIFACT_CALLSITES = [
    (
        "release-cli",
        ".github/workflows/release.yml",
        './scripts/cargo-artifact-build.sh build --target "${{ matrix.target }}" -p seclusor',
    ),
    (
        "gobindings-ffi-linux",
        ".github/workflows/go-bindings.yml",
        './scripts/cargo-artifact-build.sh zigbuild --target "${{ matrix.target }}.${{ matrix.glibc }}" -p seclusor-ffi',
    ),
    (
        "gobindings-ffi-darwin-amd64",
        ".github/workflows/go-bindings.yml",
        "./scripts/cargo-artifact-build.sh build --target x86_64-apple-darwin -p seclusor-ffi",
    ),
    (
        "gobindings-ffi-darwin-arm64",
        ".github/workflows/go-bindings.yml",
        "./scripts/cargo-artifact-build.sh build --target aarch64-apple-darwin -p seclusor-ffi",
    ),
    (
        "gobindings-ffi-windows-gnu",
        ".github/workflows/go-bindings.yml",
        "./scripts/cargo-artifact-build.sh build --target x86_64-pc-windows-gnu -p seclusor-ffi",
    ),
    (
        "make-build-release",
        "Makefile",
        "./scripts/cargo-artifact-build.sh build --workspace",
    ),
    (
        "make-build-ffi",
        "Makefile",
        "./scripts/cargo-artifact-build.sh build -p seclusor-ffi",
    ),
]

# A callsite marker is EXACTLY a comment line `# artifact-callsite: <id>` (leading
# indentation permitted). Constraining it to comment grammar means executable text
# ending in the marker string cannot masquerade as structure.
CALLSITE_MARKER_RE = re.compile(r"^\s*#\s*artifact-callsite:\s*(\S+)\s*$")

# Raw `cargo [+toolchain] build|zigbuild` — NOT `cargo-artifact-build.sh` (no
# whitespace after 'cargo' there), and not a substring of another word. The optional
# `+toolchain` selector (e.g. `cargo +stable build`) is recognized so it cannot slip
# a raw build past the guard.
RAW_CARGO = re.compile(r"(?<![\w./-])cargo\s+(?:\+[\w.\-]+\s+)?(?:build|zigbuild)\b")

# A YAML folded block scalar header: `run: >`, `- run: >-`, `run: >2`, etc. The
# runner folds the indented body into ONE shell command (newlines -> spaces), so the
# guard must too — otherwise `run: >` splits a real `cargo build ... --release`
# across physical lines and the per-line scan misses it. A blank line inside the
# block is a paragraph break (a real newline / command separator) and is preserved.
FOLDED_HEADER = re.compile(r"^(\s*)(?:-\s+)?[\w.-]+\s*:\s*>[+\-0-9]*\s*(?:#.*)?$")


def strip_comment(line):
    # No '#' appears inside our cargo commands, so a first-'#' cut is sufficient and
    # ensures a commented-out --locked cannot satisfy the assertion.
    h = line.find("#")
    return line if h < 0 else line[:h]


def fold_folded_scalars(text):
    """Collapse each YAML folded block scalar onto its header line, joining the
    indented body with spaces the way the runner does. Blank lines split the body
    into separate logical commands so an unlocked build cannot hide behind a stray
    `--locked` in a later paragraph of the same block."""
    lines = text.splitlines()
    out, i, n = [], 0, len(lines)
    while i < n:
        m = FOLDED_HEADER.match(lines[i])
        if not m:
            out.append(lines[i])
            i += 1
            continue
        key_indent = len(m.group(1))
        prefix = lines[i][: lines[i].rindex(">")]
        i += 1
        segments, current = [], []
        while i < n:
            ln = lines[i]
            if ln.strip() == "":  # paragraph break -> newline (command separator)
                if current:
                    segments.append(" ".join(current))
                    current = []
                i += 1
                continue
            if len(ln) - len(ln.lstrip()) <= key_indent:
                break  # dedent to <= the header ends the block scalar
            current.append(ln.strip())
            i += 1
        if current:
            segments.append(" ".join(current))
        out.append(prefix + (segments[0] if segments else ""))
        out.extend(segments[1:])
    return "\n".join(out)


def logical_lines(text):
    folded = fold_folded_scalars(text)
    stripped = "\n".join(strip_comment(ln) for ln in folded.splitlines())
    joined = re.sub(r"\\\s*\n\s*", " ", stripped)  # join backslash-continuations
    return joined.splitlines()


def scan_text(text, path="<input>"):
    violations = []
    for line in logical_lines(text):
        if RAW_CARGO.search(line) and "--release" in line and "--locked" not in line:
            violations.append((path, line.strip()))
    return violations


def scan_file(path):
    try:
        with open(path) as f:
            return scan_text(f.read(), path)
    except FileNotFoundError:
        return []


def _discover_markers(paths):
    """Every `# artifact-callsite: <id>` marker across the governed files, as a list
    of (id, path, line-index). Used both to reconcile against the inventory and to
    locate each callsite's command."""
    found, cache = [], {}
    for path in paths:
        if path not in cache:
            try:
                cache[path] = open(path).read().splitlines()
            except FileNotFoundError:
                cache[path] = None
        lines = cache[path]
        if lines is None:
            continue
        for i, ln in enumerate(lines):
            m = CALLSITE_MARKER_RE.match(ln)
            if m:
                found.append((m.group(1), path, i))
    return found, cache


def check_callsite_invariant():
    """Prove every inventoried artifact callsite invokes the canonical wrapper, and
    that the set of markers in the repo is exactly the reviewed inventory.

    For each id: its marker occurs exactly once, and the first non-blank line after it
    equals the inventoried canonical command verbatim (leading indentation and a
    trailing shell comment removed) — an INVOCATION invariant, so a wrapper token used
    as data, a same-basename wrong path, the token as an argument to another builder,
    or a second chained command all fail. Any discovered marker whose (id, file) is
    not in the inventory fails closed, so an unknown id or an id in the wrong file is
    rejected rather than silently ignored."""
    inv_pairs = {(cid, path) for cid, path, _ in ARTIFACT_CALLSITES}
    inv_ids = {cid for cid, _, _ in ARTIFACT_CALLSITES}
    governed = sorted({path for _, path, _ in ARTIFACT_CALLSITES} | set(DEFAULT_FILES))

    violations = []
    discovered, cache = _discover_markers(governed)

    # (a) discovered markers must equal the inventory — no unknown ids, none misplaced.
    for cid, path, _ in discovered:
        if (cid, path) in inv_pairs:
            continue
        if cid in inv_ids:
            violations.append(
                (
                    path,
                    f"artifact-callsite marker '{cid}' appears in an unexpected file",
                )
            )
        else:
            violations.append(
                (
                    path,
                    f"unrecognized artifact-callsite marker '{cid}' "
                    f"(not in the reviewed inventory)",
                )
            )

    # (b) per callsite: marker exactly once, next command exactly the canonical line.
    for cid, path, expected in ARTIFACT_CALLSITES:
        lines = cache.get(path)
        if lines is None:
            violations.append((path, f"callsite '{cid}': file missing"))
            continue
        idxs = [i for c, p, i in discovered if c == cid and p == path]
        if len(idxs) != 1:
            seen = "missing" if not idxs else f"appears {len(idxs)} times"
            violations.append(
                (path, f"callsite '{cid}': marker must appear exactly once ({seen})")
            )
            continue
        j = idxs[0] + 1
        while j < len(lines) and lines[j].strip() == "":
            j += 1
        actual = strip_comment(lines[j]).strip() if j < len(lines) else "<end of file>"
        if actual != expected:
            violations.append(
                (
                    path,
                    f"callsite '{cid}': command must be exactly "
                    f"'{expected}'; found: {actual}",
                )
            )
    return violations


def note(msg):
    print(f"[locked-guard] {msg}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scan", help="scan a single file (fixture mode) and exit")
    args = ap.parse_args()

    violations = []
    if args.scan:
        # Fixture mode: exercise only the defense-in-depth raw-command scan.
        violations += scan_file(args.scan)
    else:
        # Primary proof: the closed positive callsite invariant.
        violations += check_callsite_invariant()
        # Defense-in-depth: raw unlocked `cargo build --release` that skips the
        # wrapper anywhere in the scanned files.
        for path in DEFAULT_FILES:
            violations += scan_file(path)
        # The canonical wrapper must inject --locked.
        try:
            if "--locked" not in open(WRAPPER).read():
                violations.append((WRAPPER, "wrapper no longer injects --locked"))
        except FileNotFoundError:
            violations.append((WRAPPER, "canonical wrapper missing"))
        # The TS native build is a separate direct path; it must enforce --locked.
        try:
            if '"--locked"' not in open(NATIVE_BUILD).read():
                violations.append((NATIVE_BUILD, "cargo build missing --locked"))
        except FileNotFoundError:
            violations.append((NATIVE_BUILD, "native build script missing"))

    if violations:
        note("FAIL: published-artifact build path(s) not proven --locked:")
        for path, detail in violations:
            note(f"  {path}: {detail}")
        return 1
    note("every artifact callsite routes through the canonical --locked wrapper [PASS]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
