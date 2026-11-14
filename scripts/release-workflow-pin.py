#!/usr/bin/env python3
"""Verify that every GitHub Actions workflow and local action matches its
reviewed SHA-256 pin and adheres to the estate read-only provenance posture.

Invariants enforced on every `.github/workflows/*.y*ml`:
1. Exact SHA-256 digest match in `config/release/release-workflow.sha256`
   (lexicographically sorted, two-space separator, trailing newline, no unpinned
   or missing files).
2. Read-only permissions: top-level `permissions: {contents: read}` (no write
   scopes at workflow or job level).
3. Zero release/PR mutation tokens (`softprops/action-gh-release`,
   `peter-evans/create-pull-request`, `gh release`, `/releases`, etc.) in
   `release.yml` or `go-bindings.yml`.
4. Every external `uses:` is pinned to a lowercase 40-hex commit SHA
   (`owner/repo[/path]@<40-hex>`), never a floating tag/branch, and never one of
   the retired Node 20 action SHAs.
5. Every `actions/checkout` step explicitly sets `persist-credentials: false`.
6. Every container `image:` is pinned with an `@sha256:<64-hex>` digest.
7. Every job runner (`runs-on:` or matrix runner value) uses an explicit
   approved runner label (rejecting `*-latest` except the org larger-runner
   slugs `ubuntu-latest-arm64-s` / `windows-latest-arm64-s`, and rejecting
   retired `macos-14`).

Uses a strict fail-closed Python stdlib YAML subset parser so `make ci` works
on developer hosts without third-party Python packages; when PyYAML is
installed (enforced in CI via `SECLUSOR_REQUIRE_PYYAML=1`), cross-checks the
parsed document against `yaml.safe_load`.

Modes:
  check                 verify working tree against config/release/release-workflow.sha256
  verify-commit COMMIT  verify committed tree at COMMIT against COMMIT:config/release/release-workflow.sha256
  write                 compute and write config/release/release-workflow.sha256 after validating invariants
"""

import ast
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

# Keep script directory off sys.path so a stray local file cannot shadow PyYAML.
sys.path = [
    entry
    for entry in sys.path
    if Path(entry or ".").resolve() != Path(__file__).resolve().parent
]
try:
    import yaml as _pyyaml  # type: ignore[import-untyped]
except ImportError:
    _pyyaml = None

PIN_PATH = "config/release/release-workflow.sha256"
PINNED_DIRS = (".github/workflows", ".github/actions")
LINE_RE = re.compile(
    r"^([0-9a-f]{64})  (\.github/(?:workflows|actions)/[A-Za-z0-9._/-]+\.ya?ml)$"
)
EXTERNAL_USES_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@([0-9a-f]{40})$")
LOCAL_ACTION_RE = re.compile(
    r"^\./(\.github/actions/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)$"
)
IMAGE_DIGEST_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
BLOCK_SCALAR_RE = re.compile(r"^[|>][+-]?[0-9]*$")
DENYLISTED_ACTION_SHAS = {
    "11d5960a326750d5838078e36cf38b85af677262",  # actions/checkout@v4.4.0 (Node 20)
    "ea165f8d65b6e75b540449e92b4886f43607fa02",  # actions/upload-artifact@v4.6.2 (Node 20)
    "0057852bfaa89a5674528c7296c29d2fc3983029",  # actions/checkout@v5.0.0 (Node 20)
}
ALLOWED_RUNNER_LABELS = {
    "ubuntu-24.04",
    "ubuntu-latest-arm64-s",
    "macos-15",
    "windows-2025",
    "windows-2022",
    "windows-latest-arm64-s",
}
MUTATION_RE = re.compile(
    r"(?i)softprops/action-gh-release|ncipollo/release-action|"
    r"actions/create-release|actions/upload-release-asset|"
    r"peter-evans/create-pull-request|"
    r"\bgh\s+release\b|\bgh\s+pr\s+create\b|\bgh\s+api\b[^\n]*releases|"
    r"api\.github\.com/repos/[^\s\"']*/releases|\bcreateRelease\b"
)


def fail(reason: str) -> None:
    print(f"error: {reason}", file=sys.stderr)
    sys.exit(1)


def _strip_inline_comment(raw: str) -> str:
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(raw):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            continue
        if ch == "#" and not in_single and not in_double:
            if idx == 0 or raw[idx - 1].isspace():
                return raw[:idx].rstrip()
    if in_single or in_double:
        raise ValueError(f"unterminated quote in {raw!r}")
    return raw.rstrip()


def _split_top_level(inner: str, sep: str) -> list[str]:
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    in_single = False
    in_double = False
    escaped = False
    for ch in inner:
        if escaped:
            cur.append(ch)
            escaped = False
            continue
        if ch == "\\" and in_double:
            cur.append(ch)
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            cur.append(ch)
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            cur.append(ch)
            continue
        if not in_single and not in_double:
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
                if depth < 0:
                    raise ValueError(f"unbalanced flow brackets in {inner!r}")
            elif ch == sep and depth == 0:
                parts.append("".join(cur).strip())
                cur = []
                continue
        cur.append(ch)
    if depth != 0 or in_single or in_double:
        raise ValueError(f"unterminated flow collection in {inner!r}")
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


def _is_single_flow_span(token: str, open_ch: str, close_ch: str) -> bool:
    if len(token) < 2 or token[0] != open_ch or token[-1] != close_ch:
        return False
    depth = 0
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(token):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            continue
        if not in_single and not in_double:
            if ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
                if depth == 0 and idx != len(token) - 1:
                    return False
                if depth < 0:
                    return False
    return depth == 0 and not in_single and not in_double


def _split_key_value(line: str) -> tuple[str, str]:
    if line == "?" or line.startswith("? "):
        raise ValueError(f"complex YAML mapping keys ('?') are disallowed: {line!r}")
    in_single = False
    in_double = False
    escaped = False
    depth = 0
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            continue
        if not in_single and not in_double:
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            elif (
                ch == ":"
                and depth == 0
                and (idx + 1 == len(line) or line[idx + 1].isspace())
            ):
                key_raw = line[:idx].strip()
                val_raw = line[idx + 1 :].strip()
                if key_raw == "<<":
                    raise ValueError("YAML merge keys ('<<') are disallowed")
                key = _parse_scalar(key_raw, allow_yaml11_bool_word=True)
                if not isinstance(key, str) or not key or key == "<<":
                    raise ValueError(f"invalid mapping key {key_raw!r}")
                return key, val_raw
    raise ValueError(f"expected key: value mapping entry, got {line!r}")


def _parse_scalar(token: str, *, allow_yaml11_bool_word: bool = False) -> object:
    if not token:
        return None
    if token[0] in ("&", "*", "!", "%", "@", "`", "|", ">", "?", ",", "]", "}"):
        raise ValueError(f"disallowed or malformed YAML indicator in {token!r}")
    if token.startswith('"'):
        if len(token) < 2 or not token.endswith('"'):
            raise ValueError(f"unterminated double-quoted scalar: {token!r}")
        escaped = False
        for ch in token[1:-1]:
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
                continue
            if ch == '"':
                raise ValueError(f"unescaped interior quote in scalar: {token!r}")
        if escaped:
            raise ValueError(f"trailing backslash in double-quoted scalar: {token!r}")
        return ast.literal_eval(token)
    if token.startswith("'"):
        if len(token) < 2 or not token.endswith("'"):
            raise ValueError(f"unterminated single-quoted scalar: {token!r}")
        body = token[1:-1]
        if "'" in body.replace("''", ""):
            raise ValueError(f"unescaped interior single quote in scalar: {token!r}")
        return body.replace("''", "'")
    if token.startswith("["):
        if not _is_single_flow_span(token, "[", "]"):
            raise ValueError(f"malformed flow sequence: {token!r}")
        inner = token[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(item) for item in _split_top_level(inner, ",")]
    if token.startswith("{"):
        if not _is_single_flow_span(token, "{", "}"):
            raise ValueError(f"malformed flow mapping: {token!r}")
        inner = token[1:-1].strip()
        if not inner:
            return {}
        out: dict[str, object] = {}
        for entry in _split_top_level(inner, ","):
            k, v = _split_key_value(entry)
            if k in out:
                raise ValueError(f"duplicate key {k!r} in flow mapping")
            out[k] = _parse_scalar(v)
        return out
    if ": " in token or token.endswith(":"):
        raise ValueError(f"unquoted colon-mapping syntax in scalar: {token!r}")
    low = token.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("null", "~"):
        return None
    if not allow_yaml11_bool_word and low in ("yes", "no", "on", "off", "y", "n"):
        raise ValueError(
            f"ambiguous YAML 1.1 boolean literal {token!r}; quote string or use true/false"
        )
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", token):
        return int(token)
    if re.fullmatch(r"-?[0-9]+\.[0-9]+", token):
        raise ValueError(f"unquoted float literal {token!r}; quote version strings")
    return token


def _parse_yaml_subset(text: str) -> object:
    raw_lines = text.splitlines()
    for lineno, raw in enumerate(raw_lines, 1):
        leading = raw[: len(raw) - len(raw.lstrip())]
        if "\t" in leading:
            raise ValueError(f"line {lineno}: tab indentation is disallowed")
        stripped = raw.strip()
        if stripped in ("---", "..."):
            raise ValueError(f"line {lineno}: multi-document YAML is disallowed")

    def next_significant(idx: int) -> tuple[int, int, str] | None:
        while idx < len(raw_lines):
            cleaned = _strip_inline_comment(raw_lines[idx])
            if cleaned.strip():
                indent = len(cleaned) - len(cleaned.lstrip(" "))
                return idx, indent, cleaned.lstrip(" ")
            idx += 1
        return None

    def parse_block_scalar(
        start_idx: int, parent_indent: int, style: str
    ) -> tuple[str, int]:
        collected: list[str] = []
        block_indent: int | None = None
        idx = start_idx
        while idx < len(raw_lines):
            raw = raw_lines[idx]
            if not raw.strip():
                collected.append("")
                idx += 1
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            if indent <= parent_indent:
                break
            if block_indent is None:
                block_indent = indent
            elif indent < block_indent:
                break
            collected.append(raw[block_indent:])
            idx += 1
        while collected and collected[-1] == "":
            collected.pop()
        sep = "\n" if style.startswith("|") else " "
        body = sep.join(collected)
        if not style.endswith("-") and body:
            body += "\n"
        return body, idx

    def parse_node(idx: int, min_indent: int) -> tuple[object, int]:
        nxt = next_significant(idx)
        if nxt is None or nxt[1] < min_indent:
            return None, idx
        _, base_indent, content = nxt
        if content == "-" or content.startswith("- "):
            return parse_seq(nxt[0], base_indent)
        return parse_map(nxt[0], base_indent)

    def parse_seq(idx: int, seq_indent: int) -> tuple[list[object], int]:
        items: list[object] = []
        while True:
            nxt = next_significant(idx)
            if nxt is None or nxt[1] < seq_indent:
                break
            line_idx, indent, content = nxt
            if indent != seq_indent:
                raise ValueError(
                    f"line {line_idx + 1}: unexpected sequence indentation"
                )
            if not (content == "-" or content.startswith("- ")):
                break
            rest = content[1:].lstrip(" ")
            if not rest:
                val, idx = parse_node(line_idx + 1, seq_indent + 1)
                items.append(val)
            elif BLOCK_SCALAR_RE.match(rest):
                val, idx = parse_block_scalar(line_idx + 1, seq_indent, rest)
                items.append(val)
            else:
                has_colon = False
                try:
                    k, v = _split_key_value(rest)
                    has_colon = True
                except ValueError:
                    has_colon = False
                if has_colon:
                    entry_indent = seq_indent + 2
                    item_map: dict[str, object] = {}
                    if not v:
                        sub, next_idx = parse_node(line_idx + 1, entry_indent + 1)
                        item_map[k] = sub
                    elif BLOCK_SCALAR_RE.match(v):
                        sub, next_idx = parse_block_scalar(
                            line_idx + 1, entry_indent, v
                        )
                        item_map[k] = sub
                    else:
                        item_map[k] = _parse_scalar(v)
                        next_idx = line_idx + 1
                    idx = parse_map_into(next_idx, entry_indent, item_map)
                    items.append(item_map)
                else:
                    items.append(_parse_scalar(rest))
                    idx = line_idx + 1
        return items, idx

    def parse_map_into(idx: int, map_indent: int, out: dict[str, object]) -> int:
        while True:
            nxt = next_significant(idx)
            if nxt is None or nxt[1] < map_indent:
                break
            line_idx, indent, content = nxt
            if indent != map_indent:
                raise ValueError(f"line {line_idx + 1}: unexpected mapping indentation")
            if content == "-" or content.startswith("- "):
                break
            key, val_raw = _split_key_value(content)
            if key in out:
                raise ValueError(f"line {line_idx + 1}: duplicate mapping key {key!r}")
            if not val_raw:
                child = next_significant(line_idx + 1)
                if (
                    child is not None
                    and child[1] == map_indent
                    and (child[2] == "-" or child[2].startswith("- "))
                ):
                    sub, idx = parse_seq(child[0], map_indent)
                else:
                    sub, idx = parse_node(line_idx + 1, map_indent + 1)
                out[key] = sub
            elif BLOCK_SCALAR_RE.match(val_raw):
                sub, idx = parse_block_scalar(line_idx + 1, map_indent, val_raw)
                out[key] = sub
            else:
                out[key] = _parse_scalar(val_raw)
                idx = line_idx + 1
        return idx

    def parse_map(idx: int, map_indent: int) -> tuple[dict[str, object], int]:
        out: dict[str, object] = {}
        idx = parse_map_into(idx, map_indent, out)
        return out, idx

    doc, end_idx = parse_node(0, 0)
    leftover = next_significant(end_idx)
    if leftover is not None:
        raise ValueError(f"line {leftover[0] + 1}: trailing unparsed YAML content")
    return doc


def _normalize_pyyaml(node: object) -> object:
    if isinstance(node, dict):
        norm: dict[str, object] = {}
        for k, v in node.items():
            if k is True:
                key = "on"
            elif k is False:
                key = "off"
            else:
                key = str(k)
            norm[key] = _normalize_pyyaml(v)
        return norm
    if isinstance(node, list):
        return [_normalize_pyyaml(x) for x in node]
    return node


def load_workflow_yaml(rel: str, content: bytes) -> dict[str, object]:
    if os.environ.get("SECLUSOR_REQUIRE_PYYAML") == "1" and _pyyaml is None:
        fail("PyYAML is required when SECLUSOR_REQUIRE_PYYAML=1")
    try:
        text = content.decode("utf-8")
        doc = _parse_yaml_subset(text)
    except (UnicodeDecodeError, ValueError) as error:
        fail(f"{rel} is not valid UTF-8 workflow YAML: {error}")
    if _pyyaml is not None:
        try:
            py_doc = _normalize_pyyaml(_pyyaml.safe_load(text))
        except Exception as error:  # noqa: BLE001
            fail(f"{rel} rejected by PyYAML: {error}")
        if not isinstance(py_doc, dict) or not isinstance(doc, dict):
            fail(f"{rel} must parse to a YAML mapping")
        if py_doc != doc:
            fail(f"{rel} parsed structure differs between stdlib parser and PyYAML")
        doc = py_doc
    if not isinstance(doc, dict):
        fail(f"{rel} must parse to a YAML mapping")
    return doc


def parse_pins(text: str, source: str) -> dict[str, str]:
    pins: dict[str, str] = {}
    if not text or not text.endswith("\n"):
        fail(f"{source} must be non-empty and end with a newline")
    for raw in text.splitlines():
        match = LINE_RE.match(raw)
        if not match:
            fail(f"malformed line in {source}: {raw!r}")
        digest, path = match.groups()
        if ".." in Path(path).parts or path in pins:
            fail(f"invalid or duplicate workflow path in {source}: {path}")
        pins[path] = digest
    if list(pins) != sorted(pins):
        fail(f"{source} must list workflows in lexicographic order")
    if ".github/workflows/release.yml" not in pins:
        fail(f"{source} must pin .github/workflows/release.yml")
    return pins


def _check_runner_label(rel: str, job_name: str, label: object) -> None:
    if not isinstance(label, str) or label not in ALLOWED_RUNNER_LABELS:
        fail(
            f"{rel} job {job_name} uses unpinned or disallowed runner label {label!r} "
            f"(allowed: {sorted(ALLOWED_RUNNER_LABELS)})"
        )


def _validate_runs_on(rel: str, job_name: str, job: dict[str, object]) -> None:
    runs_on = job.get("runs-on")
    if not isinstance(runs_on, str):
        fail(f"{rel} job {job_name} must declare a string runs-on label")
    if runs_on.startswith("${{") and runs_on.endswith("}}"):
        expr = runs_on[3:-2].strip()
        m = re.fullmatch(r"matrix\.([A-Za-z0-9_-]+)", expr)
        if not m:
            fail(
                f"{rel} job {job_name} uses unsupported dynamic runs-on expression {runs_on!r}"
            )
        key = m.group(1)
        strategy = job.get("strategy")
        matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
        if not isinstance(matrix, dict):
            fail(f"{rel} job {job_name} references {runs_on} without strategy.matrix")
        values: list[object] = []
        if key in matrix and isinstance(matrix[key], list):
            values.extend(matrix[key])
        include = matrix.get("include")
        if isinstance(include, list):
            for entry in include:
                if isinstance(entry, dict) and key in entry:
                    values.append(entry[key])
        if not values:
            fail(f"{rel} job {job_name} matrix defines no values for {key!r}")
        for val in values:
            _check_runner_label(rel, job_name, val)
    else:
        _check_runner_label(rel, job_name, runs_on)


def _validate_steps(
    rel: str, scope: str, steps: object, available_files: set[str]
) -> None:
    if not isinstance(steps, list) or not steps:
        fail(f"{rel} {scope} must declare a non-empty steps list")
    for idx, step in enumerate(steps):
        if not isinstance(step, dict):
            fail(f"{rel} {scope} step #{idx + 1} must be a mapping")
        uses = step.get("uses")
        if uses is None:
            continue
        if not isinstance(uses, str):
            fail(f"{rel} {scope} step #{idx + 1} uses must be a string")
        if uses.startswith(".") or uses.startswith("/"):
            m_local = LOCAL_ACTION_RE.match(uses)
            if not m_local:
                fail(
                    f"{rel} {scope} step uses local action outside ./.github/actions/: {uses!r}"
                )
            action_dir = m_local.group(1)
            if (
                f"{action_dir}/action.yml" not in available_files
                and f"{action_dir}/action.yaml" not in available_files
            ):
                fail(
                    f"{rel} {scope} step references local action {uses!r} with no pinned action.yml/action.yaml"
                )
            continue
        m = EXTERNAL_USES_RE.match(uses)
        if not m:
            fail(
                f"{rel} {scope} step uses unpinned external action {uses!r} "
                f"(40-hex commit SHA required)"
            )
        sha = m.group(1)
        if sha in DENYLISTED_ACTION_SHAS:
            fail(f"{rel} {scope} step uses retired Node 20 action SHA {uses!r}")
        if uses.startswith("actions/checkout@"):
            with_block = step.get("with")
            if (
                not isinstance(with_block, dict)
                or with_block.get("persist-credentials") is not False
            ):
                fail(
                    f"{rel} {scope} actions/checkout step must set persist-credentials: false"
                )


def validate_file_policy(rel: str, content: bytes, available_files: set[str]) -> None:
    doc = load_workflow_yaml(rel, content)
    text = content.decode("utf-8")

    if rel.startswith(".github/actions/"):
        if not rel.endswith(("/action.yml", "/action.yaml")):
            fail(
                f"{rel} under .github/actions/ must be named action.yml or action.yaml"
            )
        runs = doc.get("runs")
        if not isinstance(runs, dict):
            fail(f"{rel} local action must declare a runs mapping")
        using = runs.get("using")
        if using == "composite":
            _validate_steps(rel, "composite action", runs.get("steps"), available_files)
        elif using == "docker":
            image = runs.get("image")
            if not isinstance(image, str) or not IMAGE_DIGEST_RE.match(image):
                fail(
                    f"{rel} docker local action image must carry an @sha256: digest: {image!r}"
                )
        else:
            fail(
                f"{rel} local action uses disallowed or unpinned runtime {using!r} "
                "(only composite or @sha256:-pinned docker actions are permitted)"
            )
        return

    permissions = doc.get("permissions")
    if (
        not isinstance(permissions, dict)
        or permissions.get("contents") != "read"
        or any(level != "read" for level in permissions.values())
    ):
        fail(
            f"{rel} must declare read-only top-level permissions including contents: read"
        )

    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        fail(f"{rel} must declare jobs")

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            fail(f"{rel} job {job_name} must be a mapping")
        job_permissions = job.get("permissions")
        if job_permissions is not None:
            if not isinstance(job_permissions, dict) or any(
                v not in ("read", "none") for v in job_permissions.values()
            ):
                fail(f"{rel} job {job_name} grants more than read permissions")
        _validate_runs_on(rel, job_name, job)
        container = job.get("container")
        if container is not None:
            image = container.get("image") if isinstance(container, dict) else container
            if not isinstance(image, str) or not IMAGE_DIGEST_RE.match(image):
                fail(
                    f"{rel} job {job_name} container image must carry an @sha256: digest: {image!r}"
                )
        services = job.get("services")
        if services is not None:
            if not isinstance(services, dict):
                fail(f"{rel} job {job_name} services must be a mapping")
            for svc_name, svc in services.items():
                svc_image = svc.get("image") if isinstance(svc, dict) else svc
                if not isinstance(svc_image, str) or not IMAGE_DIGEST_RE.match(
                    svc_image
                ):
                    fail(
                        f"{rel} job {job_name} service {svc_name} image must carry an @sha256: digest: {svc_image!r}"
                    )
        _validate_steps(rel, f"job {job_name}", job.get("steps"), available_files)

    if rel in (
        ".github/workflows/release.yml",
        ".github/workflows/go-bindings.yml",
    ) and MUTATION_RE.search(text):
        fail(f"{rel} contains a disallowed release or pull-request mutation token")


def collect_working_tree_files(root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for directory in PINNED_DIRS:
        base = root / directory
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_symlink():
                fail(f"symlink under {directory} is not allowed: {path}")
            if path.is_file():
                if path.suffix not in (".yml", ".yaml"):
                    fail(
                        f"non-YAML file under {directory} is not allowed: {path.relative_to(root).as_posix()}"
                    )
                files[path.relative_to(root).as_posix()] = path.read_bytes()
    return files


def verify(pins: dict[str, str], files: dict[str, bytes], label: str) -> None:
    available_files = set(files)
    for rel in sorted(set(pins) | set(files)):
        if rel not in pins:
            fail(f"{rel} is not pinned in {PIN_PATH}")
        if rel not in files:
            fail(f"pinned {rel} is missing from {label}")
        actual = hashlib.sha256(files[rel]).hexdigest()
        if actual != pins[rel]:
            fail(f"workflow/action in {label} differs from its reviewed digest: {rel}")
        validate_file_policy(rel, files[rel], available_files)


def check_working_tree(root: Path) -> None:
    pin_file = root / PIN_PATH
    if not pin_file.is_file() or pin_file.is_symlink():
        fail(f"{PIN_PATH} is missing")
    pins = parse_pins(pin_file.read_text(encoding="utf-8"), PIN_PATH)
    files = collect_working_tree_files(root)
    verify(pins, files, "the working tree")
    print(f"[ok] {len(pins)} pinned workflow/action file(s) verified and policy-clean")


def write_working_tree_pins(root: Path) -> None:
    files = collect_working_tree_files(root)
    if ".github/workflows/release.yml" not in files:
        fail(".github/workflows/release.yml is missing")
    available_files = set(files)
    for rel in sorted(files):
        validate_file_policy(rel, files[rel], available_files)
    lines = [
        f"{hashlib.sha256(files[rel]).hexdigest()}  {rel}\n" for rel in sorted(files)
    ]
    pin_file = root / PIN_PATH
    pin_file.parent.mkdir(parents=True, exist_ok=True)
    pin_file.write_text("".join(lines), encoding="utf-8")
    check_working_tree(root)


def git_bytes(root: Path, args: list[str]) -> bytes:
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, check=False)
    if result.returncode != 0:
        fail(result.stderr.decode("utf-8", errors="replace").strip() or "git failed")
    return result.stdout


def verify_commit(root: Path, commit: str) -> None:
    if not re.match(r"^[0-9a-f]{40}$", commit):
        commit = (
            git_bytes(root, ["rev-parse", "--verify", f"{commit}^{{commit}}"])
            .decode("utf-8")
            .strip()
        )
    pin_entry = (
        git_bytes(root, ["ls-tree", commit, "--", PIN_PATH])
        .decode("utf-8")
        .splitlines()
    )
    if len(pin_entry) != 1 or pin_entry[0].split()[0] != "100644":
        fail(f"committed {PIN_PATH} is required in the tagged commit")
    pins = parse_pins(
        git_bytes(root, ["cat-file", "blob", f"{commit}:{PIN_PATH}"]).decode("utf-8"),
        f"{commit}:{PIN_PATH}",
    )
    tree = (
        git_bytes(root, ["ls-tree", "-r", commit, "--", *PINNED_DIRS])
        .decode("utf-8")
        .splitlines()
    )
    files: dict[str, bytes] = {}
    for line in tree:
        meta, rel = line.split("\t", 1)
        mode, kind, _ = meta.split()
        if mode not in ("100644", "100755") or kind != "blob":
            fail(f"non-regular file under .github in {commit}: {rel}")
        if rel.endswith((".yml", ".yaml")):
            files[rel] = git_bytes(root, ["cat-file", "blob", f"{commit}:{rel}"])
        else:
            fail(f"non-YAML file under .github in {commit}: {rel}")
    verify(pins, files, "the tagged commit")


def main() -> None:
    root = Path.cwd()
    args = sys.argv[1:]
    if args == ["check"]:
        check_working_tree(root)
    elif args == ["write"]:
        write_working_tree_pins(root)
    elif len(args) == 2 and args[0] == "verify-commit":
        verify_commit(root, args[1])
    else:
        fail("usage: release-workflow-pin.py <check|write|verify-commit COMMIT>")


if __name__ == "__main__":
    main()
