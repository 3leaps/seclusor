#!/usr/bin/env python3
"""Cross-surface dependency-graph parity check (SC-TASK-006 AC-4).

Implements crucible EPR-0001 §4 (parity) + EPR-0002 §1/§2/§3/§4, split into two
declared policies over the crypto-roots closure of each build surface:

  * SECURITY gate (EPR-0001 §4) — the declared security-critical crypto set
    (`[crypto_components]`) must resolve to an identical upstream identity across
    every surface it is scoped to. A divergence (version/source/checksum) or a
    component missing from a scoped surface FAILS (exit 2).
  * SHARED-GRAPH LOCKSTEP policy (repo hygiene, kept separate so a utility drift
    never reads as a security alarm) — the declared shared utilities
    (`[non_crypto_shared]`) must also match across their scoped surfaces; a drift
    here FAILS the lockstep policy (exit 4), not the security gate.

Fail-closed, reconciled BOTH ways and BOTH dimensions:
  * component set — a crypto-closure node neither declared nor under a declared
    out-of-scope root REFUSES; a declared component absent from a scoped surface
    FAILS.
  * component SURFACE scope — the surfaces a component is actually derived on must
    equal its declared `surfaces`: a surface reached but not declared REFUSES (a
    silent coverage shrink); a surface declared but not reached FAILS.
  * roots — a root absent from a scoped surface FAILS; a root present on a surface
    the manifest does not scope for it REFUSES (the D11B self-enforcement).

Identity is the full `(name, version, source, checksum)` tuple (EPR-0002 §1):
a declared component whose source or checksum differs on a surface FAILS; two
packages sharing name+version but different sources coexisting in one lock make its
edges ambiguous and REFUSE; a dependency edge that resolves to no present node
REFUSES (never a silent drop) unless it maps to the exact declared `(name, version)`
scoped to that surface, whose absence reconciliation already FAILs — a name-only
match is never sufficient, so a dangling edge to an undeclared version of a declared
name still REFUSEs.

Reads Cargo.lock TOML directly (stdlib tomllib) — no build, no network, no secret
material. Output is lock metadata only.

Exit codes: 0 ok · 2 crypto FAIL · 3 REFUSE · 4 lockstep(util) FAIL.
"""

import argparse
import sys
import tomllib

EXIT_OK = 0
EXIT_FAIL_CRYPTO = 2
EXIT_REFUSE = 3
EXIT_FAIL_UTIL = 4

# Anti-fail-open guard (entarch AC-F1c): these MUST be declared crypto, never
# demoted to the utility list. secrev signs off the full crypto/util boundary; this
# fixed floor prevents a regen/edit from silently parking a primitive as a utility.
CORE_CRYPTO = frozenset(
    {
        "age",
        "x25519-dalek",
        "curve25519-dalek",
        "ed25519-dalek",
        "ed25519",
        "chacha20poly1305",
        "aead",
        "sha2",
        "digest",
        "hmac",
        "hkdf",
        "scrypt",
        "pbkdf2",
        "crypto-common",
        "block-buffer",
        "zeroize",
        "subtle",
        "secrecy",
        "signature",
        "rand_core",
        "rand",
        "rand_chacha",
        "getrandom",
    }
)

# Seed classifier used ONLY by --regen to split the derived closure into the two
# declared buckets. The committed manifest is the reviewed artifact (secrev owns
# the boundary and may move entries); the check never consults this set.
_CRYPTO_SEED = CORE_CRYPTO | frozenset(
    {
        "age-core",
        "salsa20",
        "poly1305",
        "chacha20",
        "cipher",
        "universal-hash",
        "inout",
        "opaque-debug",
        "cpufeatures",
        "generic-array",
        "typenum",
        "ppv-lite86",
        "fiat-crypto",
        "curve25519-dalek-derive",
        "zeroize_derive",
        "cookie-factory",
        "base64",
        "bech32",
    }
)


# --------------------------------------------------------------------------- lock


def load_lock(path):
    """Return (nodes, by_nv, by_name).

    nodes:   {(name, version, source): {"checksum", "deps"}}  — full-identity keyed
    by_nv:   {(name, version): [source, ...]}                 — collision detection
    by_name: {name: [(version, source), ...]}
    """
    with open(path, "rb") as f:
        lock = tomllib.load(f)
    nodes, by_nv, by_name = {}, {}, {}
    for pkg in lock.get("package", []):
        src = pkg.get("source")
        key = (pkg["name"], pkg["version"], src)
        nodes[key] = {
            "checksum": pkg.get("checksum"),
            "deps": pkg.get("dependencies", []),
        }
        by_nv.setdefault((pkg["name"], pkg["version"]), []).append(src)
        by_name.setdefault(pkg["name"], []).append((pkg["version"], src))
    return nodes, by_nv, by_name


def parse_edge(edge):
    """A Cargo.lock dependency edge: 'name', 'name version', or
    'name version (source)'."""
    parts = edge.split(" ", 2)
    name = parts[0]
    version = parts[1] if len(parts) >= 2 else None
    source = None
    if len(parts) >= 3:
        s = parts[2].strip()
        source = s[1:-1] if s.startswith("(") and s.endswith(")") else s
    return name, version, source


AMBIGUOUS = object()  # edge cannot be pinned to one node
UNRESOLVED = object()  # edge points to a node not present in this lock


def resolve(edge, by_nv, by_name):
    """Resolve an edge to a full node key (name, version, source), or a sentinel.

    UNRESOLVED — the target is absent from this lock (dangling edge).
    AMBIGUOUS  — name/name+version matches multiple nodes; cannot select one."""
    name, version, source = parse_edge(edge)
    if source is not None:
        return (name, version, source)  # fully qualified; presence checked by caller
    if version is not None:
        srcs = by_nv.get((name, version))
        if not srcs:
            return UNRESOLVED
        if len(srcs) == 1:
            return (name, version, srcs[0])
        return (
            AMBIGUOUS  # same name+version, multiple sources — needs a source qualifier
        )
    entries = by_name.get(name)
    if not entries:
        return UNRESOLVED
    if len(entries) == 1:
        v, s = entries[0]
        return (name, v, s)
    return AMBIGUOUS  # bare edge, multiple versions — cannot pin


def closure(nodes, by_nv, by_name, roots, stop_names, exempt_nv, exempt_bare):
    """Full-identity closure. Returns (visited_keys, refusals).

    Nodes whose name is in stop_names are included but not expanded (the exemption
    boundary). An ambiguous edge REFUSES. An unresolvable (dangling) edge REFUSES
    *unless* it maps unambiguously to a declared identity whose absence on THIS
    surface reconciliation will already FAIL — never merely because the target name
    is declared. Reconciliation is keyed by (name, version), so the delegation
    boundary must be too:

      * a versioned edge is exempt only when its exact (name, version) is
        declared-and-scoped on this surface (`exempt_nv`);
      * a bare-name edge is exempt only when exactly one declared identity is scoped
        on this surface (`exempt_bare`) — otherwise the absence it would delegate to
        is ambiguous.

    Anything else REFUSES, so a dangling edge to an *undeclared version of a declared
    name* (e.g. a new `zeroize 9.9.9` alongside a valid `zeroize 1.9.0`) can never be
    silently swallowed."""
    seen, refusals, stack = set(), [], list(roots)
    while stack:
        key = stack.pop()
        if key in seen:
            continue
        seen.add(key)
        if key not in nodes or key[0] in stop_names:
            continue
        for edge in nodes[key]["deps"]:
            rid = resolve(edge, by_nv, by_name)
            if rid is AMBIGUOUS:
                refusals.append(f"ambiguous edge '{edge}' from {key[0]} {key[1]}")
            elif rid is UNRESOLVED:
                ename, eversion, _ = parse_edge(edge)
                exempt = (
                    (ename, eversion) in exempt_nv
                    if eversion is not None
                    else ename in exempt_bare
                )
                if not exempt:
                    refusals.append(
                        f"unresolvable edge '{edge}' from {key[0]} {key[1]} "
                        f"(target absent from lock)"
                    )
            else:
                stack.append(rid)
    return seen, refusals


def root_keys(by_name, names):
    out = []
    for n in names:
        for version, source in by_name.get(n, []):
            out.append((n, version, source))
    return out


# ----------------------------------------------------------------------- manifest


def load_manifest(path):
    with open(path, "rb") as f:
        man = tomllib.load(f)

    def index(entries):
        # Keyed by (name, version); source+checksum are asserted attributes so a
        # cross-surface source/checksum divergence is a FAIL, not an undeclared node.
        by_nv, names = {}, set()
        for e in entries:
            by_nv[(e["name"], e["version"])] = {
                "source": e.get("source"),
                "checksum": e.get("checksum"),
                "surfaces": e.get("surfaces", []),
            }
            names.add(e["name"])
        return by_nv, names

    crypto, crypto_names = index(man.get("crypto_components", []))
    util, util_names = index(man.get("non_crypto_shared", []))
    return {
        "surfaces": man["surfaces"],
        "roots": man["roots"],
        "oos": set(man.get("out_of_scope_roots", {}).keys()),
        "anchor": man.get("anchor", "root"),
        "crypto": crypto,
        "crypto_names": crypto_names,
        "util": util,
        "util_names": util_names,
    }


def scoped_roots(roots, surface):
    return [r for r, surfs in roots.items() if surface in surfs]


def surface_exemptions(man, surface):
    """(exempt_nv, exempt_bare) for one surface — the declared identities whose
    absence here reconciliation will already FAIL, so a dangling edge to them need
    not also REFUSE. A versioned edge may delegate only to the exact declared
    (name, version) scoped to this surface; a bare-name edge only when exactly one
    declared identity is scoped here (else the delegation target is ambiguous)."""
    exempt_nv, per_name = set(), {}
    for decl in (man["crypto"], man["util"]):
        for (name, version), meta in decl.items():
            if surface in meta.get("surfaces", []):
                exempt_nv.add((name, version))
                per_name[name] = per_name.get(name, 0) + 1
    exempt_bare = {name for name, count in per_name.items() if count == 1}
    return exempt_nv, exempt_bare


def in_scope(nodes, by_nv, by_name, roots, oos, surface):
    # Regen path: refusals are advisory here (the committed manifest is the reviewed
    # artifact); the load-bearing exemption logic runs in check(). Pass no exemptions.
    keys = root_keys(by_name, scoped_roots(roots, surface))
    reached, refusals = closure(
        nodes, by_nv, by_name, keys, oos, frozenset(), frozenset()
    )
    return {k for k in reached if k[0] not in oos}, refusals


# --------------------------------------------------------------------------- regen


def derive(man):
    per_surface = {}
    for sname, path in man["surfaces"].items():
        nodes, by_nv, by_name = load_lock(path)
        scoped, _ = in_scope(
            nodes,
            by_nv,
            by_name,
            man["roots"],
            man["oos"],
            sname,
        )
        per_surface[sname] = {"nodes": nodes, "scoped": scoped}
    return per_surface


def render_entries(keys, per_surface):
    lines = []
    for name, version, source in sorted(keys):
        key = (name, version, source)
        surfs = sorted(s for s, d in per_surface.items() if key in d["scoped"])
        checksum = next(
            (
                d["nodes"][key]["checksum"]
                for d in per_surface.values()
                if key in d["nodes"]
            ),
            None,
        )
        lines.append("[[__TABLE__]]")
        lines.append(f'name = "{name}"')
        lines.append(f'version = "{version}"')
        if source is not None:
            lines.append(f'source = "{source}"')
        if checksum is not None:
            lines.append(f'checksum = "{checksum}"')
        lines.append("surfaces = [" + ", ".join(f'"{s}"' for s in surfs) + "]")
        lines.append("")
    return "\n".join(lines)


def regen(man, manifest_path):
    per_surface = derive(man)
    allkeys = set()
    for d in per_surface.values():
        allkeys |= d["scoped"]
    crypto_keys = {k for k in allkeys if k[0] in _CRYPTO_SEED}
    util_keys = allkeys - crypto_keys

    text = open(manifest_path).read()
    marker = "# === GENERATED BELOW (make parity-manifest-regen) ==="
    head = text.split(marker)[0]
    body = (
        marker
        + "\n\n"
        + render_entries(crypto_keys, per_surface).replace(
            "__TABLE__", "crypto_components"
        )
        + "\n"
        + render_entries(util_keys, per_surface).replace(
            "__TABLE__", "non_crypto_shared"
        )
    )
    open(manifest_path, "w").write(head + body)
    print(
        f"[ok] regenerated {len(crypto_keys)} crypto + {len(util_keys)} shared-util components"
    )
    return EXIT_OK


# ---------------------------------------------------------------------------- check


def _surface_ok(surfaces, known):
    return (
        surfaces
        and len(surfaces) == len(set(surfaces))
        and all(s in known for s in surfaces)
    )


def check(man):
    refuse, crypto_fail, util_fail = [], [], []
    locks = {s: load_lock(p) for s, p in man["surfaces"].items()}
    roots, oos, known = man["roots"], man["oos"], set(man["surfaces"])

    # Per-surface crypto closure (+ edge refusals), and the derived surface set of
    # every reached component (name, version) for the two-dimensional reconciliation.
    scoped_by_surface = {}
    derived_surfaces = {}  # (name, version) -> set of surfaces it is derived on
    for sname, (nodes, by_nv, by_name) in locks.items():
        exempt_nv, exempt_bare = surface_exemptions(man, sname)
        keys = root_keys(by_name, scoped_roots(roots, sname))
        reached, refusals = closure(
            nodes, by_nv, by_name, keys, oos, exempt_nv, exempt_bare
        )
        for r in refusals:
            refuse.append(f"[{sname}] {r}")
        oos_closure, _ = closure(
            nodes,
            by_nv,
            by_name,
            root_keys(by_name, oos),
            frozenset(),
            frozenset(),
            frozenset(),
        )
        scoped = {k for k in reached if k[0] not in oos}
        scoped_by_surface[sname] = scoped
        for key in scoped:
            nv = (key[0], key[1])
            derived_surfaces.setdefault(nv, set()).add(sname)
            decl = man["crypto"].get(nv) or man["util"].get(nv)
            if decl is not None:
                if sname not in decl["surfaces"]:
                    refuse.append(
                        f"[{sname}] {key[0]} {key[1]} is derived here but this surface is "
                        f"not in its declared scope — coverage silently shrank"
                    )
            elif key in oos_closure:
                continue
            else:
                refuse.append(
                    f"[{sname}] undeclared crypto-closure node {key[0]} {key[1]} ({key[2]})"
                )

    # Declaration -> presence/identity/scope reconciliation, per policy.
    def reconcile(declared, sink, policy):
        for (name, version), meta in declared.items():
            if not _surface_ok(meta["surfaces"], known):
                refuse.append(
                    f"declared {policy} {name} {version} has an invalid surfaces scope"
                )
                continue
            for sname in meta["surfaces"]:
                nodes, by_nv, _ = locks[sname]
                srcs = by_nv.get((name, version))
                if not srcs:
                    sink.append(
                        f"[{sname}] declared {policy} {name} {version} absent from lock"
                    )
                    continue
                if len(srcs) > 1:
                    refuse.append(
                        f"[{sname}] {name} {version} has multiple sources (collision)"
                    )
                    continue
                src = srcs[0]
                node = nodes[(name, version, src)]
                if src != meta["source"] or node["checksum"] != meta["checksum"]:
                    sink.append(
                        f"[{sname}] {name} {version}: identity "
                        f"(source={src}, checksum={node['checksum']}) != declared "
                        f"(source={meta['source']}, checksum={meta['checksum']})"
                    )
            # declared-minus-derived: a scoped surface where it is not reached.
            reached_on = derived_surfaces.get((name, version), set())
            for sname in set(meta["surfaces"]) - reached_on:
                sink.append(
                    f"[{sname}] declared {policy} {name} {version} not reachable from the crypto "
                    f"roots on this surface (stale declaration)"
                )

    reconcile(man["crypto"], crypto_fail, "crypto")
    reconcile(man["util"], util_fail, "shared-util")

    # Roots: surface entry/exit.
    for rname, declared_surfaces in roots.items():
        for sname, (nodes, by_nv, by_name) in locks.items():
            present = rname in by_name
            if sname in declared_surfaces and not present:
                crypto_fail.append(
                    f"[{sname}] crypto root {rname} absent from a surface it is scoped to"
                )
            if present and sname not in declared_surfaces:
                refuse.append(
                    f"[{sname}] crypto root {rname} present but this surface is undeclared for it "
                    f"— add it to [roots].{rname} and review"
                )

    # Anti-fail-open guard: CORE_CRYPTO must be declared crypto, never utility.
    for name in CORE_CRYPTO:
        if name in man["util_names"]:
            crypto_fail.append(
                f"core-crypto '{name}' misclassified under [non_crypto_shared]"
            )
        reachable = any(k[0] == name for s in scoped_by_surface.values() for k in s)
        if reachable and name not in man["crypto_names"]:
            crypto_fail.append(
                f"core-crypto '{name}' reachable but not in [crypto_components]"
            )

    if refuse:
        _report(
            "REFUSE — parity cannot be judged (coverage/identity gap)",
            refuse,
            "declare the node/surface, qualify the edge, or exempt via [out_of_scope_roots] "
            "— do not skip.",
        )
        return EXIT_REFUSE
    if crypto_fail:
        _report(
            "FAIL (security) — crypto-graph parity divergence",
            crypto_fail,
            "refresh all committed locks in one PR so the crypto graph resolves identically.",
        )
        return EXIT_FAIL_CRYPTO
    if util_fail:
        _report(
            "FAIL (shared-graph lockstep) — shared utility drift (NOT a security finding)",
            util_fail,
            "refresh all committed locks in one PR; utilities are kept in lockstep by policy.",
        )
        return EXIT_FAIL_UTIL

    print(
        f"[ok] parity holds across {len(man['surfaces'])} surfaces: "
        f"{len(man['crypto'])} crypto (security gate) + {len(man['util'])} shared-util (lockstep), "
        f"full-identity keyed"
    )
    return EXIT_OK


def _report(headline, items, remedy):
    print(headline + ":", file=sys.stderr)
    for it in sorted(set(items)):
        print(f"  {it}", file=sys.stderr)
    print(f"  remedy: {remedy}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", default="ci/parity-manifest.toml")
    ap.add_argument(
        "--regen",
        action="store_true",
        help="rewrite the generated component tables in place, then exit",
    )
    args = ap.parse_args()
    man = load_manifest(args.manifest)
    if args.regen:
        return regen(man, args.manifest)
    return check(man)


if __name__ == "__main__":
    sys.exit(main())
