#!/usr/bin/env python3
"""Fails when a copied canonical asset differs from this repo's committed manifest.

scaffold-ci ships controls BY COPY -- files under assets/ and templates/ copied verbatim
into consuming repositories. A copy has no link back to its source, so a repo-local edit
to one is invisible at PR time: the drift sweep answers "did this copy receive
canonical's content" on a schedule, in another repository, and cannot answer "this repo
reversed a rule canonical asserts". On 2026-09-20 exactly that edit merged silently.

This is the in-repo half of the fix. .github/canonical-assets.json is a committed record
of what this repo runs; this verifier recomputes it. A local edit then fails CI here
unless the manifest is regenerated and committed IN THE SAME PR, which puts the
divergence in the diff, in front of the reviewer. Deliberate divergence stays possible --
it becomes explicit. That is the whole design: visibility, not prohibition.

The comparison is LOCAL: the manifest is never checked against live canonical (the
canonical repo is private; CI has no credential for it, and needs none). Canonical moving
therefore cannot fail this check -- a canonical bump is the sweep's question, not this
one's, and a control that red-lines thirty repositories on the day canonical legitimately
changes is a control that gets switched off.

Hash contract (shared with sync-canonical-asset-manifest.ps1, which writes what this
reads): UTF-8 with BOM tolerated, line endings normalised CRLF/CR -> LF, hashed as UTF-8
with no BOM. Line endings and BOM are normalised -- git flips those per
.gitattributes, and a hash that red-lines a CRLF checkout is a false-positive factory.
One more thing is masked: on a `uses: owner/repo@<40-hex sha>` line, the SHA and any
trailing `# vX` comment are replaced by a fixed token before hashing. Dependabot bumps
those pins in consuming repos on its own schedule; hashing them red-lined every bump of
a canonical workflow. The action NAME stays hashed, and a non-SHA ref (`@v3`, `@main`)
is not masked, so swapping the action or unpinning it still reads DIVERGED -- and
assert_workflow_hygiene.py separately enforces SHA pinning. Everything else is exact,
because exactness is the point.

Pure Python, stdlib only, read-only, no network -- same reasons as
assert_gate_coverage.py (a shell wrapper cannot survive CRLF; Python does not care).

Exit 0: every listed asset matches. Exit 1: an asset DIVERGED or is MISSING. Exit 2: the
manifest itself is absent, unparsable, an unknown schema, empty, or names a path outside
the repository -- the control is broken, which must never read as "assets fine".
"""
import hashlib
import json
import re
import sys
from pathlib import Path

TEACHING = """
A listed asset diverges from the committed canonical-asset manifest. Each listed
file is a copy of a canonical scaffold-ci asset.

  Deliberate change? Regenerate the manifest and commit it IN THIS PR -- the
  generator lives in the canonical skills checkout:
    pwsh ~/.agents/skills/scaffold-ci/scripts/sync-canonical-asset-manifest.ps1 -RepoRoot .
  The manifest diff tells the reviewer the divergence is intentional. Consider
  upstreaming the improvement to fixportal-agents-skills.

  Accidental? Restore the file from canonical (scaffold-ci/assets/ in the skills
  checkout) or revert the edit.

  Canonical moved? Re-sync the asset from scaffold-ci and regenerate the manifest
  in the same PR.
"""


# Must stay equivalent to the generator's $PinnedUses pattern -- both sides of the contract.
PINNED_USES = re.compile(r"^([ \t]*(?:-[ \t]+)?uses:[ \t]*[^\s@#]+@)[0-9a-f]{40}(?:[ \t]+#.*)?$", re.M)


def asset_hash(path: Path) -> str:
    text = path.read_bytes().decode("utf-8-sig")
    normalised = text.replace("\r\n", "\n").replace("\r", "\n")
    normalised = PINNED_USES.sub(r"\1<pinned>", normalised)
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    manifest_path = root / ".github" / "canonical-assets.json"
    if not manifest_path.is_file():
        print(f"ERROR: {manifest_path} not found.")
        print("This repository's CI runs the canonical-asset gate, so the manifest must")
        print("be committed. Restore it, or regenerate it from the canonical checkout:")
        print("  pwsh ~/.agents/skills/scaffold-ci/scripts/sync-canonical-asset-manifest.ps1 -RepoRoot .")
        return 2
    try:
        manifest = json.loads(manifest_path.read_bytes().decode("utf-8-sig"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        print(f"ERROR: {manifest_path} is not valid JSON: {exc}")
        print("The manifest may carry a hand-edit; fix it or regenerate it (see above).")
        return 2
    if not isinstance(manifest, dict) or manifest.get("schema") != 1:
        print(f"ERROR: unsupported manifest schema {manifest.get('schema') if isinstance(manifest, dict) else type(manifest).__name__!r};")
        print("this verifier knows schema 1. Re-sync verifier and manifest together from canonical.")
        return 2
    assets = manifest.get("assets")
    if not isinstance(assets, list) or not assets:
        print(f"ERROR: {manifest_path} lists no assets -- refusing to report success over nothing.")
        return 2

    failures = 0
    for entry in assets:
        rel = entry.get("path") if isinstance(entry, dict) else None
        expected = entry.get("sha256") if isinstance(entry, dict) else None
        if not isinstance(rel, str) or not isinstance(expected, str) or not rel or not expected:
            print(f"ERROR: malformed manifest entry {entry!r}")
            return 2
        rel_path = Path(rel)
        if rel_path.is_absolute() or ".." in rel_path.parts:
            print(f"ERROR: manifest entry escapes the repository: {rel}")
            return 2
        root_resolved = root.resolve()
        target = (root / rel).resolve()
        try:
            target.relative_to(root_resolved)
        except ValueError:
            print(f"ERROR: manifest entry resolves outside the repository: {rel}")
            return 2
        if not target.is_file():
            print(f"MISSING  {rel}  (listed in the manifest, absent from the tree)")
            failures += 1
            continue
        try:
            actual = asset_hash(target)
        except (OSError, UnicodeDecodeError) as exc:
            print(f"ERROR    {rel}  (cannot read or decode; cannot verify: {exc})")
            failures += 1
            continue
        if actual == expected:
            print(f"ok       {rel}")
        else:
            print(f"DIVERGED {rel}")
            failures += 1

    if failures:
        print(TEACHING)
        return 1
    print(f"canonical asset manifest OK - {len(assets)} asset(s) verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
