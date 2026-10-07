"""S19: hallucinated package. Every dependency declared in csproj / Directory.Packages.props,
package.json, requirements*.txt and pyproject.toml is looked up in its public registry.
Not found => hit. A failed lookup => the whole smell is 'not assessed', never a pass.
A package the repository resolves from a private source -- a root nuget.config
packageSourceMapping, or a root .npmrc scoped registry -- is skipped, not looked up: the
public registry cannot know it, so its absence there says nothing."""
import argparse, json, os, pathlib, re, urllib.request, urllib.error
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
try:
    import tomllib
except ImportError:
    tomllib = None

def nuget_sources(root):
    """pattern -> True when it maps to a non-nuget.org source. Raises ET.ParseError on a
    malformed nuget.config: the caller then skips NuGet lookups only."""
    nuget = {}
    for f in root.iterdir():
        if f.name.lower() == "nuget.config" and f.is_file():
            cfg = ET.fromstring(f.read_bytes())
            urls = {a.get("key"): a.get("value", "") for a in cfg.findall("packageSources/add") if a.get("key")}
            for src in cfg.iter("packageSource"):
                private = "api.nuget.org" not in urls.get(src.get("key"), "")
                for p in src.iter("package"):
                    nuget[p.get("pattern", "").lower()] = private
    return nuget

def npm_scopes(root):
    """scope -> True when its registry is not registry.npmjs.org. Independent of nuget.config."""
    npm = {}
    for f in root.iterdir():
        if f.name == ".npmrc" and f.is_file():
            for m in re.finditer(r"^\s*(@[^:\s]+):registry\s*=\s*(\S+)", f.read_text(encoding="utf-8", errors="replace"), re.M):
                npm[m.group(1).lower()] = "registry.npmjs.org" not in m.group(2)
    return npm

def is_private(eco, pkg, nuget, npm):
    pkg = pkg.lower()
    if eco == "npm":
        return pkg.startswith("@") and npm.get(pkg.split("/")[0], False)
    if eco != "nuget":
        return False
    # NuGet source mapping: an exact id beats any prefix, then the longest prefix wins.
    best = None
    for pattern, private in nuget.items():
        if pattern == pkg:
            rank = (1, len(pattern))
        elif pattern.endswith("*") and pkg.startswith(pattern[:-1]):
            rank = (0, len(pattern))
        else:
            continue
        if best is None or rank > best[0]:
            best = (rank, private)
    return bool(best and best[1])

def declared(root, rel):
    name = pathlib.PurePosixPath(rel).name.lower()
    if not (name.endswith(".csproj") or name in ("directory.packages.props", "packages.props", "package.json", "pyproject.toml") or re.match(r"requirements.*\.txt$", name)):
        return []  # Not a manifest: do not even open it (a gitlink lists as a directory).
    path = root / rel
    if not path.is_file():
        return []
    # utf-8-sig drops a leading BOM, which json.loads and tomllib would otherwise reject.
    text = path.read_bytes().decode("utf-8-sig", errors="replace")
    out = []
    if name.endswith(".csproj") or name in ("directory.packages.props", "packages.props"):
        for i, line in enumerate(text.splitlines(), 1):
            for m in re.finditer(r'<Package(?:Reference|Version)\s+(?:Include|Update)="([^"]+)"', line):
                out.append(("nuget", m.group(1), i))
    elif name == "package.json":
        data = json.loads(text)
        lines = text.splitlines()
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for pkg in (data.get(section) or {}):
                line = next((i for i, l in enumerate(lines, 1) if f'"{pkg}"' in l), 1)
                out.append(("npm", pkg, line))
    elif re.match(r"requirements.*\.txt$", name):
        for i, line in enumerate(text.splitlines(), 1):
            m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", line)
            if not m or line.strip().startswith(("#", "-", ".", "/", "~")):
                continue
            # `git+https://...`, a bare URL or `file:///...` names no registry package; only
            # `name @ url` (PEP 508 direct reference) still names one.
            if "://" in line and not re.match(r"\s*[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]*\])?\s*@\s*\S", line):
                continue
            out.append(("pypi", m.group(1), i))
    elif name == "pyproject.toml":
        if tomllib is None:
            raise RuntimeError("tomllib not available")
        lines = text.splitlines()
        data = tomllib.loads(text)
        for dep_str in (data.get("project", {}).get("dependencies") or []):
            pkg = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", dep_str).group(1)
            line = next((i for i, l in enumerate(lines, 1) if pkg in l), 1)
            out.append(("pypi", pkg, line))
        for section, deps in (data.get("project", {}).get("optional-dependencies") or {}).items():
            for dep_str in deps:
                pkg = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", dep_str).group(1)
                line = next((i for i, l in enumerate(lines, 1) if pkg in l), 1)
                out.append(("pypi", pkg, line))
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies") or {}
        for pkg in poetry_deps:
            if pkg != "python":
                line = next((i for i, l in enumerate(lines, 1) if pkg in l), 1)
                out.append(("pypi", pkg, line))
        for group_deps in (data.get("tool", {}).get("poetry", {}).get("group") or {}).values():
            for pkg in (group_deps.get("dependencies") or {}):
                if pkg != "python":
                    line = next((i for i, l in enumerate(lines, 1) if pkg in l), 1)
                    out.append(("pypi", pkg, line))
    return out

def exists(eco, pkg, fixture):
    if fixture is not None:
        v = fixture.get(f"{eco}:{pkg}")
        if v == "error" or v is None:
            raise urllib.error.URLError("fixture")
        if v == "crash":
            raise ValueError("fixture")
        return bool(v)
    url = {"nuget": f"https://api.nuget.org/v3-flatcontainer/{pkg.lower()}/index.json",
           "npm": f"https://registry.npmjs.org/{pkg.replace('/', '%2F')}",
           "pypi": f"https://pypi.org/pypi/{pkg}/json"}[eco]
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=15) as r:
            return r.status == 200
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        raise

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True); ap.add_argument("--files", required=True); ap.add_argument("--smell", required=True)
    a = ap.parse_args()
    root = pathlib.Path(a.root)
    fx_path = os.environ.get("AAQ_REGISTRY_FIXTURE")
    fixture = json.loads(pathlib.Path(fx_path).read_text(encoding="utf-8")) if fx_path else None
    hits, failed, skipped, public = [], [], set(), []
    parse_errors, nuget_skipped, npm_skipped = [], False, False
    try:
        scopes = npm_scopes(root)
    except OSError as e:
        # Same reasoning as nuget.config below: without the scope map a private npm package
        # reads as hallucinated, so npm lookups are skipped rather than guessed.
        scopes, npm_skipped = {}, True
        parse_errors.append(f"failed to read .npmrc: {type(e).__name__}")
    try:
        nuget_map = nuget_sources(root)
    except (ET.ParseError, OSError) as e:
        # Without the source mapping a private NuGet id is indistinguishable from a
        # hallucinated one, so NuGet lookups are skipped. npm and PyPI are unaffected.
        nuget_map, nuget_skipped = {}, True
        parse_errors.append(f"failed to parse nuget.config: {type(e).__name__}")
    for rel in pathlib.Path(a.files).read_text(encoding="utf-8").splitlines():
        rel = rel.strip()
        if not rel:
            continue
        try:
            decls = declared(root, rel)
        except (ValueError, KeyError, AttributeError, OSError, RuntimeError) as e:
            # RuntimeError: declared() raises it for pyproject.toml when tomllib is missing.
            parse_errors.append(f"failed to parse {rel}: {type(e).__name__}")
            continue
        for eco, pkg, line in decls:
            if (nuget_skipped and eco == "nuget") or (npm_skipped and eco == "npm"):
                continue
            if is_private(eco, pkg, nuget_map, scopes):
                skipped.add(f"{eco}:{pkg}")
            else:
                public.append((rel, eco, pkg, line))

    # Lookups are network-bound and independent, so they run concurrently: a manifest with
    # many dependencies costs about one round trip, not the sum of them. The first spelling
    # of each (ecosystem, lower-cased id) is the one looked up, as before.
    # ponytail: fixed pool of 8; raise it only if a large manifest still nears the job timeout.
    first = {}
    for _, eco, pkg, _ in public:
        first.setdefault((eco, pkg.lower()), pkg)

    def lookup(key):
        # Any lookup failure (RemoteDisconnected, IncompleteRead, a malformed URL's ValueError)
        # stays local to its package as 'not assessed': pool.map would otherwise re-raise it
        # and abort the run before the JSON is printed. The exception is returned, not
        # logged: stdout carries only the JSON.
        try:
            return exists(key[0], first[key], fixture)
        except Exception as e:
            return e

    with ThreadPoolExecutor(max_workers=8) as pool:
        seen = dict(zip(first, pool.map(lookup, first)))
    for rel, eco, pkg, line in public:
        found = seen[(eco, pkg.lower())]
        if isinstance(found, Exception):
            failed.append(f"{eco}:{pkg} ({type(found).__name__})")
        elif not found:
            hits.append({"file": rel, "line": line, "text": f"{eco} package '{pkg}' not found in the public registry"})
    if parse_errors:
        status, reason = "not assessed", "; ".join(parse_errors)
    elif failed:
        status, reason = "not assessed", "lookup failed for " + ", ".join(sorted(set(failed)))
    else:
        status, reason = "assessed", ("private source, not looked up: " + ", ".join(sorted(skipped))) if skipped else ""
    print(json.dumps({"status": status, "reason": reason, "hits": sorted(hits, key=lambda h: (h["file"], h["line"]))}))

if __name__ == "__main__":
    main()
