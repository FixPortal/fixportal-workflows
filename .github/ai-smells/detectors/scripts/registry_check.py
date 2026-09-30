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

def private_sources(root):
    """(nuget_patterns, npm_scopes): pattern -> True when it maps to a non-nuget.org source,
    scope -> True when its registry is not registry.npmjs.org."""
    nuget, npm = {}, {}
    for f in root.iterdir():
        if f.name.lower() == "nuget.config":
            cfg = ET.fromstring(f.read_bytes())
            urls = {a.get("key"): a.get("value", "") for a in cfg.findall("packageSources/add") if a.get("key")}
            for src in cfg.iter("packageSource"):
                private = "api.nuget.org" not in urls.get(src.get("key"), "")
                for p in src.iter("package"):
                    nuget[p.get("pattern", "").lower()] = private
        elif f.name == ".npmrc":
            for m in re.finditer(r"^\s*(@[^:\s]+):registry\s*=\s*(\S+)", f.read_text(encoding="utf-8", errors="replace"), re.M):
                npm[m.group(1).lower()] = "registry.npmjs.org" not in m.group(2)
    return nuget, npm

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
    text = (root / rel).read_bytes().decode("utf-8", errors="replace")
    name = pathlib.PurePosixPath(rel).name.lower()
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
            if m and not line.strip().startswith(("#", "-")):
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
    parse_error = None
    try:
        nuget_map, npm_scopes = private_sources(root)
    except ET.ParseError:
        nuget_map, npm_scopes = {}, {}
        parse_error = "failed to parse nuget.config: ParseError"
    for rel in pathlib.Path(a.files).read_text(encoding="utf-8").splitlines():
        rel = rel.strip()
        if not rel:
            continue
        try:
            decls = declared(root, rel)
        except (ValueError, KeyError, AttributeError) as e:
            parse_error = f"failed to parse {rel}: {type(e).__name__}"
            continue
        for eco, pkg, line in decls:
            if is_private(eco, pkg, nuget_map, npm_scopes):
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
        try:
            return exists(key[0], first[key], fixture)
        except (urllib.error.URLError, TimeoutError, OSError):
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        seen = dict(zip(first, pool.map(lookup, first)))
    for rel, eco, pkg, line in public:
        found = seen[(eco, pkg.lower())]
        if found is None:
            failed.append(f"{eco}:{pkg}")
        elif not found:
            hits.append({"file": rel, "line": line, "text": f"{eco} package '{pkg}' not found in the public registry"})
    if parse_error:
        status, reason = "not assessed", parse_error
    elif failed:
        status, reason = "not assessed", "lookup failed for " + ", ".join(sorted(set(failed)))
    else:
        status, reason = "assessed", ("private source, not looked up: " + ", ".join(sorted(skipped))) if skipped else ""
    print(json.dumps({"status": status, "reason": reason, "hits": sorted(hits, key=lambda h: (h["file"], h["line"]))}))

if __name__ == "__main__":
    main()
