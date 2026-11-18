"""S19: hallucinated package. Every dependency declared in csproj / Directory.Packages.props,
package.json, requirements*.txt and pyproject.toml is looked up in its public registry.
Not found => hit. A failed lookup => the whole smell is 'not assessed', never a pass.
A package the repository resolves from a private source -- a root nuget.config
packageSourceMapping, or a root .npmrc scoped registry -- is skipped, not looked up: the
public registry cannot know it, so its absence there says nothing."""
import argparse, json, os, pathlib, posixpath, re, urllib.request, urllib.error
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
try:
    import tomllib
except ImportError:
    tomllib = None

def host_is(url, *hosts):
    """True when url's hostname is one of hosts. A substring test would take
    `pypi.org.example.invalid` for PyPI; a value with no readable hostname is never public."""
    try:
        return (urlparse(url.strip()).hostname or "").lower() in hosts
    except ValueError:
        return False

NUGET_HOSTS, NPM_HOSTS, PYPI_HOSTS = ("api.nuget.org", "nuget.org", "www.nuget.org"), ("registry.npmjs.org",), ("pypi.org",)

def nuget_sources(root):
    """(pattern -> True when it maps to a non-nuget.org source, unmapped) where unmapped is True
    when a non-nuget.org source is declared with no packageSourceMapping, so no id can be told
    private from hallucinated. Raises ET.ParseError on a malformed nuget.config: the caller
    then skips NuGet lookups only."""
    nuget, unmapped = {}, False
    # Case-variant configs at one root: NuGet reads a single file per directory, so sort by name
    # and read them in that order; a pattern listed on several sources is private when any of them is.
    for f in sorted(root.iterdir(), key=lambda p: p.name):
        if f.name.lower() == "nuget.config" and f.is_file():
            cfg = ET.fromstring(f.read_bytes())
            disabled = {a.get("key") for a in cfg.findall("disabledPackageSources/add") if a.get("value", "").lower() == "true"}
            urls = {a.get("key"): a.get("value", "") for a in cfg.findall("packageSources/add") if a.get("key")}
            mapped = False
            for src in cfg.iter("packageSource"):
                mapped = True
                private = not host_is(urls.get(src.get("key"), ""), *NUGET_HOSTS)
                for p in src.iter("package"):
                    pattern = p.get("pattern", "").lower(); nuget[pattern] = nuget.get(pattern, False) or private
            if not mapped and any(not host_is(v, *NUGET_HOSTS) for k, v in urls.items() if k not in disabled):
                unmapped = True
    return nuget, unmapped

def npm_scopes(root):
    """scope -> True when its registry is not registry.npmjs.org. The key "" is the unscoped
    `registry=`. Independent of nuget.config."""
    npm = {}
    for f in root.iterdir():
        if f.name == ".npmrc" and f.is_file():
            for m in re.finditer(r"^\s*(@[^:\s]+:)?registry\s*=\s*(\S+)", f.read_text(encoding="utf-8", errors="replace"), re.M):
                npm[(m.group(1) or ":")[:-1].lower()] = not host_is(m.group(2), *NPM_HOSTS)
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

NPM_NON_REGISTRY = re.compile(r"^(?:file|link|workspace|portal|git|git\+\w+|github|gitlab|bitbucket|https?):|^(?:\.{1,2}[/\\]|~/|/)|^[\w.-]+/[\w.-]+(?:#.*)?$")

def npm_registry_name(key, spec):
    """The registry package a package.json entry names, or None when its spec is not a registry one.
    `npm:real@1` is an alias: the key is local, the aliased name is what the registry holds."""
    if not isinstance(spec, str):
        return key
    spec = spec.strip()
    if spec.startswith("npm:"):
        alias = spec[4:]
        return alias.rsplit("@", 1)[0] if "@" in alias[1:] else alias
    return None if NPM_NON_REGISTRY.match(spec) else key

def poetry_local(spec):
    return isinstance(spec, dict) and any(k in spec for k in ("path", "git", "url"))

PEP508_DIRECT = re.compile(r"\s*[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]*\])?\s*@\s*\S")  # `name @ url`: installed from the URL
PYPI_INDEX = re.compile(r"^\s*(?:-i|--index-url|--extra-index-url)[\s=]+(\S+)")

REQ_INCLUDE = re.compile(r"^\s*(?:-r|-c|--requirement|--constraint)[\s=]+(\S+)")

def declared(root, rel, indexes=None, includes=None):
    """Declared dependencies as (ecosystem, name, line). A manifest that declares a PyPI index
    other than pypi.org appends rel to `indexes`: its PyPI names cannot be checked on pypi.org.
    A requirements file that includes another records the pair in `includes` (rel -> children),
    because pip applies an index option to every file in the install."""
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
        # ParseError (a SyntaxError) reaches main()'s per-file handler: not assessed, never a pass.
        # Comments blanked (newlines kept) so a mention of the id in a comment is not taken for its line.
        bare = re.sub(r"<!--.*?-->", lambda m: re.sub(r"[^\n]", " ", m.group()), text, flags=re.S)
        for el in ET.fromstring(text).iter():
            # Local name: old-style projects carry the MSBuild namespace. Attribute order and
            # line wrapping do not matter to the XML parser.
            if el.tag.rsplit("}", 1)[-1] in ("PackageReference", "PackageVersion"):
                pkg = el.get("Include") or el.get("Update")
                if pkg:
                    tag = re.search(r"<Package(?:Reference|Version)\b[^>]*?\b(?:Include|Update)\s*=\s*[\"']" + re.escape(pkg) + r"[\"']", bare)
                    out.append(("nuget", pkg, bare.count("\n", 0, tag.start()) + 1 if tag else 1))
    elif name == "package.json":
        data = json.loads(text)
        lines = text.splitlines()
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for key, spec in (data.get(section) or {}).items():
                pkg = npm_registry_name(key, spec)
                if pkg is None:
                    continue  # file:, link:, workspace:, git and URL specs name no registry package
                line = next((i for i, l in enumerate(lines, 1) if f'"{key}"' in l), 1)
                out.append(("npm", pkg, line))
    elif re.match(r"requirements.*\.txt$", name):
        for i, line in enumerate(text.splitlines(), 1):
            idx = PYPI_INDEX.match(line)
            if idx and not host_is(idx.group(1), *PYPI_HOSTS) and indexes is not None:
                indexes.append(rel)
            inc = REQ_INCLUDE.match(line)
            if inc and includes is not None:
                includes.setdefault(rel, []).append(posixpath.normpath(posixpath.join(posixpath.dirname(rel), inc.group(1))))
            m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", line)
            if not m or line.strip().startswith(("#", "-", ".", "/", "~")):
                continue
            # `git+https://...`, a bare URL, `file:///...` and `name @ url` (PEP 508 direct
            # reference) all install from a location, so none names a registry package.
            if "://" in line or PEP508_DIRECT.match(line):
                continue
            out.append(("pypi", m.group(1), i))
    elif name == "pyproject.toml":
        if tomllib is None:
            raise RuntimeError("tomllib not available")
        lines = text.splitlines()
        data = tomllib.loads(text)
        # Poetry's built-in PyPI source is named `PyPI` and carries no url. A custom source blocks the
        # manifest unless it is `explicit`: an explicit source serves only the dependencies that name it.
        explicit = set()
        for s in (data.get("tool", {}).get("poetry", {}).get("source") or []):
            if not isinstance(s, dict) or (str(s.get("name", "")).lower() == "pypi" and not s.get("url")) or host_is(str(s.get("url", "")), *PYPI_HOSTS):
                continue
            if s.get("priority") == "explicit":
                explicit.add(s.get("name"))
            elif indexes is not None:
                indexes.append(rel)
        for dep_str in (data.get("project", {}).get("dependencies") or []):
            if PEP508_DIRECT.match(dep_str):
                continue
            pkg = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", dep_str).group(1)
            line = next((i for i, l in enumerate(lines, 1) if pkg in l), 1)
            out.append(("pypi", pkg, line))
        for section, deps in (data.get("project", {}).get("optional-dependencies") or {}).items():
            for dep_str in deps:
                if PEP508_DIRECT.match(dep_str):
                    continue
                pkg = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", dep_str).group(1)
                line = next((i for i, l in enumerate(lines, 1) if pkg in l), 1)
                out.append(("pypi", pkg, line))
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies") or {}
        def served_elsewhere(spec):
            return isinstance(spec, dict) and spec.get("source") in explicit
        for pkg, spec in poetry_deps.items():
            if pkg != "python" and not poetry_local(spec) and not served_elsewhere(spec):
                line = next((i for i, l in enumerate(lines, 1) if pkg in l), 1)
                out.append(("pypi", pkg, line))
        for group_deps in (data.get("tool", {}).get("poetry", {}).get("group") or {}).values():
            for pkg, spec in (group_deps.get("dependencies") or {}).items():
                if pkg != "python" and not poetry_local(spec) and not served_elsewhere(spec):
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
    # Ecosystems whose public registry cannot vouch for a name, and the reason. The reason is
    # reported only when a manifest of that ecosystem is actually seen.
    blocked, blocked_seen, index_files = {}, set(), []
    try:
        scopes = npm_scopes(root)
    except OSError as e:
        # Same reasoning as nuget.config below: without the scope map a private npm package
        # reads as hallucinated, so npm lookups are skipped rather than guessed.
        scopes, npm_skipped = {}, True
        parse_errors.append(f"failed to read .npmrc: {type(e).__name__}")
    # A private unscoped `registry=` hides unscoped names only: a scope mapped in .npmrc still
    # resolves to its own registry, public or private, so scoped names are judged by is_private.
    npm_default_private = scopes.get("", False)
    try:
        nuget_map, nuget_unmapped = nuget_sources(root)
    except (ET.ParseError, OSError) as e:
        # Without the source mapping a private NuGet id is indistinguishable from a
        # hallucinated one, so NuGet lookups are skipped. npm and PyPI are unaffected.
        nuget_map, nuget_skipped, nuget_unmapped = {}, True, False
        parse_errors.append(f"failed to parse nuget.config: {type(e).__name__}")
    if nuget_unmapped:
        blocked["nuget"] = "nuget not assessed: nuget.config declares a non-nuget.org source without packageSourceMapping"
    includes, decl_by_file = {}, []
    for rel in pathlib.Path(a.files).read_text(encoding="utf-8").splitlines():
        rel = rel.strip()
        if not rel:
            continue
        try:
            decls = declared(root, rel, index_files, includes)
        except (ValueError, KeyError, AttributeError, OSError, RuntimeError, ET.ParseError) as e:
            # RuntimeError: declared() raises it for pyproject.toml when tomllib is missing.
            parse_errors.append(f"failed to parse {rel}: {type(e).__name__}")
            continue
        decl_by_file.append((rel, decls))
    # pip applies an index option to every file in the same install, so a requirements file
    # joined to one that sets a private index (in either direction, through -r or -c) shares it.
    linked = {}
    for parent, children in includes.items():
        for child in children:
            linked.setdefault(parent, set()).add(child)
            linked.setdefault(child, set()).add(parent)
    private_index, queue = set(index_files), list(index_files)
    while queue:
        for other in linked.get(queue.pop(), ()):
            if other not in private_index:
                private_index.add(other)
                queue.append(other)
    for rel, decls in decl_by_file:
        for eco, pkg, line in decls:
            if (nuget_skipped and eco == "nuget") or (npm_skipped and eco == "npm"):
                continue
            if eco in blocked:
                blocked_seen.add(eco)
                continue
            if eco == "npm" and npm_default_private and not (pkg.startswith("@") and pkg.lower().split("/")[0] in scopes):
                blocked_seen.add("npm")
                continue
            if eco == "pypi" and rel in private_index:
                blocked_seen.add(f"pypi:{rel}")
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
    parse_errors += [blocked[e] for e in sorted(blocked_seen) if e in blocked]
    if "npm" in blocked_seen:
        parse_errors.append("npm not assessed: .npmrc sets an unscoped registry other than registry.npmjs.org")
    parse_errors += [f"pypi not assessed: {e[5:]} uses a PyPI index other than pypi.org" for e in sorted(blocked_seen) if e.startswith("pypi:")]
    # Every gap is reported: a blocked ecosystem must not hide a failed lookup in another.
    reasons = parse_errors + (["lookup failed for " + ", ".join(sorted(set(failed)))] if failed else [])
    if reasons:
        status, reason = "not assessed", "; ".join(reasons)
    else:
        status, reason = "assessed", ("private source, not looked up: " + ", ".join(sorted(skipped))) if skipped else ""
    print(json.dumps({"status": status, "reason": reason, "hits": sorted(hits, key=lambda h: (h["file"], h["line"]))}))

if __name__ == "__main__":
    main()
