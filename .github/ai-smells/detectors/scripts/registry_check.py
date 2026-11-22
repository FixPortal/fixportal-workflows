"""S19: hallucinated package. Every dependency declared in csproj / Directory.Packages.props,
package.json, requirements*.txt and pyproject.toml is looked up in its public registry.
Not found => hit. A failed lookup => the whole smell is 'not assessed', never a pass.
A package the repository resolves from a private source -- a nuget.config
packageSourceMapping, or an .npmrc scoped registry, in the manifest's directory or any
ancestor up to the root -- is skipped, not looked up: the public registry cannot know it,
so its absence there says nothing."""
import argparse, json, os, pathlib, posixpath, re, shlex, urllib.request, urllib.error
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
try:
    import tomllib
except ImportError:
    tomllib = None

def host_is(url, *hosts):
    """True when url's hostname is one of hosts. A substring test would take
    `pypi.org.example.invalid` for PyPI; a value with no readable hostname is never public.
    That includes a value with no scheme: pip and NuGet read one as a local path
    (`--find-links pypi.org/wheels` is a directory), so it must not be taken for the host."""
    try:
        return (urlparse(url.strip()).hostname or "").lower() in hosts
    except ValueError:
        return False

NUGET_HOSTS, NPM_HOSTS, PYPI_HOSTS = ("api.nuget.org", "nuget.org", "www.nuget.org"), ("registry.npmjs.org",), ("pypi.org",)

def nuget_configs(directory):
    """The parsed nuget.config files in one directory. Case-variant names at one directory are read
    in name order. Raises ET.ParseError on a malformed file: the caller skips NuGet lookups for the
    manifests under it only."""
    return [ET.fromstring(f.read_bytes()) for f in sorted(directory.iterdir(), key=lambda p: p.name)
            if f.name.lower() == "nuget.config" and f.is_file()]

def nuget_sources(configs):
    """(pattern -> True when it maps to a non-nuget.org source, unmapped) for configs applied root
    first, as NuGet merges them: a later file adds to what came before, and a section's `<clear />`
    drops everything inherited for that section. A mapping may name a source an ancestor defines.
    unmapped is True when a non-nuget.org source is in effect with no packageSourceMapping, so no id
    can be told private from hallucinated."""
    urls, disabled, mapping = {}, set(), {}
    stores = {"packageSources": urls, "disabledPackageSources": disabled, "packageSourceMapping": mapping}
    for cfg in configs:
        seen_in_file = set()
        for section, store in stores.items():
            node = cfg.find(section)
            for child in (node if node is not None else []):
                if child.tag == "clear":
                    store.clear()
                elif child.tag == "add" and section == "packageSources" and child.get("key"):
                    urls[child.get("key").lower()] = child.get("value", "")
                elif child.tag == "add" and section == "disabledPackageSources":
                    # Source keys compare case-insensitively. A disabled source serves nothing, so its mapped
                    # patterns still rank but are never private: the id is looked up (ide review, RV-39).
                    key = child.get("key", "").lower()
                    if child.get("value", "").lower() == "true":
                        disabled.add(key)
                    else:
                        disabled.discard(key)
                elif child.tag == "packageSource" and section == "packageSourceMapping":
                    # A nearer file's packageSource REPLACES the same key's inherited patterns (NuGet's
                    # VirtualSettingSection); within one file, repeats of a key add up (CodeRabbit, PR #503).
                    key = (child.get("key") or "").lower()
                    patterns = [p.get("pattern", "").lower() for p in child.iter("package")]
                    mapping[key] = (mapping.get(key, []) + patterns) if key in seen_in_file else patterns
                    seen_in_file.add(key)
    nuget = {}
    for key, patterns in mapping.items():
        private = key not in disabled and not host_is(urls.get(key, ""), *NUGET_HOSTS)
        for pattern in patterns:
            nuget[pattern] = nuget.get(pattern, False) or private  # private when any source mapping it is
    unmapped = not mapping and any(not host_is(v, *NUGET_HOSTS) for k, v in urls.items() if k not in disabled)
    return nuget, unmapped

def npm_scopes(root):
    """scope -> True when its registry is not registry.npmjs.org. The key "" is the unscoped
    `registry=`. Independent of nuget.config."""
    npm = {}
    for f in root.iterdir():
        if f.name == ".npmrc" and f.is_file():
            for m in re.finditer(r"^\s*(@[^:\s]+:)?registry\s*=\s*(\S+)", f.read_text(encoding="utf-8", errors="replace"), re.M):
                # An npm registry value is always a URL, never a path, so one written without a scheme
                # (`registry=registry.npmjs.org/`) is read as its host (ide review, RV-23).
                url = m.group(2) if "://" in m.group(2) else "https://" + m.group(2)
                npm[(m.group(1) or ":")[:-1].lower()] = not host_is(url, *NPM_HOSTS)
    return npm

def config_dirs(root, rel):
    """The manifest's own directory, then each ancestor up to root: where its nuget.config and .npmrc live."""
    parts = pathlib.PurePosixPath(rel).parent.parts
    return [root.joinpath(*parts[:n]) for n in range(len(parts), -1, -1)]

def sources_for(dirs, configs_by_dir, scopes_by_dir):
    """((nuget map, unmapped), npm scopes) in effect for a manifest whose config dirs are `dirs`,
    nearest first. Either half is None when a config in that manifest's chain could not be read.
    NuGet configs merge root first (nuget_sources); the nearest .npmrc that names a scope decides it."""
    chain = list(reversed(dirs))
    nuget = None if any(configs_by_dir.get(d) is None for d in chain if d in configs_by_dir) else \
        nuget_sources([cfg for d in chain for cfg in configs_by_dir.get(d, [])])
    npm = {}
    for d in dirs:
        if d in scopes_by_dir and scopes_by_dir[d] is None:
            return nuget, None
        for scope, private in scopes_by_dir.get(d, {}).items():
            npm.setdefault(scope, private)
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

def poetry_off_pypi(spec, explicit):
    """True when no alternative of a Poetry dependency comes from PyPI. The spec is a table, or a
    list of them (multiple constraints); each alternative is local (path/git/url) or names an
    explicit source. A plain version string is a PyPI one."""
    specs = spec if isinstance(spec, list) else [spec]
    return all(isinstance(s, dict) and (any(k in s for k in ("path", "git", "url")) or s.get("source") in explicit) for s in specs)

PEP508_DIRECT = re.compile(r"\s*[A-Za-z0-9][A-Za-z0-9._-]*\s*(\[[^\]]*\])?\s*@\s*\S")  # `name @ url`: installed from the URL
# A find-links source serves packages pypi.org does not hold, and --no-index forbids pypi.org outright,
# so both read like a non-PyPI index.
# A short option may carry its value attached (`-fwheels`), as pip's optparse accepts; a long one needs a separator.
PYPI_INDEX = re.compile(r"^\s*(?:(?:-i|-f)(?:[\s=]+|(?=\S))|(?:--index-url|--extra-index-url|--find-links)[\s=]+)(\S+)")
NO_INDEX = re.compile(r"^\s*--no-index\b")

REQ_INCLUDE = re.compile(r"^\s*(?:(?:-r|-c)(?:[\s=]+|(?=\S))|(?:--requirement|--constraint)[\s=]+)(.+)")

PIP_COMMENT = re.compile(r"(^|\s+)#.*$")  # pip's COMMENT_RE: `#` starts a comment only at the start or after whitespace

def pip_lines(text):
    """(git line, text) for each logical line as pip 26 preprocesses a requirements file:
    str.splitlines() (a lone CR ends a line), a line ending in `\\` joined to the next unless it is a
    comment, then comments and blank lines dropped. The number is git's (only \\n counts) for the
    first physical line, to match the PR diff."""
    joined, git_line, start, pending = [], 1, None, []
    for raw in text.splitlines(keepends=True):
        line = raw.rstrip("\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029")
        if not line.endswith("\\") or PIP_COMMENT.match(line):
            if PIP_COMMENT.match(line):
                line = " " + line  # as pip does, so the comment is still stripped after joining
            joined.append((git_line if start is None else start, "".join(pending + [line])))
            start, pending = None, []
        else:
            start = git_line if start is None else start
            pending.append(line.strip("\\"))
        git_line += raw.count("\n")
    if pending:
        joined.append((start, "".join(pending)))
    out = []
    for number, line in joined:
        line = PIP_COMMENT.sub("", line).strip()
        if line:
            out.append((number, line))
    return out

def locate(text, token, after=None):
    """1-based line of the first match of regex `token` after the first match of `after`
    (1 when none). Scoping to the section the dependency was parsed from keeps an earlier mention
    of the name (a keyword, an override, a description) from taking the line."""
    start = 0
    if after:
        m = re.search(after, text, re.M)
        start = m.end() if m else 0
    m = re.compile(token, re.M).search(text, start)
    return text.count("\n", 0, m.start()) + 1 if m else 1

def pip_options(line, rel, indexes, includes):
    """Records what one requirements line says about where packages come from: a non-PyPI index
    or find-links source marks rel private, and -r/-c names a file pip applies the same options to."""
    idx = PYPI_INDEX.match(line)
    # pip 26.2.1 read `-i "https://pypi.org/simple"` and `-i"..."` as the bare URL.
    if (NO_INDEX.match(line) or (idx and not host_is(idx.group(1).strip("\"'"), *PYPI_HOSTS))) and indexes is not None:
        indexes.append(rel)
    inc = REQ_INCLUDE.match(line)
    # pip tokenises an option's value with shlex, so `-r "a b.txt"` names `a b.txt`; pip_lines has already
    # stripped comments, so a `#` inside a path is kept. Unbalanced quotes raise ValueError, which the
    # callers report as not assessed.
    target = shlex.split(inc.group(1)) if inc else []
    if target and includes is not None and "://" not in target[0]:
        includes.setdefault(rel, []).append(posixpath.normpath(posixpath.join(posixpath.dirname(rel), target[0])))

def read_included_options(root, includes, indexes, done, problems):
    """Follows -r/-c includes into files nobody listed, whatever their name: pip applies an index
    option from any file in the install, so an unchanged or oddly named child still decides whether
    a package is private. Only option lines are read. A path outside the tree is never opened; the
    `done` set ends a cycle."""
    tree = root.resolve()
    queue = [child for children in list(includes.values()) for child in children]
    # Resolved identities as well: through a directory link to `.`, `again/options.txt` and
    # `again/again/options.txt` are one file, and textual paths alone never stopped (Linux, Python 3.12).
    # A second spelling is not re-read but is linked to the first, so a parent that includes either
    # one still takes the file's index options. The key is the file AND the directory its spelling
    # names: pip 26.2.1 resolves a child against that directory, so two file links to one file are
    # two includes with different children.
    read = {}
    while queue:
        rel = queue.pop()
        if rel in done:
            continue
        done.add(rel)
        try:
            path = (root / rel).resolve()
            identity = (path, (root / rel).parent.resolve())
            if identity in read:
                includes.setdefault(rel, []).append(read[identity])
                continue
            if not path.is_relative_to(tree) or not path.is_file():
                continue
            read[identity] = rel
            text = path.read_bytes().decode("utf-8-sig", errors="replace")
            for _, line in pip_lines(text):
                pip_options(line, rel, indexes, includes)
        except (OSError, ValueError) as e:
            problems.append(f"failed to read {rel}: {type(e).__name__}")
            continue
        queue.extend(includes.get(rel, []))

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
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for key, spec in (data.get(section) or {}).items():
                pkg = npm_registry_name(key, spec)
                if pkg is None:
                    continue  # file:, link:, workspace:, git and URL specs name no registry package
                out.append(("npm", pkg, locate(text, rf'"{re.escape(key)}"\s*:', rf'"{section}"\s*:\s*\{{')))
    elif re.match(r"requirements.*\.txt$", name):
        for i, line in pip_lines(text):
            pip_options(line, rel, indexes, includes)
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
            out.append(("pypi", pkg, locate(text, rf'["\']\s*{re.escape(pkg)}(?![\w.-])', r"^\s*dependencies\s*=\s*\[")))
        for section, deps in (data.get("project", {}).get("optional-dependencies") or {}).items():
            for dep_str in deps:
                if PEP508_DIRECT.match(dep_str):
                    continue
                pkg = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", dep_str).group(1)
                # Located from its own group's key, so a name two groups share takes each group's line.
                # The key starts a line or follows `{`/`,`, so `# b = [...]` is not group b.
                group = rf"optional-dependencies[\s\S]*?(?:^|[{{,])[ \t]*[\"']?{re.escape(section)}[\"']?[ \t]*="
                out.append(("pypi", pkg, locate(text, rf'["\']\s*{re.escape(pkg)}(?![\w.-])', group)))
        # PEP 735 groups. An `{include-group = ...}` entry names another group, read in its own right.
        for deps in (data.get("dependency-groups") or {}).values():
            for dep_str in deps:
                if not isinstance(dep_str, str) or PEP508_DIRECT.match(dep_str):
                    continue
                # A specifier may carry surrounding whitespace (`" pytest>=8"`, CodeRabbit PR #503).
                pkg = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", dep_str.strip()).group(1)
                out.append(("pypi", pkg, locate(text, rf'["\']\s*{re.escape(pkg)}(?![\w.-])', r"^\s*\[dependency-groups\]")))
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies") or {}
        for pkg, spec in poetry_deps.items():
            if pkg != "python" and not poetry_off_pypi(spec, explicit):
                out.append(("pypi", pkg, locate(text, rf'^\s*["\']?{re.escape(pkg)}["\']?\s*=', r"^\s*\[tool\.poetry\.dependencies\]")))
        for group, group_deps in (data.get("tool", {}).get("poetry", {}).get("group") or {}).items():
            for pkg, spec in (group_deps.get("dependencies") or {}).items():
                if pkg != "python" and not poetry_off_pypi(spec, explicit):
                    out.append(("pypi", pkg, locate(text, rf'^\s*["\']?{re.escape(pkg)}["\']?\s*=', rf"^\s*\[tool\.poetry\.group\.{re.escape(group)}\.dependencies\]")))
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
    parse_errors = []
    # Ecosystems whose public registry cannot vouch for a name, and the reason. The reason is
    # reported only when a manifest of that ecosystem is actually seen.
    blocked = {"nuget": "nuget not assessed: nuget.config declares a non-nuget.org source without packageSourceMapping"}
    blocked_seen, index_files = set(), []
    rels = [rel.strip() for rel in pathlib.Path(a.files).read_text(encoding="utf-8").splitlines() if rel.strip()]
    # A manifest's own directory and its ancestors, not the root alone: a subdirectory .npmrc or
    # nuget.config makes its packages private too (observatory review, C2-X3).
    dirs = sorted({d for rel in rels for d in config_dirs(root, rel) if d.is_dir()} | {root})
    # An unreadable config is None for its directory: only manifests whose chain holds it skip (CodeRabbit, PR #503).
    scopes_by_dir, configs_by_dir = {}, {}
    for d in dirs:
        try:
            scopes_by_dir[d] = npm_scopes(d)
        except OSError as e:
            # Same reasoning as nuget.config below: without the scope map a private npm package
            # reads as hallucinated, so npm lookups are skipped rather than guessed.
            scopes_by_dir[d] = None
            parse_errors.append(f"failed to read .npmrc: {type(e).__name__}")
        try:
            configs_by_dir[d] = nuget_configs(d)
        except (ET.ParseError, OSError) as e:
            # Without the source mapping a private NuGet id is indistinguishable from a
            # hallucinated one, so NuGet lookups are skipped. npm and PyPI are unaffected.
            configs_by_dir[d] = None
            parse_errors.append(f"failed to parse nuget.config: {type(e).__name__}")
    includes, decl_by_file = {}, []
    for rel in rels:
        try:
            decls = declared(root, rel, index_files, includes)
        except (ValueError, KeyError, AttributeError, OSError, RuntimeError, ET.ParseError) as e:
            # RuntimeError: declared() raises it for pyproject.toml when tomllib is missing.
            parse_errors.append(f"failed to parse {rel}: {type(e).__name__}")
            continue
        decl_by_file.append((rel, decls))
    # Only a requirements-named file had its options read by declared(). A listed include with any
    # other name (`-r indexes.txt`) returned [] unread, so it must still be followed (ide review, RV-38).
    read_included_options(root, includes, index_files,
                          {rel for rel, _ in decl_by_file if re.match(r"requirements.*\.txt$", pathlib.PurePosixPath(rel).name.lower())}, parse_errors)
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
        nuget, scopes = sources_for(config_dirs(root, rel), configs_by_dir, scopes_by_dir)
        nuget_map, nuget_unmapped = nuget or ({}, False)
        # A private unscoped `registry=` hides unscoped names only: a scope mapped in .npmrc still
        # resolves to its own registry, public or private, so scoped names are judged by is_private.
        npm_default_private = (scopes or {}).get("", False)
        for eco, pkg, line in decls:
            if (nuget is None and eco == "nuget") or (scopes is None and eco == "npm"):
                continue
            if eco == "nuget" and nuget_unmapped:
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
