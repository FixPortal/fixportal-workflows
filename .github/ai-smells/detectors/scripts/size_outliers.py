"""S30: oversized file or function. File > 800 lines, or a function spanning > 120 lines,
is a hit: a brace-delimited block opened by a method/function signature, or a Python
function measured by its syntax tree. Brace counting never sees a Python body open, and
indentation scanning is fooled by wrapped signatures and column-0 string content, so
Python goes through ast instead. Every hit carries `line` and `endLine`: the PR filter
tests the whole span, not just its first line."""
import argparse, ast, json, pathlib, re

FILE_MAX, FUNC_MAX = 800, 120
# The lookahead rejects type declarations: `class Svc(IDep d) {` and `record R(int A) {`
# have a parameter list and a brace but are not functions, and measuring one as a function
# made the scan skip every method nested inside it.
SIGNATURE = re.compile(r"^\s*(public|private|protected|internal|static|async|export|function|def)\b(?![^(]*\b(?:class|record|struct|interface|enum)\b)[^;=]*\([^;]*\)\s*(\{|=>|:)?\s*$")
OPENER = re.compile(r"^\s*(public|private|protected|internal|static|async|export|function|def)\b(?![^(]*\b(?:class|record|struct|interface|enum)\b)[^;=]*\(")
WRAP_LIMIT = 30  # a parameter list longer than this many lines is not a signature

def python_hits(rel, source):
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []  # Unparseable: the file-size check above still applies.
    lines = source.splitlines()
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            span = node.end_lineno - node.lineno + 1
            if span > FUNC_MAX:
                hits.append({"file": rel, "line": node.lineno, "endLine": node.end_lineno, "text": f"function spans {span} lines: {lines[node.lineno - 1].strip()[:80]}"})
    return hits

def signature_end(lines, i):
    """Index of the last line of the signature that starts at lines[i], or None. A parameter
    list wrapped over several lines is joined up to its closing ')' before matching."""
    if not OPENER.match(lines[i]):
        return None
    joined, k = lines[i], i
    while joined.count("(") > joined.count(")") and k + 1 < len(lines) and k - i < WRAP_LIMIT:
        k += 1
        joined += " " + lines[k].strip()
    return k if SIGNATURE.match(joined) else None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True); ap.add_argument("--files", required=True); ap.add_argument("--smell", required=True)
    a = ap.parse_args()
    root = pathlib.Path(a.root)
    hits, unread = [], []
    for rel in pathlib.Path(a.files).read_text(encoding="utf-8").splitlines():
        rel = rel.strip()
        if not rel or not rel.endswith((".cs", ".ts", ".tsx", ".js", ".jsx", ".py")):
            continue
        path = root / rel
        if not path.is_file():
            continue  # a gitlink / submodule path lists as a directory
        try:
            # utf-8-sig drops a leading BOM, which ast.parse would otherwise reject as U+FEFF.
            source = path.read_bytes().decode("utf-8-sig", errors="replace")
        except OSError:
            unread.append(rel)
            continue
        lines = source.splitlines()
        if len(lines) > FILE_MAX:
            hits.append({"file": rel, "line": 1, "endLine": len(lines), "text": f"file is {len(lines)} lines"})
        if rel.endswith(".py"):
            hits += python_hits(rel, source)
            continue
        i = 0
        while i < len(lines):
            head = signature_end(lines, i)
            if head is not None:
                depth, j, opened = 0, i, False
                while j < len(lines):
                    depth += lines[j].count("{") - lines[j].count("}")
                    opened = opened or "{" in lines[j]
                    if opened and depth <= 0:
                        break
                    j += 1
                if opened and j - i + 1 > FUNC_MAX:
                    hits.append({"file": rel, "line": i + 1, "endLine": j + 1, "text": f"function spans {j - i + 1} lines: {lines[i].strip()[:80]}"})
                    i = j
            i += 1
    status, reason = ("not assessed", "could not read " + ", ".join(unread)) if unread else ("assessed", "")
    print(json.dumps({"status": status, "reason": reason, "hits": sorted(hits, key=lambda h: (h["file"], h["line"]))}))

if __name__ == "__main__":
    main()
