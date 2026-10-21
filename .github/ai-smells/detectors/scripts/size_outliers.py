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
# After the parameter list: an optional `: ReturnType` (TS/Python), then `{`, `=>` or nothing.
# An optional `key: ` prefix admits `default: function Inner(`.
SIGNATURE = re.compile(r"^\s*(?:[\w$]+\s*:\s*)?(public|private|protected|internal|static|async|export|function|def)\b(?![^(]*\b(?:class|record|struct|interface|enum)\s+\w+)[^;=]*\([^;]*\)\s*(?::[^;]*?)?\s*(\{|=>)?\s*$")
OPENER = re.compile(r"^\s*(?:[\w$]+\s*:\s*)?(public|private|protected|internal|static|async|export|function|def)\b(?![^(]*\b(?:class|record|struct|interface|enum)\s+\w+)[^;=]*\(")
# TS/JS arrow bindings: `const f = (a): T => {`, `const f = useCallback((a) => {`, `const L = lazy(() =>`.
# shortcut: `const f = a => {` is read only when the parameter is bare; a type annotation
# on the binding that itself contains `=` (a function type) is not read. Upgrade to a parser.
CONST_OPENER = re.compile(r"^\s*(?:export\s+(?:default\s+)?)?(?:const|let|var)\s+[\w$]+\s*(?::[^=]+)?=\s*(?:async\s+)?(?:[\w$.]+\s*\(\s*)?(?:async\s+)?(?:\(|(?=[\w$]+\s*=>))")
CONST_SIGNATURE = re.compile(CONST_OPENER.pattern + r".*=>\s*\{?\s*$")
ARROW_END = re.compile(r"=>\s*\{?\s*$")
# Strings, char literals, template literals and comments, blanked before braces are counted.
# shortcut: a regex literal holding a quote or `//` can desynchronise this; upgrade to a tokenizer.
LITERAL = re.compile(r'//[^\n]*|/\*.*?\*/|@"(?:""|[^"])*"|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|`(?:\\.|[^`\\])*`', re.S)
KEEP = re.compile(r"[^\r\n\x0b\x0c\x1c-\x1e\x85  ]")
WRAP_LIMIT = 30  # a parameter list longer than this many lines is not a signature
SOURCE = (".cs", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py")
UNSUPPORTED = (".ps1", ".psm1", ".go", ".java", ".rs", ".rb", ".kt", ".swift", ".cpp", ".c")

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
                signature = " ".join(lines[node.lineno - 1:node.body[0].lineno - 1]).strip() or lines[node.lineno - 1].strip()
                hits.append({"file": rel, "line": node.lineno, "endLine": node.end_lineno, "text": f"function spans {span} lines: {signature}"})
    return hits

def blank_literals(source):
    return LITERAL.sub(lambda m: KEEP.sub(" ", m.group()), source)

def signature_end(lines, i):
    """Index of the last line of the signature that starts at lines[i], or None. A parameter
    list wrapped over several lines is joined up to its closing ')' before matching."""
    if not (OPENER.match(lines[i]) or CONST_OPENER.match(lines[i])):
        return None
    joined, k = lines[i], i
    while joined.count("(") > joined.count(")") and not ARROW_END.search(joined) and k + 1 < len(lines) and k - i < WRAP_LIMIT:
        k += 1
        joined += " " + lines[k].strip()
    return k if (SIGNATURE.match(joined) or CONST_SIGNATURE.match(joined)) else None

def block_end(code, i, head):
    """Index of the line that closes the block opened by the signature at code[i..head], or
    None. A `=>` signature with no `{` (`lazy(() =>`) is closed by its parentheses instead."""
    signature = " ".join(code[i:head + 1])
    open_c, close_c = ("(", ")") if signature.rstrip().endswith("=>") else ("{", "}")
    depth, opened = 0, False
    for j in range(i, len(code)):
        depth += code[j].count(open_c) - code[j].count(close_c)
        opened = opened or open_c in code[j]
        if opened and depth <= 0:
            return j
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True); ap.add_argument("--files", required=True); ap.add_argument("--smell", required=True)
    a = ap.parse_args()
    root = pathlib.Path(a.root)
    hits, unread, skipped = [], [], []
    for rel in pathlib.Path(a.files).read_text(encoding="utf-8").splitlines():
        rel = rel.strip()
        if rel.lower().endswith(UNSUPPORTED):
            skipped.append(rel)
        if not rel or not rel.lower().endswith(SOURCE):
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
        if rel.lower().endswith(".py"):
            hits += python_hits(rel, source)
            continue
        code = blank_literals(source).splitlines()
        i = 0
        while i < len(lines):
            head = signature_end(code, i)
            if head is not None:
                j = block_end(code, i, head)
                if j is not None and j - i + 1 > FUNC_MAX:
                    signature = " ".join(line.strip() for line in lines[i:head + 1])
                    hits.append({"file": rel, "line": i + 1, "endLine": j + 1, "text": f"function spans {j - i + 1} lines: {signature}"})
                    i = j
            i += 1
    status, reason = ("not assessed", "could not read " + ", ".join(unread)) if unread else ("assessed", "")
    if skipped:
        status, reason = "not assessed", "; ".join(filter(None, [reason, "unsupported source: " + ", ".join(skipped)]))
    print(json.dumps({"status": status, "reason": reason, "hits": sorted(hits, key=lambda h: (h["file"], h["line"]))}))

if __name__ == "__main__":
    main()
