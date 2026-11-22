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
# A signature that starts with a return type or a bare name instead of a modifier: TS class
# methods (`render() {`), C# members with default accessibility, local functions and explicit
# interface implementations (`void IFoo.Bar()`). Control flow, `new` and `return` are not
# functions, and a callback argument (`it("x", function () {`) is not a declaration. The tail is
# accepted only with a `{`/`=>` or a `{` on the next line, so a call statement is never read.
# shortcut: a `where T : ...` constraint clause is not read; upgrade to a parser.
NAMED_HEAD = r"^\s*(?!(?:if|for|foreach|while|switch|catch|lock|using|return|new|else|do|try|finally|throw|await|yield|fixed|with|case|default|typeof|nameof|sizeof|checked|unchecked)\b)(?![^(]*\b(?:class|record|struct|interface|enum)\s+\w+)(?:[\w$<>\[\],.?]+\s+)*[\w$]+(?:<[^()]*>)?(?:\.[\w$]+)*\s*\("
NAMED_OPENER = re.compile(NAMED_HEAD)
# A callback argument starts with `function` or an arrow; a parameter whose type is a function
# (`visit(cb: () => void) {`) starts with a name, so it is a declaration.
NAMED = re.compile(NAMED_HEAD + r"(?![^;]*\bfunction\b)(?!\s*(?:async\s+)?(?:\([^()]*\)|[\w$]+)\s*=>)[^;{}]*\)\s*(?::[^;{}=]*)?\s*(\{|=>)?\s*$")
# A name-form signature whose `{` is on the next line is read only with a return type before the
# name or a `: ReturnType` after the parameters, so a bare call statement before a block is not.
# shortcut: an Allman-style TS method with no return type (`render()` then `{`) is not read.
NAMED_TYPED = re.compile(r"^\s*(?:[\w$<>\[\],.?]+\s+)+[\w$.<>]+\s*\(|\)\s*:\s*\S")
# Strings, char literals, template literals and comments, blanked before braces are counted.
# shortcut: a regex literal holding a quote or `//` can desynchronise this; upgrade to a tokenizer.
LITERAL = re.compile(r'//[^\n]*|/\*.*?\*/|@"(?:""|[^"])*"|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|`(?:\\.|[^`\\])*`', re.S)
KEEP = re.compile(r"[^\r\n]")
# A type declaration line: the scope a function sits in. Keyword-named functions (`function record(`)
# have no whitespace-then-name after the keyword, so they do not match.
TYPE_DECL = re.compile(r"^\s*(?:[\w$]+\s+)*?(?:class|record|struct|interface|enum)\s+([A-Za-z_$][\w$]*)")
WRAP_LIMIT = 30  # a parameter list longer than this many lines is not a signature
SOURCE = (".cs", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py")
UNSUPPORTED = (".ps1", ".psm1", ".go", ".java", ".rs", ".rb", ".kt", ".swift", ".cpp", ".c")

def split_lines(text):
    """Lines as git counts them: only \\n ends one (a CR before it is dropped). str.splitlines()
    also breaks on \\v, \\f, \\x1c-\\x1e, NEL, U+2028/9 and a lone CR, which would shift every
    later line number away from the PR diff's."""
    lines = [l[:-1] if l.endswith("\r") else l for l in text.split("\n")]
    if lines and lines[-1] == "":
        lines.pop()
    return lines

def scope_label(names):
    return f" in {'.'.join(names)}" if names else ""

def python_hits(rel, source):
    """(hits, parsed). parsed is False when the source does not parse: the caller records the
    file as not assessed, and the file-size check in main() still applies."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return [], False
    # The parser also ends a line at a lone CR, so its line numbers index these lines, and
    # git_line maps one to the line git and the PR diff count (only \n ends one).
    lines = re.split(r"\r\n|\r|\n", source)
    starts = [0] + [m.end() for m in re.finditer(r"\r\n|\r|\n", source)]
    def git_line(n):
        return source.count("\n", 0, starts[n - 1]) + 1
    hits = []
    def visit(node, scope):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                first, last = git_line(child.lineno), git_line(child.end_lineno)
                span = last - first + 1
                if span > FUNC_MAX:
                    signature = " ".join(lines[child.lineno - 1:child.body[0].lineno - 1]).strip() or lines[child.lineno - 1].strip()
                    hits.append({"file": rel, "line": first, "endLine": last, "text": f"function spans {span} lines{scope_label(scope)}: {signature}"})
                visit(child, scope + [child.name])
            else:
                visit(child, scope + [child.name] if isinstance(child, ast.ClassDef) else scope)
    visit(tree, [])
    return hits, True

def enclosing_types(code, i):
    """Names of the type declarations whose braces enclose line i, outermost first. The PR
    filter keys an oversized function by its text, so two same-signature methods in one file
    need the type to read differently."""
    names = []
    for k in range(i):
        m = TYPE_DECL.match(code[k])
        if not m:
            continue
        depth, opened = 0, False
        for j in range(k, len(code)):
            depth += code[j].count("{") - code[j].count("}")
            opened = opened or "{" in code[j]
            if opened and depth <= 0:
                if j >= i:
                    names.append(m.group(1))
                break
            if not opened and ";" in code[j]:
                break  # `record R(int A);` has no body
    return names

def blank_literals(source):
    return LITERAL.sub(lambda m: KEEP.sub(" ", m.group()), source)

def signature_end(lines, i):
    """Index of the last line of the signature that starts at lines[i], or None. A parameter
    list wrapped over several lines is joined up to its closing ')' before matching."""
    if not (OPENER.match(lines[i]) or CONST_OPENER.match(lines[i]) or NAMED_OPENER.match(lines[i])):
        return None
    joined, k = lines[i], i
    while joined.count("(") > joined.count(")") and not ARROW_END.search(joined) and k + 1 < len(lines) and k - i < WRAP_LIMIT:
        k += 1
        joined += " " + lines[k].strip()
    if SIGNATURE.match(joined) or CONST_SIGNATURE.match(joined):
        return k
    named = NAMED.match(joined)
    if named and (named.group(1) or (NAMED_TYPED.search(joined) and k + 1 < len(lines) and lines[k + 1].lstrip().startswith("{"))):
        return k
    return None

def params_close(code, i, head):
    """Column on code[head] just past the `)` where the signature's parentheses first balance.
    The LAST `)` belongs to the body in `f(): number { return g() }`. Unbalanced on the head
    line (`useCallback((a) => {`), the last `)` is the best cut there is. A type parameter
    list before the first `(` is skipped: in `f<T extends { make(): void }>(arg: T) {` the
    first balanced `)` closes `make()`, not the parameters."""
    depth = sum(line.count("(") - line.count(")") for line in code[i:head])
    angle, seen_paren = 0, depth != 0
    for col, ch in enumerate(code[head]):
        if not seen_paren and ch == "<":
            angle += 1
            continue
        if not seen_paren and ch == ">" and angle and code[head][col - 1:col] != "=":
            angle -= 1
            continue
        if angle:
            continue
        if ch in "()":
            seen_paren = True
            depth += 1 if ch == "(" else -1
            if depth == 0:
                return col + 1
    return code[head].rfind(")") + 1

def is_braced_type(tail):
    """True when tail is `: { ... }` and that one brace group is the whole return type, so the
    body's `{` is on the next line. `: number { return 0 }` is an inline body, not a type."""
    if not re.match(r":\s*\{", tail):
        return False
    depth = 0
    for col, ch in enumerate(tail):
        depth += (ch == "{") - (ch == "}")
        if depth == 0 and ch == "}":
            return col == len(tail) - 1
    return False

def block_end(code, i, head):
    """Index of the line that closes the block opened by the signature at code[i..head], or
    None. A `=>` signature with no `{` (`lazy(() =>`) is closed by its parentheses instead."""
    signature = " ".join(code[i:head + 1])
    open_c, close_c = "{", "}"
    start, first = head, code[head][params_close(code, i, head):]  # braces inside the parameter list are not the body
    if signature.rstrip().endswith("=>"):
        if head + 1 < len(code) and code[head + 1].lstrip().startswith("{"):
            start, first = head + 1, code[head + 1]  # `=>` with the body's `{` on the next line
        else:
            open_c, close_c, start, first = "(", ")", i, code[i]
    else:
        # `f(): { a: string }` with the body's `{` on the next line: the return type's braces
        # balance, so without this the signature line itself would be taken as the whole block.
        tail = first.strip()
        if is_braced_type(tail) and head + 1 < len(code) and code[head + 1].lstrip().startswith("{"):
            start, first = head + 1, code[head + 1]
    depth, opened = 0, False
    for j in range(start, len(code)):
        text = first if j == start else code[j]
        depth += text.count(open_c) - text.count(close_c)
        opened = opened or open_c in text
        if opened and depth <= 0:
            return j
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True); ap.add_argument("--files", required=True); ap.add_argument("--smell", required=True)
    a = ap.parse_args()
    root = pathlib.Path(a.root)
    hits, unread, skipped, unparsed = [], [], [], []
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
        lines = split_lines(source)
        if len(lines) > FILE_MAX:
            hits.append({"file": rel, "line": 1, "endLine": len(lines), "text": f"file is {len(lines)} lines"})
        if rel.lower().endswith(".py"):
            py_hits, parsed = python_hits(rel, source)
            hits += py_hits
            if not parsed:
                unparsed.append(rel)
            continue
        code = split_lines(blank_literals(source))
        i = 0
        while i < len(lines):
            head = signature_end(code, i)
            if head is not None:
                j = block_end(code, i, head)
                if j is not None and j - i + 1 > FUNC_MAX:
                    signature = " ".join(line.strip() for line in lines[i:head + 1])
                    hits.append({"file": rel, "line": i + 1, "endLine": j + 1, "text": f"function spans {j - i + 1} lines{scope_label(enclosing_types(code, i))}: {signature}"})
                    i = j
            i += 1
    notes = [f"{label}: " + ", ".join(paths) for label, paths in (("could not read", unread), ("could not parse, function sizes not measured", unparsed), ("unsupported source", skipped)) if paths]
    status, reason = ("not assessed", "; ".join(notes)) if notes else ("assessed", "")
    print(json.dumps({"status": status, "reason": reason, "hits": sorted(hits, key=lambda h: (h["file"], h["line"]))}))

if __name__ == "__main__":
    main()
