"""S41: file-wide hyper-commenting. A source file whose comment lines exceed 45% of its
non-blank lines, with at least 20 non-blank lines, is a hit spanning the whole file
(line 1 .. endLine). Source extensions only: in Markdown the comment pattern reads
headings, bullets and `---` rules as comments."""
import argparse, json, pathlib, re

DIRECTIVE = r"(?:include|region|endregion|ifdef|ifndef|if|else|elif|endif|pragma|define|undef|error|warning|line)\b"
# '#' + directive or Rust attribute is code. C-family sources may put whitespace after the '#'; elsewhere
# '# define the thing' is prose.
# No SOURCE language comments with `--` or `<!--`, and a bare leading `*` is a comment only
# inside an open /* block (see comment_count): otherwise `*args,` and `--depth;` read as prose.
COMMENT = re.compile(rf"^\s*(//|#(?!{DIRECTIVE}|\[|!\[)|/\*)")
C_COMMENT = re.compile(rf"^\s*(//|#(?![ \t]*{DIRECTIVE}|\[|!\[)|/\*)")
C_FAMILY = (".c", ".cpp", ".cs")
SOURCE = (".cs", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".ps1", ".psm1",
          ".go", ".java", ".rs", ".rb", ".kt", ".swift", ".cpp", ".c")
THRESHOLD, MIN_LINES = 0.45, 20

def split_lines(text):
    """Lines as git counts them: only \\n ends one (a CR before it is dropped). str.splitlines()
    also breaks on \\v, \\f, \\x1c-\\x1e, NEL, U+2028/9 and a lone CR, which would shift every
    reported line number away from the PR diff's."""
    lines = [l[:-1] if l.endswith("\r") else l for l in text.split("\n")]
    if lines and lines[-1] == "":
        lines.pop()
    return lines

PS_DIRECTIVE = re.compile(rf"#(?:{DIRECTIVE}|\[|!\[)")

def ps_hash_comments(line, i):
    """True when the `#` at line[i] starts a line comment. pwsh 7 reads `a#b` as one argument word but
    `$y#1` as the variable `$y` and then a comment, and `;#c`, `)#c` and `"a"#c` as comments."""
    before = line[:i]
    return not before or not (before[-1].isalnum() or before[-1] in "_-.") or re.search(r"\$[\w:]+$", before) is not None

def ps_comment_count(lines):
    """Lines holding a comment and no code, read as pwsh's tokenizer reads them: quoted strings and
    here-strings stay open across lines, a `<# ... #>` block may open or close anywhere outside one, and
    `#` starts a line comment at a token boundary. A `#region`-style directive line is code, as for
    every other language here."""
    count, state = 0, None  # None, "block", a quote, or "@'" / '@"' for a here-string
    for line in lines:
        code = comment = False
        i = 0
        if state in ("@'", '@"'):
            if not line.startswith(state[1] + "@"):
                continue  # here-string content is a string: code, never a comment
            state, i, code = None, 2, True
        while i < len(line):
            if state == "block":
                comment = True
                end = line.find("#>", i)
                if end < 0:
                    break
                state, i = None, end + 2
                continue
            c = line[i]
            if state:  # inside a quoted string
                code = True
                if state == '"' and c == "`":
                    i += 2
                    continue
                if c == state:
                    if line[i + 1:i + 2] == state:
                        i += 2  # a doubled quote is the quote itself
                        continue
                    state = None
                i += 1
                continue
            if c.isspace():
                i += 1
            elif line.startswith("<#", i):
                state, i, comment = "block", i + 2, True
            elif c == "#" and ps_hash_comments(line, i):
                if PS_DIRECTIVE.match(line, i):
                    code = True
                else:
                    comment = True
                break
            elif line.startswith(("@'", '@"'), i) and not line[i + 2:].strip():
                state, code = line[i:i + 2], True
                break
            else:
                code = True
                if c in "'\"":
                    state = c
                i += 1
        if comment and not code:
            count += 1
    return count

def comment_count(lines, pattern, ps_blocks=False):
    """ps_blocks: a PowerShell file, read by ps_comment_count."""
    if ps_blocks:
        return ps_comment_count(lines)
    count, in_block = 0, False
    for line in lines:
        if in_block:
            count += 1
            in_block = "*/" not in line
        elif pattern.match(line):
            count += 1
            stripped = line.lstrip()
            in_block = stripped.startswith("/*") and "*/" not in stripped
    return count

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True); ap.add_argument("--files", required=True); ap.add_argument("--smell", required=True)
    a = ap.parse_args()
    root = pathlib.Path(a.root)
    hits, unread = [], []
    for rel in pathlib.Path(a.files).read_text(encoding="utf-8").splitlines():
        rel = rel.strip()
        if not rel or not rel.lower().endswith(SOURCE):
            continue
        path = root / rel
        if not path.is_file():
            continue  # a gitlink / submodule path lists as a directory
        try:
            text = path.read_bytes().decode("utf-8", errors="replace")
        except OSError:
            unread.append(rel)
            continue
        all_lines = split_lines(text)
        lines = [l for l in all_lines if l.strip()]
        if len(lines) < MIN_LINES:
            continue
        comment = C_COMMENT if rel.lower().endswith(C_FAMILY) else COMMENT
        ratio = comment_count(lines, comment, rel.lower().endswith((".ps1", ".psm1"))) / len(lines)
        if ratio > THRESHOLD:
            hits.append({"file": rel, "line": 1, "endLine": len(all_lines), "text": f"{ratio:.0%} of {len(lines)} non-blank lines are comments"})
    status, reason = ("not assessed", "could not read " + ", ".join(unread)) if unread else ("assessed", "")
    print(json.dumps({"status": status, "reason": reason, "hits": sorted(hits, key=lambda h: h["file"])}))

if __name__ == "__main__":
    main()
