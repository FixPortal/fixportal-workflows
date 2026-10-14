"""S41: file-wide hyper-commenting. A source file whose comment lines exceed 45% of its
non-blank lines, with at least 20 non-blank lines, is a hit spanning the whole file
(line 1 .. endLine). Source extensions only: in Markdown the comment pattern reads
headings, bullets and `---` rules as comments."""
import argparse, json, pathlib, re

DIRECTIVE = r"(?:include|region|endregion|ifdef|ifndef|if|else|elif|endif|pragma|define|undef|error|warning|line)\b"
# '#' + directive or Rust attribute is code. C-family sources may put whitespace after the '#'; elsewhere
# '# define the thing' is prose.
COMMENT = re.compile(rf"^\s*(//|#(?!{DIRECTIVE}|\[|!\[)|/\*|\*|<!--|--)")
C_COMMENT = re.compile(rf"^\s*(//|#(?![ \t]*{DIRECTIVE}|\[|!\[)|/\*|\*|<!--|--)")
C_FAMILY = (".c", ".cpp", ".cs")
SOURCE = (".cs", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".ps1", ".psm1",
          ".go", ".java", ".rs", ".rb", ".kt", ".swift", ".cpp", ".c")
THRESHOLD, MIN_LINES = 0.45, 20

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
        all_lines = text.splitlines()
        lines = [l for l in all_lines if l.strip()]
        if len(lines) < MIN_LINES:
            continue
        comment = C_COMMENT if rel.lower().endswith(C_FAMILY) else COMMENT
        ratio = sum(1 for l in lines if comment.match(l)) / len(lines)
        if ratio > THRESHOLD:
            hits.append({"file": rel, "line": 1, "endLine": len(all_lines), "text": f"{ratio:.0%} of {len(lines)} non-blank lines are comments"})
    status, reason = ("not assessed", "could not read " + ", ".join(unread)) if unread else ("assessed", "")
    print(json.dumps({"status": status, "reason": reason, "hits": sorted(hits, key=lambda h: h["file"])}))

if __name__ == "__main__":
    main()
