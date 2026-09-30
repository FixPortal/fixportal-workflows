"""S30: oversized file or function. File > 800 lines, or a function spanning > 120 lines,
is a hit: a brace-delimited block opened by a method/function signature, or a Python def
measured by indentation. Brace counting never sees a Python body open, so without the
indentation path it scanned to end of file for every def and flagged none."""
import argparse, json, pathlib, re

FILE_MAX, FUNC_MAX = 800, 120
SIGNATURE = re.compile(r"^\s*(public|private|protected|internal|static|async|export|function|def)\b[^;=]*\([^;]*\)\s*(\{|=>|:)?\s*$")
PY_DEF = re.compile(r"^\s*(async\s+)?def\s")

def indent_of(line):
    return len(line) - len(line.lstrip())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True); ap.add_argument("--files", required=True); ap.add_argument("--smell", required=True)
    a = ap.parse_args()
    root = pathlib.Path(a.root)
    hits = []
    for rel in pathlib.Path(a.files).read_text(encoding="utf-8").splitlines():
        rel = rel.strip()
        if not rel or not rel.endswith((".cs", ".ts", ".tsx", ".js", ".jsx", ".py")):
            continue
        lines = (root / rel).read_bytes().decode("utf-8", errors="replace").splitlines()
        if len(lines) > FILE_MAX:
            hits.append({"file": rel, "line": 1, "text": f"file is {len(lines)} lines"})
        i = 0
        while i < len(lines):
            if rel.endswith(".py") and PY_DEF.match(lines[i]):
                # The body is every following line indented deeper, blank lines included;
                # trailing blanks belong to whatever comes next.
                j = i + 1
                while j < len(lines) and (not lines[j].strip() or indent_of(lines[j]) > indent_of(lines[i])):
                    j += 1
                while j > i + 1 and not lines[j - 1].strip():
                    j -= 1
                if j - i > FUNC_MAX:
                    hits.append({"file": rel, "line": i + 1, "text": f"function spans {j - i} lines: {lines[i].strip()[:80]}"})
            elif SIGNATURE.match(lines[i]):
                depth, j, opened = 0, i, False
                while j < len(lines):
                    depth += lines[j].count("{") - lines[j].count("}")
                    opened = opened or "{" in lines[j]
                    if opened and depth <= 0:
                        break
                    j += 1
                if opened and j - i + 1 > FUNC_MAX:
                    hits.append({"file": rel, "line": i + 1, "text": f"function spans {j - i + 1} lines: {lines[i].strip()[:80]}"})
                    i = j
            i += 1
    print(json.dumps({"status": "assessed", "reason": "", "hits": sorted(hits, key=lambda h: (h["file"], h["line"]))}))

if __name__ == "__main__":
    main()
