"""S30: oversized file or function. File > 800 lines, or a brace-delimited block
opened by a method/function signature spanning > 120 lines, is a hit."""
import argparse, json, pathlib, re

FILE_MAX, FUNC_MAX = 800, 120
SIGNATURE = re.compile(r"^\s*(public|private|protected|internal|static|async|export|function|def)\b[^;=]*\([^;]*\)\s*(\{|=>|:)?\s*$")

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
            if SIGNATURE.match(lines[i]):
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
