"""S41: file-wide hyper-commenting. A file whose comment lines exceed 45% of its
non-blank lines, with at least 20 non-blank lines, is a hit at line 1."""
import argparse, json, pathlib, re

COMMENT = re.compile(r"^\s*(//|#(?!include|region|endregion|if|else|endif|pragma)|/\*|\*|<!--|--)")
THRESHOLD, MIN_LINES = 0.45, 20

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True); ap.add_argument("--files", required=True); ap.add_argument("--smell", required=True)
    a = ap.parse_args()
    root = pathlib.Path(a.root)
    hits = []
    for rel in pathlib.Path(a.files).read_text(encoding="utf-8").splitlines():
        rel = rel.strip()
        if not rel:
            continue
        text = (root / rel).read_bytes().decode("utf-8", errors="replace")
        lines = [l for l in text.splitlines() if l.strip()]
        if len(lines) < MIN_LINES:
            continue
        ratio = sum(1 for l in lines if COMMENT.match(l)) / len(lines)
        if ratio > THRESHOLD:
            hits.append({"file": rel, "line": 1, "text": f"{ratio:.0%} of {len(lines)} non-blank lines are comments"})
    print(json.dumps({"status": "assessed", "reason": "", "hits": sorted(hits, key=lambda h: h["file"])}))

if __name__ == "__main__":
    main()
