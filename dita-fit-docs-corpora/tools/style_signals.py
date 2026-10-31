"""Count how often Learn style-guide / copilot-instructions rules are broken in a docs repo.

usage: python3 -I tools/style_signals.py REPO_DIR > results/style-REPO.tsv
Scans tracked *.md files. Front matter, fenced code blocks and inline code are removed
before prose rules run, so code samples do not count. Include files (*/includes/*) are
scanned too; root-level files and .github/ are skipped. Output: TSV  rule  files  occurrences  example
"""
import re, subprocess, sys
from collections import defaultdict

repo = sys.argv[1]
files = subprocess.run(["git", "-C", repo, "ls-files", "*.md"], capture_output=True, text=True).stdout.split("\n")
files = [f for f in files if f and "/" in f and not f.startswith(".")]  # content only: skip root files and .github/

FENCE = re.compile(r"^\s*(```|~~~)")
INLINE = re.compile(r"`[^`]*`")
LINK_URL = re.compile(r"\]\([^)]*\)")
HEAD = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
SMALL = {"a", "an", "and", "as", "at", "but", "by", "for", "in", "of", "on", "or", "the", "to", "with", "vs", "from", "into", "via"}

prose_rules = {
    "may-for-possibility": re.compile(r"\b[Mm]ay\b"),
    "etc-or-and-so-on": re.compile(r"\betc\.|\band so on\b"),
    "we-our-authors": re.compile(r"\b(?:We|we|Our|our|us)\b"),
    "you-should": re.compile(r"\b[Yy]ou should\b"),
    "click": re.compile(r"\b[Cc]lick(?:s|ed|ing)?\b"),
    "latin-eg-ie": re.compile(r"\b(?:e\.g\.|i\.e\.)"),
    "please": re.compile(r"\b[Pp]lease\b"),
    "simply-just-easy": re.compile(r"\b(?:simply|easily|just)\b"),
    "non-inclusive-terms": re.compile(r"\b(?:whitelist|blacklist|slave)s?\b", re.I),
    "master-word": re.compile(r"\bmaster\b", re.I),
}
raw_rules = {
    "learn-link-with-locale": re.compile(r"https://learn\.microsoft\.com/[a-z]{2}-[a-z]{2}/"),
    "learn-absolute-link": re.compile(r"https://learn\.microsoft\.com/"),
    "bare-url-not-in-angle-brackets": re.compile(r"(?<![(<\"'])\bhttps?://[^\s)>\]\"']+"),
}
count = defaultdict(int); fcount = defaultdict(set); example = {}
def hit(rule, f, s):
    count[rule] += 1; fcount[rule].add(f); example.setdefault(rule, f"{f}: {s.strip()[:90]}")

for f in files:
    try:
        text = open(f"{repo}/{f}", encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    lines = text.split("\n")
    fm = {}
    i = 0
    if lines and lines[0].strip() == "---":
        for j in range(1, min(len(lines), 200)):
            if lines[j].strip() == "---":
                for l in lines[1:j]:
                    m = re.match(r"^([A-Za-z_.\-]+):\s*(.*)$", l)
                    if m: fm[m.group(1)] = m.group(2).strip().strip("'\"")
                i = j + 1; break
    is_include = "/includes/" in f or fm.get("ms.topic", "").lower() == "include"
    if not is_include:
        hit("ai-usage-present", f, fm.get("ai-usage", "")) if "ai-usage" in fm else None
        if fm.get("ai-usage") == "ai-generated": hit("ai-usage-ai-generated", f, "")
        t = fm.get("title", "")
        if re.match(r"^[A-Z][a-z]+ing\b", t): hit("gerund-title", f, t)
    in_code = False; prev_heading = False; ol_seq = False
    for l in lines[i:]:
        if FENCE.match(l):
            in_code = not in_code; prev_heading = False; continue
        if in_code: continue
        for r, rx in raw_rules.items():
            for _ in rx.finditer(l): hit(r, f, l)
        p = LINK_URL.sub("]", INLINE.sub("", l))
        h = HEAD.match(p)
        if h:
            txt = re.sub(r"<[^>]+>|\[|\]", "", h.group(2)).strip()
            words = [w for w in re.findall(r"[A-Za-z][\w'-]*", txt)]
            if len(h.group(1)) == 1 and re.match(r"^[A-Z][a-z]+ing\b", txt): hit("gerund-h1", f, txt)
            # title case: >=2 later non-small words, all capitalized, at least one is a plain dictionary-like word
            later = [w for w in words[1:] if w.lower() not in SMALL]
            if len(later) >= 2 and all(w[0].isupper() for w in later) and any(w[1:].islower() for w in later):
                hit("title-case-heading", f, txt)
            if prev_heading: hit("consecutive-headings", f, txt)
            prev_heading = True
            continue
        if p.strip():
            prev_heading = False
        if re.match(r"^\s*[2-9]\d*\.\s", p): hit("ordered-list-not-all-1", f, p)
        if re.match(r"^\s*>?\s*\[!", p): continue
        for r, rx in prose_rules.items():
            for _ in rx.finditer(p): hit(r, f, p)

print("rule\tfiles\toccurrences\texample")
print(f"md-files\t{len(files)}\t-\t-")
for r in sorted(count):
    print(f"{r}\t{len(fcount[r])}\t{count[r]}\t{example[r]}")
