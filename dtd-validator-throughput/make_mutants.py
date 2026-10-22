"""Make deliberately invalid copies of DITA topics, one DTD violation each.

usage: python3 -I make_mutants.py FILE-LIST OUT-DIR [PER-KIND]
Writes OUT-DIR/<kind>/<n>.dita and OUT-DIR/files.txt (all mutants)."""
import os
import sys

KINDS = {
    # element not declared anywhere in the DTD
    "undeclared-element": lambda s: s.replace("<p>", "<p><bogus/>", 1),
    # declared element in a place its parent's content model forbids
    "content-model": lambda s: s.replace("<p>", "<p><section/>", 1),
    # second <title> where the topic model allows exactly one
    "duplicate-title": lambda s: s.replace("</title>", "</title><title>x</title>", 1),
    # attribute not declared for the element
    "undeclared-attribute": lambda s: s.replace("<p>", '<p foo="bar">', 1),
    # value outside a declared enumeration
    "bad-enum-value": lambda s: s.replace("<p>", '<p translate="maybe">', 1),
}

files, out = open(sys.argv[1]).read().split(), sys.argv[2]
per_kind = int(sys.argv[3]) if len(sys.argv) > 3 else 50
candidates = []
for f in files:
    s = open(f, encoding="utf-8").read()
    # Only full DITA topics (not LwDITA, whose <p> differs) with a body paragraph.
    if "<p>" in s and "</title>" in s and "DTD DITA" in s and "LIGHTWEIGHT" not in s:
        candidates.append((f, s))
listing = []
for kind, mutate in KINDS.items():
    os.makedirs(os.path.join(out, kind), exist_ok=True)
    for n, (f, s) in enumerate(candidates[:: max(1, len(candidates) // per_kind)][:per_kind]):
        path = os.path.join(out, kind, f"{n:03d}.dita")
        open(path, "w", encoding="utf-8").write(mutate(s))
        listing.append(path)
open(os.path.join(out, "files.txt"), "w").write("\n".join(listing) + "\n")
print(f"{len(listing)} mutants from {len(candidates)} candidate topics")
