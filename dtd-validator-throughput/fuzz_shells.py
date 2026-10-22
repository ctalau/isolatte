"""Differential test corpus for every compiled DTD shell.

usage: python3 -I fuzz_shells.py DTDMAP.tsv OUT-DIR [VALID] [MUTANTS] [SEED]

For each public id in DTDMAP, generates VALID random documents by walking the
shell's own content models (respecting #REQUIRED/#FIXED attributes and
enumerations), and MUTANTS random edits of them (drop / duplicate / swap a
child, stray text, bad attribute value, undeclared attribute or element,
missing required attribute). The mutants are *not* assumed invalid: ground
truth comes from stock xmllint (see fuzz_compare.sh). Writes
OUT-DIR/<n>-<kind>.dita and OUT-DIR/files.txt."""
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "compiled"))
import gen  # noqa: E402

# The DOCTYPE/root element of each DITA-OT shell, by DTD file name.
ROOTS = {
    "topic": "topic", "basetopic": "topic", "concept": "concept", "task": "task",
    "generalTask": "task", "machineryTask": "task", "reference": "reference",
    "glossary": "glossentry", "glossentry": "glossentry", "glossgroup": "glossgroup",
    "troubleshooting": "troubleshooting", "ditabase": "dita", "map": "map", "basemap": "map",
    "bookmap": "bookmap", "classifyMap": "map", "subjectScheme": "subjectScheme",
    "learningAssessment": "learningAssessment", "learningContent": "learningContent",
    "learningOverview": "learningOverview", "learningPlan": "learningPlan",
    "learningSummary": "learningSummary", "learningBookmap": "bookmap",
    "lw-topic": "topic", "lw-map": "map",
    "learningMap": "map", "learningGroupMap": "learningGroupMap", "learningObjectMap": "learningObjectMap",
}
MAX_DEPTH = 7
MAX_NODES = 250
INF = float("inf")


def root_for(path):
    base = os.path.basename(path)[:-4].split("_")[-1]
    return ROOTS[base]


class Shell:
    def __init__(self, path):
        self.elements, self.attlists, self.entities = gen.parse_dtd(open(path, encoding="utf-8").read())
        self.cost = self._min_costs()

    def _min_costs(self):
        """Smallest number of elements a valid instance of each element needs."""
        cost = {n: INF for n in self.elements}

        def model_cost(node):
            k = node[0]
            if k == "name":
                return cost.get(node[1], INF)
            if k == "pcdata":
                return 0
            if k in "?*":
                return 0
            if k == "+":
                return model_cost(node[1])
            parts = [model_cost(c) for c in node[1]]
            return sum(parts) if k == "seq" else min(parts)

        changed = True
        while changed:
            changed = False
            for n, (kind, tree) in self.elements.items():
                c = 1 + (model_cost(tree) if kind == "ELEMENT" else 0)
                if c < cost[n]:
                    cost[n], changed = c, True
        self.model_cost = model_cost
        return cost


class Doc:
    def __init__(self, shell, rng):
        self.s, self.rng, self.nodes, self.ids = shell, rng, 0, 0

    def value(self, atype, enum, default, fixed):
        if default == "FIXED":
            return fixed
        if atype in ("ENUMERATION", "NOTATION"):
            return self.rng.choice(enum)
        if atype == "ID":
            self.ids += 1
            return f"id{self.ids}"
        if atype == "NMTOKEN":
            return self.rng.choice(["tok", "a-1", "x.y"])
        if atype == "NMTOKENS":
            return "a b"
        if atype in ("IDREF", "IDREFS"):
            return "id1"
        return self.rng.choice(["text", "a b", "1"])

    def attrs(self, name):
        out = {}
        for an, (atype, enum, default, fixed) in self.s.attlists.get(name, {}).items():
            if atype in ("ENTITY", "ENTITIES"):
                continue
            want = default == "REQUIRED" or an.startswith("xmlns") and default == "FIXED" \
                or self.rng.random() < 0.08
            if want:
                out[an] = self.value(atype, enum, default, fixed)
        return out

    def particle(self, node, depth):
        """Child element names for a content-model particle."""
        k, rng, shallow = node[0], self.rng, depth < MAX_DEPTH and self.nodes < MAX_NODES
        if k == "name":
            return [node[1]]
        if k == "pcdata":
            return []
        if k in "?*+":
            lo = 1 if k == "+" else 0
            hi = (1 if k == "?" else 3) if shallow else lo
            return [c for _ in range(rng.randint(lo, max(lo, hi))) for c in self.particle(node[1], depth)]
        if k == "seq":
            return [c for p in node[1] for c in self.particle(p, depth)]
        options = node[1]
        if not shallow:
            best = min(self.s.model_cost(o) for o in options)
            options = [o for o in options if self.s.model_cost(o) == best]
        return self.particle(rng.choice(options), depth)

    def element(self, name, depth):
        self.nodes += 1
        kind, tree = self.s.elements[name]
        node = {"name": name, "attrs": self.attrs(name), "kids": []}
        if kind == "ELEMENT":
            node["kids"] = [self.element(c, depth + 1) for c in self.particle(tree, depth)]
        elif kind == "MIXED":
            allowed = sorted({c for c in self.particle(("*", tree), 0)} if tree else set())
            allowed = [c for c in allowed if self.s.cost.get(c, INF) < INF]
            kids = ["text"]
            if depth < MAX_DEPTH and self.nodes < MAX_NODES and allowed:
                for _ in range(self.rng.randint(0, 2)):
                    kids.append(self.element(self.rng.choice(allowed), depth + 1))
                    kids.append("more text")
            node["kids"] = kids
        elif kind == "ANY":
            node["kids"] = ["any text"]
        return node


def walk(node):
    yield node
    for k in node["kids"]:
        if isinstance(k, dict):
            yield from walk(k)


def mutate(shell, root, rng):
    """One random edit; returns its kind (validity is decided by xmllint)."""
    elems = [n for n in walk(root)]
    target = rng.choice(elems)
    el_kids = [i for i, k in enumerate(target["kids"]) if isinstance(k, dict)]
    kinds = ["undeclared-element", "stray-text", "bad-attr-value", "undeclared-attr"]
    if el_kids:
        kinds += ["drop-child", "dup-child", "swap-children"]
    decls = shell.attlists.get(target["name"], {})
    if any(d[2] == "REQUIRED" for d in decls.values()):
        kinds.append("drop-required-attr")
    kind = rng.choice(kinds)
    if kind == "undeclared-element":
        target["kids"].insert(rng.randint(0, len(target["kids"])), {"name": "bogus", "attrs": {}, "kids": []})
    elif kind == "stray-text":
        target["kids"].insert(rng.randint(0, len(target["kids"])), "stray")
    elif kind == "bad-attr-value":
        typed = [a for a, d in decls.items() if d[0] in ("ENUMERATION", "NMTOKEN", "ID") or d[2] == "FIXED"]
        if typed:
            target["attrs"][rng.choice(typed)] = "not valid!"
        else:
            kind = "undeclared-attr"
    if kind == "undeclared-attr":
        target["attrs"]["bogus-attr"] = "x"
    elif kind == "drop-child":
        del target["kids"][rng.choice(el_kids)]
    elif kind == "dup-child":
        i = rng.choice(el_kids)
        target["kids"].insert(i, target["kids"][i])
    elif kind == "swap-children":
        i = rng.choice(el_kids)
        j = rng.choice(el_kids)
        target["kids"][i], target["kids"][j] = target["kids"][j], target["kids"][i]
    elif kind == "drop-required-attr":
        req = [a for a, d in decls.items() if d[2] == "REQUIRED" and a in target["attrs"]]
        if req:
            del target["attrs"][rng.choice(req)]
    return kind


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;")


def serialize(node, out):
    if isinstance(node, str):
        out.append(esc(node))
        return
    attrs = "".join(f' {k}="{esc(v)}"' for k, v in node["attrs"].items())
    if not node["kids"]:
        out.append(f"<{node['name']}{attrs}/>")
        return
    out.append(f"<{node['name']}{attrs}>")
    for k in node["kids"]:
        serialize(k, out)
    out.append(f"</{node['name']}>")


def main():
    dtdmap, out_dir = sys.argv[1:3]
    n_valid = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    n_mut = int(sys.argv[4]) if len(sys.argv) > 4 else 6
    rng = random.Random(int(sys.argv[5]) if len(sys.argv) > 5 else 1)
    os.makedirs(out_dir, exist_ok=True)
    shells, listing, n = {}, [], 0
    for line in open(dtdmap):
        pub, path = line.rstrip("\n").split("\t")
        if path not in shells:
            shells[path] = Shell(path)
        shell, root_name = shells[path], root_for(path)
        assert root_name in shell.elements, (path, root_name)
        for i in range(n_valid + n_mut):
            d = Doc(shell, rng)
            root = d.element(root_name, 0)
            kind = "valid" if i < n_valid else mutate(shell, root, rng)
            body = []
            serialize(root, body)
            text = (f'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE {root_name} PUBLIC "{pub}" '
                    f'"{root_name}.dtd">\n{"".join(body)}\n')
            n += 1
            f = os.path.join(out_dir, f"{n:05d}-{kind}.dita")
            open(f, "w", encoding="utf-8").write(text)
            listing.append(f)
    open(os.path.join(out_dir, "files.txt"), "w").write("\n".join(listing) + "\n")
    print(f"{len(listing)} documents for {sum(1 for _ in open(dtdmap))} public ids / {len(shells)} shells")


main()
