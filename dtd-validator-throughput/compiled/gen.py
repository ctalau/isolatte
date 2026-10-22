"""Compile flattened DTDs into Rust and JavaScript validator tables.

usage: python3 -I gen.py DTDMAP.tsv OUT.rs OUT.js

Every content model becomes a minimized DFA over element ids (Glushkov
automaton -> subset construction -> Moore minimization). DFAs, attribute
declarations and attribute lists are deduplicated across all doctype shells,
so the shells share one set of tables and differ only in their per-element
index rows. Element and attribute names map to ids through a generated
`match` (Rust) or a Map (JS)."""
import json
import re
import sys

# ---------------------------------------------------------------- DTD parsing

def declarations(text):
    """Yield the body of every <!...> declaration (quotes respected)."""
    i, n = 0, len(text)
    while True:
        i = text.find("<!", i)
        if i < 0:
            return
        j, q = i + 2, None
        while j < n:
            c = text[j]
            if q:
                if c == q:
                    q = None
            elif c in "\"'":
                q = c
            elif c == ">":
                break
            j += 1
        yield text[i + 2 : j]
        i = j + 1


TOKEN = re.compile(r"\s*(#PCDATA|[()|,?*+]|[^\s()|,?*+]+)")


def tokens(s):
    out, pos = [], 0
    s = s.strip()
    while pos < len(s):
        m = TOKEN.match(s, pos)
        out.append(m.group(1))
        pos = m.end()
    return out


def parse_model(toks):
    """Content model -> tree of ('name', n) | ('pcdata',) | ('seq'|'or', [kids]) | (op, kid)."""
    pos = 0

    def particle():
        nonlocal pos
        t = toks[pos]
        if t == "(":
            pos += 1
            kids, sep = [particle()], None
            while toks[pos] in "|,":
                sep = toks[pos]
                pos += 1
                kids.append(particle())
            assert toks[pos] == ")", toks[pos:]
            pos += 1
            node = ("or" if sep == "|" else "seq", kids)
        elif t == "#PCDATA":
            pos += 1
            node = ("pcdata",)
        else:
            pos += 1
            node = ("name", t)
        if pos < len(toks) and toks[pos] in "?*+":
            node = (toks[pos], node)
            pos += 1
        return node

    tree = particle()
    assert pos == len(toks), toks[pos:]
    return tree


def parse_dtd(text):
    elements, attlists, entities = {}, {}, {}
    for d in declarations(text):
        m = re.match(r"ENTITY\s+([^%\s]\S*)\s+(\"[^\"]*\"|'[^']*')\s*$", d, re.S)
        if m:
            # Internal general entity; first declaration wins (XML 1.0 4.2).
            entities.setdefault(m.group(1), m.group(2)[1:-1])
        elif d.startswith("ENTITY") and not d.startswith("ENTITY %"):
            raise SystemExit(f"external general entities are not supported: {d[:80]}")
        if d.startswith("ELEMENT"):
            _, name, spec = d.split(None, 2)
            spec = spec.strip()
            if spec == "EMPTY":
                elements[name] = ("EMPTY", None)
            elif spec == "ANY":
                elements[name] = ("ANY", None)
            else:
                tree = parse_model(tokens(spec))
                mixed = "#PCDATA" in spec
                elements[name] = ("MIXED" if mixed else "ELEMENT", tree)
        elif d.startswith("ATTLIST"):
            m = re.match(r"ATTLIST\s+(\S+)\s+(\S+)\s+(.*)$", d, re.S)
            elem, attr, rest = m.groups()
            if rest.startswith("("):
                close = rest.index(")")
                atype, enum, rest = "ENUMERATION", rest[1:close].split("|"), rest[close + 1 :]
            elif rest.startswith("NOTATION"):
                close = rest.index(")")
                atype, enum, rest = "NOTATION", rest[rest.index("(") + 1 : close].split("|"), rest[close + 1 :]
            else:
                atype, rest = rest.split(None, 1)
                enum = []
            enum = [v.strip() for v in enum]
            rest = rest.strip()
            if rest.startswith("#REQUIRED"):
                default, value = "REQUIRED", None
            elif rest.startswith("#IMPLIED"):
                default, value = "IMPLIED", None
            elif rest.startswith("#FIXED"):
                default, value = "FIXED", rest[6:].strip()[1:-1]
            else:
                default, value = "DEFAULT", rest[1:-1]
            # First declaration of an attribute wins (XML 1.0 3.3).
            attlists.setdefault(elem, {}).setdefault(attr, (atype, enum, default, value))
    return elements, attlists, expand_entities(entities)


def expand_entities(raw):
    """Replacement text of each entity with character and entity references
    resolved, so the runtime only needs one lookup."""
    ref = re.compile(r"&(#x[0-9A-Fa-f]+|#[0-9]+|[^;\s]+);")
    done = {}

    def expand(name, depth=0):
        if name not in done:
            assert depth < 16, f"entity recursion at {name}"

            def sub(m):
                r = m.group(1)
                if r.startswith("#x"):
                    return chr(int(r[2:], 16))
                if r.startswith("#"):
                    return chr(int(r[1:]))
                return expand(r, depth + 1)
            done[name] = ref.sub(sub, raw[name])
            if "<" in done[name]:
                raise SystemExit(f"entity {name} contains markup: not supported")
        return done[name]

    return {n: expand(n) for n in raw}

# ---------------------------------------------------------------- automata

def glushkov(tree):
    """Return (symbols, first, last, follow, nullable) over positions."""
    symbols, follow = [], []

    def walk(node):
        kind = node[0]
        if kind == "name":
            p = len(symbols)
            symbols.append(node[1])
            follow.append(set())
            return {p}, {p}, False
        if kind == "pcdata":
            return set(), set(), True
        if kind in "?*+":
            f, l, nl = walk(node[1])
            if kind in "*+":
                for p in l:
                    follow[p] |= f
            return f, l, nl or kind in "?*"
        parts = [walk(k) for k in node[1]]
        if kind == "or":
            return (set().union(*(p[0] for p in parts)), set().union(*(p[1] for p in parts)),
                    any(p[2] for p in parts))
        # seq
        first, nullable = set(), True
        for f, _, nl in parts:
            if nullable:
                first |= f
            nullable = nullable and nl
        last, nullable_tail = set(), True
        for _, l, nl in reversed(parts):
            if nullable_tail:
                last |= l
            nullable_tail = nullable_tail and nl
        for i in range(len(parts) - 1):
            for p in parts[i][1]:
                for j in range(i + 1, len(parts)):
                    follow[p] |= parts[j][0]
                    if not parts[j][2]:
                        break
        return first, last, nullable

    first, last, nullable = walk(tree)
    return symbols, first, last, follow, nullable


def dfa(tree):
    """Minimized DFA: (finals: list[bool], trans: list[dict sym->state]), start 0."""
    return minimize(*_positions_dfa(*glushkov(tree)))


def _positions_dfa(symbols, first, last, follow, nullable):
    # Subset construction. State 0 = start; any other state = the set of
    # positions just consumed (a singleton for a deterministic model).
    states, index, trans, finals = [None], {None: 0}, [], []
    k = 0
    while k < len(states):
        cur = states[k]
        nxt_pos = first if cur is None else set().union(*(follow[p] for p in cur))
        finals.append(nullable if cur is None else bool(cur & last))
        moves = {}
        for p in nxt_pos:
            moves.setdefault(symbols[p], set()).add(p)
        out = {}
        for sym, ps in moves.items():
            key = frozenset(ps)
            if key not in index:
                index[key] = len(states)
                states.append(key)
            out[sym] = index[key]
        trans.append(out)
        k += 1
    return finals, trans


def minimize(finals, trans):
    n = len(finals)
    block = [1 if f else 0 for f in finals]
    while True:
        sig = [(block[s], tuple(sorted((a, block[t]) for a, t in trans[s].items()))) for s in range(n)]
        ids = {}
        new = [ids.setdefault(x, len(ids)) for x in sig]
        if len(ids) == len(set(block)):
            break
        block = new
    # Renumber blocks in BFS order from the start state.
    order, seen = [], {}
    queue = [block[0]]
    rep = {}
    for s in range(n):
        rep.setdefault(block[s], s)
    while queue:
        b = queue.pop(0)
        if b in seen:
            continue
        seen[b] = len(order)
        order.append(b)
        for a, t in sorted(trans[rep[b]].items()):
            if block[t] not in seen:
                queue.append(block[t])
    mfinals = [finals[rep[b]] for b in order]
    mtrans = [{a: seen[block[t]] for a, t in trans[rep[b]].items()} for b in order]
    return mfinals, mtrans

# ---------------------------------------------------------------- tables

KIND = {"EMPTY": 1, "ANY": 2, "MIXED": 3, "ELEMENT": 4}
ATYPE = {"CDATA": 0, "ID": 1, "IDREF": 2, "IDREFS": 3, "ENTITY": 4, "ENTITIES": 5,
         "NMTOKEN": 6, "NMTOKENS": 7, "ENUMERATION": 8, "NOTATION": 9}
ADEF = {"IMPLIED": 0, "REQUIRED": 1, "FIXED": 2, "DEFAULT": 3}
NONE16 = 0xFFFF


class Interner:
    def __init__(self):
        self.items, self.index = [], {}

    def __call__(self, x):
        if x not in self.index:
            self.index[x] = len(self.items)
            self.items.append(x)
        return self.index[x]


def build(shells):
    elems, attrs, strs = Interner(), Interner(), Interner()
    enums, adecls, alists = Interner(), Interner(), Interner()
    dfa_cache = {}
    state_final, state_trans = [], []   # global states

    parsed = []
    for pub, path in shells:
        e, a, ents = parse_dtd(open(path, encoding="utf-8").read())
        parsed.append((pub, e, a, ents))
        for name in sorted(e):
            elems(name)
        for el in sorted(a):
            for an in sorted(a[el]):
                attrs(an)
    # Names used in content models but never declared still need ids.
    for _, e, _, _ in parsed:
        for kind, tree in e.values():
            stack = [tree] if tree else []
            while stack:
                n = stack.pop()
                if n[0] == "name":
                    elems(n[1])
                elif n[0] in ("seq", "or"):
                    stack.extend(n[1])
                elif n[0] in "?*+":
                    stack.append(n[1])

    def global_dfa(tree):
        if tree is None:
            tree = ("pcdata",)
        key = repr(tree)
        if key not in dfa_cache:
            finals, trans = dfa(tree)
            sig = (tuple(finals), tuple(tuple(sorted(t.items())) for t in trans))
            if sig in dfa_cache:
                dfa_cache[key] = dfa_cache[sig]
            else:
                base = len(state_final)
                for f, t in zip(finals, trans):
                    state_final.append(f)
                    state_trans.append(sorted((elems(s), base + d) for s, d in t.items()))
                dfa_cache[key] = dfa_cache[sig] = base
        return dfa_cache[key]

    empty_alist = alists(())
    shell_rows = []
    for pub, e, a, ents in parsed:
        kind = [0] * len(elems.items)
        start = [0] * len(elems.items)
        alist = [None] * len(elems.items)
        nreq = [0] * len(elems.items)
        for name, (k, tree) in e.items():
            i = elems.index[name]
            kind[i] = KIND[k]
            start[i] = global_dfa(tree) if k in ("MIXED", "ELEMENT") else 0
        for el, decls in a.items():
            if el not in elems.index:
                continue
            row = []
            for an, (atype, enum, default, value) in decls.items():
                eid = enums(tuple(strs(v) for v in enum)) if enum else NONE16
                fid = strs(value) if default == "FIXED" else NONE16
                row.append(adecls((attrs.index[an], ATYPE[atype], ADEF[default], eid, fid)))
            row.sort(key=lambda d: adecls.items[d][0])
            i = elems.index[el]
            alist[i] = alists(tuple(row))
            nreq[i] = sum(1 for d in row if adecls.items[d][2] == ADEF["REQUIRED"])
        shell_rows.append((pub, kind, start, alist, nreq, sorted(ents.items())))
    return dict(elems=elems.items, attrs=attrs.items, strs=strs.items, enums=enums.items,
                adecls=adecls.items, alists=alists.items, empty_alist=empty_alist,
                state_final=state_final, state_trans=state_trans, shells=shell_rows)


def flat_offsets(lists):
    off, flat = [0], []
    for l in lists:
        flat.extend(l)
        off.append(len(flat))
    return off, flat

# ---------------------------------------------------------------- emitters

def rust_str(s):
    return '"' + "".join(c if c.isascii() and c.isprintable() and c not in '"\\' else "\\u{%x}" % ord(c)
                         for c in s) + '"'


def rust_bytes(s):
    return 'b"' + "".join(c if c.isalnum() or c in ":-._" else "\\x%02x" % b
                          for c, b in ((ch, ord(ch)) for ch in s)) + '"' if s.isascii() else \
        "&[" + ",".join(str(b) for b in s.encode()) + "]"


def arr(name, ty, xs, per_line=24):
    body = ",\n".join(",".join(str(int(x)) for x in xs[i:i + per_line]) for i in range(0, len(xs), per_line))
    return f"pub static {name}: [{ty}; {len(xs)}] = [\n{body}\n];\n"


def emit_rust(t, out):
    w = ["// @generated by compiled/gen.py from the flattened DITA DTDs. Do not edit.\n",
         f"pub const NONE: u16 = {NONE16};\n",
         "pub const ELEM_NAMES: &[&str] = &[" + ",".join(json.dumps(n) for n in t["elems"]) + "];\n",
         "pub const ATTR_NAMES: &[&str] = &[" + ",".join(json.dumps(n) for n in t["attrs"]) + "];\n",
         "pub const STRS: &[&[u8]] = &[" + ",".join(rust_bytes(s) for s in t["strs"]) + "];\n"]
    for fn, names in (("elem_id", t["elems"]), ("attr_id", t["attrs"])):
        w.append(f"#[inline]\npub fn {fn}(name: &[u8]) -> u16 {{\n    match name {{\n")
        for i, n in enumerate(names):
            w.append(f"        {rust_bytes(n)} => {i},\n")
        w.append("        _ => NONE,\n    }\n}\n")
    eoff, eflat = flat_offsets(t["enums"])
    w += [arr("ENUM_OFF", "u32", eoff), arr("ENUM_VALS", "u16", eflat)]
    ad = t["adecls"]
    w += [arr("AD_ATTR", "u16", [d[0] for d in ad]), arr("AD_TYPE", "u8", [d[1] for d in ad]),
          arr("AD_DEFAULT", "u8", [d[2] for d in ad]), arr("AD_ENUM", "u16", [d[3] for d in ad]),
          arr("AD_FIXED", "u16", [d[4] for d in ad])]
    loff, lflat = flat_offsets(t["alists"])
    w += [arr("ALIST_OFF", "u32", loff), arr("ALIST", "u16", lflat)]
    toff, tflat = flat_offsets(t["state_trans"])
    w += ["pub static STATE_FINAL: [bool; %d] = [%s];\n" % (
              len(t["state_final"]), ",".join("true" if f else "false" for f in t["state_final"])),
          arr("TRANS_OFF", "u32", toff), arr("TRANS_SYM", "u16", [s for s, _ in tflat]),
          arr("TRANS_NEXT", "u32", [d for _, d in tflat])]
    w.append("pub struct Shell {\n    pub public_id: &'static str,\n    pub kind: &'static [u8],\n"
             "    pub start: &'static [u32],\n    pub alist: &'static [u16],\n    pub nreq: &'static [u8],\n"
             "    /// Internal general entities (name, fully expanded replacement text), sorted.\n"
             "    pub entities: &'static [(&'static str, &'static str)],\n}\n")
    for i, (pub, kind, start, alist, nreq, ents) in enumerate(t["shells"]):
        alist = [t["empty_alist"] if a is None else a for a in alist]
        w += [arr(f"S{i}_KIND", "u8", kind), arr(f"S{i}_START", "u32", start),
              arr(f"S{i}_ALIST", "u16", alist), arr(f"S{i}_NREQ", "u8", nreq),
              f"pub static S{i}_ENTITIES: &[(&str, &str)] = &["
              + ",".join(f"({rust_str(n)},{rust_str(v)})" for n, v in ents) + "];\n"]
    w.append("pub static SHELLS: &[Shell] = &[\n")
    for i, (pub, *_rest) in enumerate(t["shells"]):
        w.append(f"    Shell {{ public_id: {json.dumps(pub)}, kind: &S{i}_KIND, start: &S{i}_START, "
                 f"alist: &S{i}_ALIST, nreq: &S{i}_NREQ, entities: S{i}_ENTITIES }},\n")
    w.append("];\n")
    open(out, "w").write("".join(w))


def emit_js(t, out):
    def ta(ty, xs):
        return f"new {ty}({json.dumps(list(map(int, xs)), separators=(',', ':'))})"
    eoff, eflat = flat_offsets(t["enums"])
    loff, lflat = flat_offsets(t["alists"])
    toff, tflat = flat_offsets(t["state_trans"])
    ad = t["adecls"]
    w = ["// @generated by compiled/gen.py from the flattened DITA DTDs. Do not edit.\n'use strict';\n",
         f"const ELEM_NAMES = {json.dumps(t['elems'])};\n",
         f"const ATTR_NAMES = {json.dumps(t['attrs'])};\n",
         "exports.NONE = 0xffff;\nexports.ELEM_NAMES = ELEM_NAMES;\nexports.ATTR_NAMES = ATTR_NAMES;\n",
         "exports.ELEM_ID = new Map(ELEM_NAMES.map((n, i) => [n, i]));\n",
         "exports.ATTR_ID = new Map(ATTR_NAMES.map((n, i) => [n, i]));\n",
         f"exports.STRS = {json.dumps(t['strs'])};\n",
         f"exports.ENUM_OFF = {ta('Uint32Array', eoff)};\n",
         f"exports.ENUM_VALS = {ta('Uint16Array', eflat)};\n",
         f"exports.AD_ATTR = {ta('Uint16Array', [d[0] for d in ad])};\n",
         f"exports.AD_TYPE = {ta('Uint8Array', [d[1] for d in ad])};\n",
         f"exports.AD_DEFAULT = {ta('Uint8Array', [d[2] for d in ad])};\n",
         f"exports.AD_ENUM = {ta('Uint16Array', [d[3] for d in ad])};\n",
         f"exports.AD_FIXED = {ta('Uint16Array', [d[4] for d in ad])};\n",
         f"exports.ALIST_OFF = {ta('Uint32Array', loff)};\n",
         f"exports.ALIST = {ta('Uint16Array', lflat)};\n",
         f"exports.STATE_FINAL = {ta('Uint8Array', t['state_final'])};\n",
         f"exports.TRANS_OFF = {ta('Uint32Array', toff)};\n",
         f"exports.TRANS_SYM = {ta('Uint16Array', [s for s, _ in tflat])};\n",
         f"exports.TRANS_NEXT = {ta('Uint32Array', [d for _, d in tflat])};\n",
         "exports.SHELLS = [\n"]
    for pub, kind, start, alist, nreq, ents in t["shells"]:
        alist = [t["empty_alist"] if a is None else a for a in alist]
        w.append(f"  {{ publicId: {json.dumps(pub)}, kind: {ta('Uint8Array', kind)}, "
                 f"start: {ta('Uint32Array', start)}, alist: {ta('Uint16Array', alist)}, "
                 f"nreq: {ta('Uint8Array', nreq)}, entities: {json.dumps(dict(ents))} }},\n")
    w.append("];\n")
    open(out, "w").write("".join(w))


if __name__ == "__main__":
    shells = [l.rstrip("\n").split("\t") for l in open(sys.argv[1]) if "\t" in l]
    t = build(shells)
    emit_rust(t, sys.argv[2])
    emit_js(t, sys.argv[3])
    ntrans = sum(len(x) for x in t["state_trans"])
    print(f"shells={len(shells)} elements={len(t['elems'])} attributes={len(t['attrs'])} "
          f"attr_decls={len(t['adecls'])} attr_lists={len(t['alists'])} enums={len(t['enums'])} "
          f"dfa_states={len(t['state_final'])} transitions={ntrans}")
