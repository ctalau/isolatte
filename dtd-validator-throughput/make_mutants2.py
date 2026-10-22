"""Second negative corpus: DTD violations aimed at the checks a validator
compiled from the DTD has to implement itself (content-model completion,
character data in element-only content, ID uniqueness, NMTOKEN syntax,
EMPTY, #REQUIRED, #FIXED, entities, DOCTYPE/root mismatch), plus "ok-"
positive controls that must stay valid.

usage: python3 -I make_mutants2.py FILE-LIST OUT-DIR [PER-KIND]
Writes OUT-DIR/<kind>/<n>.dita and OUT-DIR/files.txt."""
import os
import re
import sys

ROOT_ID = re.compile(r'<topic\b[^>]*\bid="([^"]+)"')


def missing_title(s):
    # <topic> requires <title> first: drop the root's title.
    return re.sub(r"<title>.*?</title>", "", s, count=1, flags=re.S)


def stray_text(s):
    # <body> has element-only content.
    return s.replace("<body>", "<body>stray text", 1)


def bad_nmtoken(s):
    # @id on <p> is an NMTOKEN, which cannot contain a space.
    return s.replace("<p>", '<p id="two words">', 1)


def duplicate_id(s):
    # @id on <topic> is an ID; a nested topic reuses the root's.
    m = ROOT_ID.search(s)
    i = s.rfind("</topic>")
    return s[:i] + f'<topic id="{m.group(1)}"><title>x</title></topic>' + s[i:]


def empty_with_content(s):
    # <colspec> is EMPTY.
    return re.sub(r"<colspec\b([^>]*?)/>", r"<colspec\1>x</colspec>", s, count=1)


def missing_required(s):
    # @cols on <tgroup> is #REQUIRED.
    return re.sub(r'(<tgroup\b[^>]*?)\s+cols="[^"]*"', r"\1", s, count=1)


def bad_fixed(s):
    # @xml:space on <codeblock> is #FIXED "preserve".
    return s.replace("<codeblock", '<codeblock xml:space="default"', 1)


def undefined_entity(s):
    # (&nbsp; would be valid: DITA's topic.mod declares it.)
    return s.replace("<p>", "<p>&nbspx;", 1)


def declared_entity_in_element_content(s):
    # &nbsp; is declared, but U+00A0 is not whitespace, so it is character
    # data -- not allowed directly in <body>.
    return s.replace("<body>", "<body>&nbsp;", 1)


def root_mismatch(s):
    # DOCTYPE names <concept> but the root is <topic> (still the topic DTD).
    return s.replace("<!DOCTYPE topic", "<!DOCTYPE concept", 1)


def text_in_empty_ws(s):
    # Even whitespace is not allowed inside an EMPTY element.
    return re.sub(r"<colspec\b([^>]*?)/>", r"<colspec\1> </colspec>", s, count=1)


# Positive controls ("ok-" kinds): edits that keep the topic VALID, so every
# validator must accept them.
def ok_nbsp_in_p(s):
    return s.replace("<p>", "<p>&nbsp;", 1)


def ok_explicit_fixed(s):
    return s.replace("<codeblock", '<codeblock xml:space="preserve"', 1)


KINDS = {
    "ok-nbsp-in-p": (ok_nbsp_in_p, lambda s: "<p>" in s and "LIGHTWEIGHT" not in s),
    "ok-explicit-fixed": (ok_explicit_fixed, lambda s: "<codeblock" in s and "xml:space" not in s
                          and "LIGHTWEIGHT" not in s),
    "missing-title": (missing_title, lambda s: "<title>" in s and "DTD DITA Topic//" in s),
    "stray-text": (stray_text, lambda s: "<body>" in s),
    "bad-nmtoken": (bad_nmtoken, lambda s: "<p>" in s and "LIGHTWEIGHT" not in s),
    "duplicate-id": (duplicate_id, lambda s: "DTD DITA Topic//" in s and ROOT_ID.search(s) and "</topic>" in s),
    "empty-with-content": (empty_with_content, lambda s: re.search(r"<colspec\b[^>]*/>", s)),
    "missing-required": (missing_required, lambda s: re.search(r'<tgroup\b[^>]*\scols="', s)),
    "bad-fixed": (bad_fixed, lambda s: "<codeblock" in s and "LIGHTWEIGHT" not in s),
    "undefined-entity": (undefined_entity, lambda s: "<p>" in s),
    "nbsp-in-body": (declared_entity_in_element_content, lambda s: "<body>" in s and "LIGHTWEIGHT" not in s),
    "root-mismatch": (root_mismatch, lambda s: "<!DOCTYPE topic" in s and "DTD DITA Topic//" in s),
    "ws-in-empty": (text_in_empty_ws, lambda s: re.search(r"<colspec\b[^>]*/>", s)),
}

files, out = open(sys.argv[1]).read().split(), sys.argv[2]
per_kind = int(sys.argv[3]) if len(sys.argv) > 3 else 30
texts = [(f, open(f, encoding="utf-8").read()) for f in files]
listing = []
for kind, (mutate, applies) in KINDS.items():
    cands = [(f, s) for f, s in texts if applies(s)]
    os.makedirs(os.path.join(out, kind), exist_ok=True)
    for n, (f, s) in enumerate(cands[:: max(1, len(cands) // per_kind)][:per_kind]):
        m = mutate(s)
        assert m != s, (kind, f)
        path = os.path.join(out, kind, f"{n:03d}.dita")
        open(path, "w", encoding="utf-8").write(m)
        listing.append(path)
open(os.path.join(out, "files.txt"), "w").write("\n".join(listing) + "\n")
print(f"{len(listing)} mutants in {len(KINDS)} kinds")
