"""Build the single-file browser validator page.

usage: python3 -I build_page.py TEMPLATE.html VALIDATOR.wasm DTDMAP.tsv OUT.html
Replaces the __WASM_BASE64__ placeholder in the template with the wasm build
of compiled/rust (see `cargo build --lib --target wasm32-unknown-unknown`),
and __SHELLS_JSON__ with the compiled shells' public ids, each as
[public id, shell name, DITA version group]."""
import base64
import json
import sys


def describe(pub):
    """'-//OASIS//DTD DITA 2.x Learning Plan//EN' -> ('Learning Plan', 'DITA 2.0')."""
    name = pub.removeprefix("-//OASIS//DTD ").removesuffix("//EN")
    if name.startswith("LIGHTWEIGHT DITA "):
        return name.removeprefix("LIGHTWEIGHT DITA "), "LwDITA"
    name = name.removeprefix("DITA ")
    for tag, group in (("2.0 ", "DITA 2.0"), ("2.x ", "DITA 2.0"), ("1.3 ", "DITA 1.3"), ("1.x ", "DITA 1.3")):
        if name.startswith(tag):
            return name.removeprefix(tag), group
    return name, "DITA 1.3"  # unversioned ids resolve to DITA 1.3 in DITA-OT


template, wasm, dtdmap, out = sys.argv[1:5]
page = open(template, encoding="utf-8").read()
assert page.count("__WASM_BASE64__") == 1 and page.count("__SHELLS_JSON__") == 1
data = base64.b64encode(open(wasm, "rb").read()).decode()
shells = [[pub, *describe(pub)] for pub in (l.split("\t")[0] for l in open(dtdmap) if "\t" in l)]
page = page.replace("__SHELLS_JSON__", json.dumps(shells)).replace("__WASM_BASE64__", data)
open(out, "w", encoding="utf-8").write(page)
print(f"{out}: {len(page)} bytes (wasm {len(data)} base64, {len(shells)} public ids)")
