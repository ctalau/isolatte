"""Flatten every DITA 1.3, DITA 2.0 and LwDITA DTD shell that DITA-OT ships.

usage: python3 -I all_shells.py DITA-OT-DIR FLATTEN-BIN OUT-DIR OUT-MAP.tsv [OUT-CATALOG.xml]

Walks the shell catalogs of the org.oasis-open.dita.v1_3, ...v2_0,
...techcomm.v2_0 and org.oasis-open.xdita.v0_3_0 (LwDITA) plugins, groups the public ids by the DTD
file they name, flattens each file once (through the full DITA-OT catalog,
XML_CATALOG_FILES must point at catalog-dita.xml), and writes one
"PUBLIC-ID<TAB>flattened.dtd" line per public id.

ALIASES adds public ids that documents use but DITA-OT's catalogs do not
declare. OUT-CATALOG, if given, is an OASIS catalog that maps those aliases to
the same DTD files and then delegates to catalog-dita.xml, so the reference
validators (xmllint, Xerces) resolve exactly what the compiled ones use."""
import glob
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

NS = "{urn:oasis:names:tc:entity:xmlns:xml:catalog}"
XML_BASE = "{http://www.w3.org/XML/1998/namespace}base"
PLUGINS = ["org.oasis-open.dita.v1_3/dtd", "org.oasis-open.dita.v2_0/dtd",
           "org.oasis-open.dita.techcomm.v2_0", "org.oasis-open.xdita.v0_3_0"]
# DITA 1.3 kept "Glossary" as an alias of the glossentry shell; DITA 2.0 dropped
# it, but documents (e.g. ScriptoriumDev/LearningDITA) still use the 2.x form.
ALIASES = {"-//OASIS//DTD DITA 2.x Glossary//EN": "-//OASIS//DTD DITA 2.x Glossary Entry//EN",
           "-//OASIS//DTD DITA 2.0 Glossary//EN": "-//OASIS//DTD DITA 2.0 Glossary Entry//EN"}


def public_entries(catalog, out, seen):
    if catalog in seen:
        return
    seen.add(catalog)

    def walk(el, base):
        base = os.path.normpath(os.path.join(base, el.get(XML_BASE, "")))
        for c in el:
            tag = c.tag.replace(NS, "")
            if tag == "public":
                out.setdefault(c.get("publicId"), os.path.normpath(os.path.join(base, c.get("uri"))))
            elif tag == "nextCatalog":
                public_entries(os.path.normpath(os.path.join(base, c.get("catalog"))), out, seen)
            elif tag == "group":
                walk(c, base)

    walk(ET.parse(catalog).getroot(), os.path.dirname(catalog))


def main():
    ditaot, flatten, out_dir, out_map = sys.argv[1:5]
    plugins = os.path.join(ditaot, "plugins")
    entries, seen = {}, set()
    for p in PLUGINS:
        for cat in sorted(glob.glob(os.path.join(plugins, p, "**", "catalog*.xml"), recursive=True)):
            public_entries(cat, entries, seen)
    # Document-type shells only: DTD public ids naming a .dtd (not .mod/.ent), no DITAVAL.
    shells = {pub: path for pub, path in entries.items()
              if "//DTD " in pub and path.endswith(".dtd") and "ditaval" not in path.lower()}
    for alias, target in ALIASES.items():
        shells.setdefault(alias, shells[target])
    by_file = {}
    for pub, path in sorted(shells.items()):
        by_file.setdefault(path, []).append(pub)
    os.makedirs(out_dir, exist_ok=True)
    lines = []
    for path, pubs in sorted(by_file.items()):
        name = os.path.relpath(path, plugins).replace(os.sep, "_").replace(".dtd", "") + ".dtd"
        flat = os.path.abspath(os.path.join(out_dir, name))
        with open(flat, "wb") as f:
            subprocess.run([flatten, pubs[0], os.path.basename(path)], stdout=f, check=True)
        lines += [f"{pub}\t{flat}\n" for pub in pubs]
    open(out_map, "w").write("".join(lines))
    if len(sys.argv) > 5:
        cat = ['<?xml version="1.0"?>\n<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog" prefer="public">\n']
        cat += [f'  <public publicId="{a}" uri="file://{os.path.abspath(shells[a])}"/>\n' for a in ALIASES]
        cat.append(f'  <nextCatalog catalog="file://{os.path.abspath(os.path.join(ditaot, "catalog-dita.xml"))}"/>\n</catalog>\n')
        open(sys.argv[5], "w").write("".join(cat))
    print(f"{len(lines)} public ids, {len(by_file)} shells")


main()
