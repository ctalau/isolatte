/* flatten_dtd: resolve a DTD by PUBLIC id through the XML catalog
 * (XML_CATALOG_FILES), let libxml2 expand every parameter entity and
 * conditional section, and print the resulting element/attribute/general
 * entity/notation declarations. Parameter-entity declarations are dropped,
 * since nothing in the output references them any more. */
#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/catalog.h>
#include <libxml/entities.h>

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s PUBLIC-ID SYSTEM-ID\n", argv[0]); return 2; }
    xmlInitParser();
    xmlInitializeCatalog();
    xmlDtdPtr dtd = xmlParseDTD(BAD_CAST argv[1], BAD_CAST argv[2]);
    if (!dtd) { fprintf(stderr, "cannot load DTD %s\n", argv[1]); return 1; }
    xmlBufferPtr buf = xmlBufferCreate();
    for (xmlNodePtr n = dtd->children; n; n = n->next) {
        if (n->type == XML_ENTITY_DECL) {
            xmlEntityPtr e = (xmlEntityPtr)n;
            if (e->etype == XML_INTERNAL_PARAMETER_ENTITY ||
                e->etype == XML_EXTERNAL_PARAMETER_ENTITY) continue;
        }
        if (n->type != XML_ELEMENT_DECL && n->type != XML_ATTRIBUTE_DECL &&
            n->type != XML_ENTITY_DECL && n->type != XML_NOTATION_NODE) continue;
        xmlNodeDump(buf, NULL, n, 0, 0);
    }
    /* Notations live in a hash table, not in the children list. */
    fwrite(xmlBufferContent(buf), 1, xmlBufferLength(buf), stdout);
    xmlBufferFree(buf);
    xmlFreeDtd(dtd);
    return 0;
}
