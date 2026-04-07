# dita-multilingual-sample

A DITA sample project demonstrating multilingual content reuse with keyscopes. The project models a user manual for a simple electric kettle ("AquaBoil 3000") translated into three languages: English, German (Deutsch), and French (Français).

## Key concepts demonstrated

### Keys for content reuse
- **`product-name`** — Defined once in the root map, inherited by all keyscopes. Not translated.
- **`socket-type`** — Defined per-language in each submap with locale-specific values:
  - EN: Type G (BS 1363)
  - DE: Typ F (Schuko, CEE 7/4)
  - FR: Type E (CEE 7/5)
- **`img-kettle-front`**, **`img-kettle-plug`** — Image keys defined once in the root map, referenced from all language topics. Single source, not translated.

### Map architecture
```
multilingual-manual.ditamap          ← root map (common keys + cover page)
  ├── topics/cover.dita              ← single multilingual cover page
  ├── en.ditamap  (keyscope="en")    ← English submap with EN socket-type key
  ├── de.ditamap  (keyscope="de")    ← German submap with DE socket-type key
  └── fr.ditamap  (keyscope="fr")    ← French submap with FR socket-type key
```

Each submap is imported via `<mapref>` with a separate `keyscope`, so the language-specific `socket-type` key resolves correctly within each scope while the shared `product-name` and image keys are inherited from the root map.

## Building the PDF

Requires DITA-OT 4.x and Java 11+.

```bash
dita --input=multilingual-manual.ditamap --format=pdf --output=out
```

The output is a single PDF (`out/multilingual-manual.pdf`) containing all three languages with a shared cover page.

## Project structure

```
dita-multilingual-sample/
├── images/
│   ├── kettle-front.svg          # Product image (shared)
│   └── kettle-plug.svg           # Plug image (shared)
├── topics/
│   ├── cover.dita                # Multilingual cover page
│   ├── en/
│   │   ├── safety.dita
│   │   ├── setup.dita
│   │   └── usage.dita
│   ├── de/
│   │   ├── safety.dita
│   │   ├── setup.dita
│   │   └── usage.dita
│   └── fr/
│       ├── safety.dita
│       ├── setup.dita
│       └── usage.dita
├── en.ditamap                    # English submap
├── de.ditamap                    # German submap
├── fr.ditamap                    # French submap
├── multilingual-manual.ditamap   # Root map
└── out/
    └── multilingual-manual.pdf   # Generated PDF
```
