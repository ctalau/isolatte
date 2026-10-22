# dtd-validator-throughput

How fast can every `.dita` topic of the [Oxygen XML user guide](https://github.com/oxygenxml/userguide)
be DTD-validated? Compared here: a pure-Rust validator (**xmloxide**), a second
pure-Rust one (**rusty_xml**), libxml2 used as a library with cached DTDs, and
stock `xmllint --valid`.

## Corpus

- `oxygenxml/userguide` @ HEAD (shallow clone): **2,757 `.dita` topics, 15.1 MB**
- DOCTYPEs: Topic (2,421), Task (109), Troubleshooting 1.2/1.3 (86), Concept (57),
  Glossary (51), LwDITA Topic (29), Reference (3); one topic has no DOCTYPE
- DTDs + catalog from DITA-OT 4.2.4 (`catalog-dita.xml`, DITA 1.3 + LwDITA plugins)

## Result

Host: 4 vCPU cloud VM, files in page cache. Times cover read + parse + validate of all
2,757 files; the one-time DTD load is listed separately. Median of 5 runs
(`results-raw.txt` has every run; run-to-run noise is ±15%).

| Validator | Threads | Validation time | **Files/s** | MB/s | DTD load (once) |
|---|---:|---:|---:|---:|---:|
| **xmloxide 0.5.0** (Rust, patched) | 1 | 0.390 s | **7,070** | 39 | 0.13 s |
| **xmloxide 0.5.0** (Rust, patched) | 4 | 0.136 s | **20,300** | 111 | 0.15 s |
| libxml2 2.9.14, cached DTD (C) | 1 | 0.459 s | 6,010 | 33 | 0.19 s |
| libxml2 2.9.14, cached DTD (C) | 4 | 0.223 s | 12,340 | 68 | 0.23 s |
| rusty_xml 0.8.3 (Rust) | 1 | 22.98 s | 120 | 0.7 | 0.15 s |
| rusty_xml 0.8.3 (Rust) | 4 | 5.92 s | 466 | 2.6 | 0.18 s |
| `xmllint --valid` (stock, 50 files/process) | 1 proc | 116.8 s | 24 | 0.13 | per file |
| `xmllint --valid` (stock, 50 files/process) | 4 procs | 30.0 s | 92 | 0.5 | per file |

**Whole user guide, end to end: ~0.28 s with xmloxide on 4 threads**
(0.15 s loading 8 DTDs + 0.14 s validating) — vs 30 s for parallel stock `xmllint`.

All validators agree on the real corpus: every topic is valid except
`dcpp_how_to_make_visible_information_from_topic_prologue_revision_history.dita`,
which has no DOCTYPE.

## Why the cached runs are ~250× faster than xmllint

A DITA shell DTD pulls in ~40 `.mod`/`.ent` files (MathML and SVG domains included)
and expands to ~900 KB of declarations. `xmllint --valid` re-reads and re-parses that
for **every** file (~38 ms/file); the topic itself is a few KB and takes well under
1 ms. So the main gain comes from parsing each DTD once and reusing it. The
choice of language matters much less after that: xmloxide beats libxml2-with-cache
by 1.2× on one thread and 1.6× on four.

## How it works

1. **Flatten the DTDs** (`c/flatten_dtd.c`). Neither Rust crate can load DITA's
   modular DTDs. xmloxide skips parameter-entity references outright, and
   rusty_xml has no catalog/file resolution for external parameter entities.
   So libxml2 resolves each public ID through the DITA-OT catalog, expands every
   parameter entity and `INCLUDE`/`IGNORE` section, and dumps the result as one
   self-contained DTD per doctype (`work-flat/*.dtd`, 19 KB for LwDITA and
   ~0.9 MB for the others). This runs once, at setup.
2. **Validate** (`rust-bench/src/main.rs`, `c/libxml2_cached.c`). Each thread
   parses the 8 flattened DTDs once. Worker threads then pull file paths from a
   shared atomic counter. For each topic they read the DOCTYPE public ID, parse the
   document *without* loading its external DTD, and validate the tree against
   the cached DTD. All three library-based runs use the same flattened DTDs.
   libxml2 gets per-thread DTD copies because `xmlValidateDtd` compiles content-model
   automata into the DTD lazily, which is not thread-safe.

## Correctness checks

- **Real corpus:** every validator reports exactly the one DOCTYPE-less file.
- **Negative corpus** (`make_mutants.py`): 250 broken copies of real topics, in
  5 kinds × 50: undeclared element, element in a forbidden position (`<section>`
  in `<p>`), duplicate `<title>`, undeclared attribute, and an out-of-enumeration
  value (`translate="maybe"`). **All four validators flag 250/250.**
- **xmloxide bug found and patched.** Stock xmloxide 0.5.0 falsely rejected 19
  topics with 39 errors: `attribute 'space' on element 'codeblock' is not declared`.
  It compares an attribute's *local* name (`space`) with the DTD's qualified name
  (`xml:space`). `patches/xmloxide-0.5.0-prefixed-attr-names.patch` compares the
  qualified name instead, and with it the false positives go away. Speed is unchanged
  (unpatched: 7,690 files/s on 1 thread).

## Caveats

- libxml2 is Ubuntu's 2.9.14. Newer libxml2 releases (2.12+) have parser speedups
  and might narrow the gap with xmloxide.
- The cached-DTD approach parses topics without their DTD, so DTD attribute
  defaults (DITA `@class`) are not inserted into the tree. That is fine for
  validation. It would not be fine for a pipeline that needs `@class`.
- The noise between runs is real (shared VM): treat xmloxide vs libxml2-cached as
  "1.2–1.8× faster", not as an exact ratio.
- rusty_xml is correct but ~60× slower than xmloxide here. Its validator returns
  only the first error, and it is slow on large DTDs.

## Run it

```sh
./setup.sh       # clones corpus, downloads DITA-OT 4.2.4, flattens DTDs, builds everything
./benchmark.sh   # REPS=5 by default; prints one line per run
```
