# dtd-validator-throughput

How fast can every `.dita` topic of the [Oxygen XML user guide](https://github.com/oxygenxml/userguide)
be DTD-validated? Compared here: a pure-Rust validator (**xmloxide**), a second
pure-Rust one (**rusty_xml**), libxml2 used as a library with cached DTDs,
**Xerces-J with a shared grammar pool**, stock `xmllint --valid`, and — fastest
by far — **validators compiled from the DTDs into Rust and JavaScript code**
(see [Compiling the DTDs to Rust and JS](#compiling-the-dtds-to-rust-and-js)).

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
| **DTD compiled to Rust** (+ quick-xml) | 1 | 0.088 s | **31,300** | 171 | none |
| **DTD compiled to Rust** (+ quick-xml) | 4 | 0.024 s | **116,700** | 640 | none |
| **DTD compiled to JS** (+ saxes, Node 22), JIT-warm | 1 | 0.343 s | **8,040** | 44 | none |
| **DTD compiled to JS** (+ saxes, Node 22), JIT-warm | 4 | 0.112 s | **24,600** | 135 | none |
| **xmloxide 0.5.0** (Rust, patched) | 1 | 0.390 s | **7,070** | 39 | 0.13 s |
| **xmloxide 0.5.0** (Rust, patched) | 4 | 0.136 s | **20,300** | 111 | 0.15 s |
| libxml2 2.9.14, cached DTD (C) | 1 | 0.459 s | 6,010 | 33 | 0.19 s |
| libxml2 2.9.14, cached DTD (C) | 4 | 0.223 s | 12,340 | 68 | 0.23 s |
| Xerces-J 2.12.2, shared pool keyed by public ID, JIT-warm | 1 | 1.03 s | 2,680 | 15 | 0.30 s |
| Xerces-J 2.12.2, shared pool keyed by public ID, JIT-warm | 4 | 0.408 s | 6,750 | 37 | 0.38 s |
| Xerces-J 2.12.2, shared pool keyed by public ID, cold JVM (1st pass) | 4 | 1.06 s | 2,600 | 14 | 0.38 s |
| rusty_xml 0.8.3 (Rust) | 1 | 22.98 s | 120 | 0.7 | 0.15 s |
| rusty_xml 0.8.3 (Rust) | 4 | 5.92 s | 466 | 2.6 | 0.18 s |
| `xmllint --valid` (stock, 50 files/process) | 1 proc | 116.8 s | 24 | 0.13 | per file |
| `xmllint --valid` (stock, 50 files/process) | 4 procs | 30.0 s | 92 | 0.5 | per file |

**Whole user guide, end to end: 0.031 s for the DTD compiled to Rust (fresh
process, 4 threads), 0.42 s for the DTD compiled to JS (fresh `node`, cold JIT)**, and
~0.28 s with xmloxide on 4 threads
(0.15 s loading 8 DTDs + 0.14 s validating) — vs ~1.5 s for a fresh Xerces-J
process (JVM startup + cold JIT) and 30 s for parallel stock `xmllint`.
Xerces rows are the median of passes 3–5 within one JVM (`results-raw-xerces.txt`).

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

## Compiling the DTDs to Rust and JS

`compiled/gen.py` takes the 8 flattened DTDs (6.5 MB in total) and emits
`work-gen/generated.rs` (223 KB) and `work-gen/generated.js` (189 KB). Generating
takes 2.1 s, and the Rust crate then takes 7 s to build with LTO, giving a 0.79 MB
binary. After that, nothing DTD-related is parsed at run time.

- **Content models → minimized DFAs.** Each `<!ELEMENT>` model becomes a Glushkov
  automaton, then a DFA via subset construction, then a minimized DFA (Moore's
  algorithm) over integer element ids. Mixed content becomes a one-state DFA over
  its allowed children. 544 element names over all shells yield **422 DFA states and
  10,120 transitions**. For example, `body`'s 40-way choice minimizes to 1 state and
  `topic` to 7. DFAs, attribute declarations (572 distinct), attribute lists (198)
  and enumerations (113) are deduplicated across shells, so each shell is just a
  row of per-element indexes into shared tables.
- **Names → ids.** A generated `match` on byte strings in Rust, a `Map` in JS.
- **Attributes.** Declared or not, `#REQUIRED` count, `#FIXED` value, and
  ID / IDREF(S) / NMTOKEN(S) / enumeration syntax, with non-CDATA whitespace
  normalization. ID uniqueness and IDREF targets are checked per document.
- **Entities.** The DTDs' internal general entities (`&nbsp;`, `&included-domains;`
  …) are expanded at generation time into a per-shell table. The generator refuses
  external or markup-bearing entities; DITA has none.
- **Runtimes.** `compiled/rust/src/main.rs` (quick-xml 0.42 events) and
  `compiled/js/validator.js` (saxes 6, `worker_threads`) walk the document with a
  stack of DFA states, about 300 lines each.

Where the time goes (1 thread; median of 5 runs, or of JIT-warm passes 3–5 for JS):

| | Parse only | Parse + validate | Validation overhead |
|---|---:|---:|---:|
| Rust: quick-xml | 0.065 s (42,600 files/s) | 0.088 s (31,300 files/s) | ~35% |
| JS: saxes | 0.201 s (13,700 files/s) | 0.343 s (8,040 files/s) | ~70% |

The compiled Rust validator runs **4.4× xmloxide on 1 thread and 5.7× on 4 threads**.
It does 9.5× the 4-thread rate of libxml2 with cached DTDs, and 1,270× stock
`xmllint --valid`. Even the JS version on 4 warm threads is faster than every
library-based validator here. Its cold, single-process run of 0.42 s is mostly
Node startup and the JIT, about as long as xmloxide's whole run.

**Correctness.** On the real corpus, both compiled validators flag only the
DOCTYPE-less topic, the same as every other validator. On both negative corpora
(640 files, 18 kinds, including 2 kinds of valid "ok-" controls) they match stock
`xmllint`, the ground truth, **file for file** (`results-detection-*.txt`):

| Kind (30 each) | xmllint | libxml2-cached | xmloxide | Xerces pool | compiled Rust | compiled JS |
|---|---:|---:|---:|---:|---:|---:|
| missing-title, stray-text, bad-nmtoken, duplicate-id, empty-with-content, ws-in-empty, missing-required, bad-fixed | 30 | 30 | 30 | 30 | 30 | 30 |
| root-mismatch (DOCTYPE `concept`, root `<topic>`) | 30 | **0** | 30 | 30 | 30 | 30 |
| undefined-entity (`&nbspx;`) | 30 | **0** | **0** | 30 | 30 | 30 |
| nbsp-in-body (declared `&nbsp;` in element-only content) | 30 | **0** | **0** | 30\* | 30 | 30 |
| ok-nbsp-in-p (valid) | 0 | 0 | 0 | **30 ✗** | 0 | 0 |
| ok-explicit-fixed (valid) | 0 | 0 | 0 | 0 | 0 | 0 |

The first negative corpus (5 kinds × 50) is 250/250 for everything.

Two of the earlier harnesses turn out to be *less strict* than full validation:

- **libxml2-cached and xmloxide never check entity references.** Both parse each
  topic without its DTD, then validate the tree, so an undefined entity is
  never noticed.
- **libxml2-cached does not check the root element against the DOCTYPE name.**
  `xmlValidateDtd` gets a DTD from `xmlParseDTD`, which has no name.
- **\*Xerces with a grammar pool gives a false positive.** A DTD grammar taken
  from the pool brings no entity declarations, so the valid `&nbsp;` is reported
  as an undefined entity. Its nbsp-in-body "hits" are for that reason, not for
  the real content error.

**Limits of the compiled validators.** They accept only documents whose DOCTYPE
names one of the compiled shells, and refuse internal DTD subsets. Attribute
defaults are not inserted (no `@class` in an output tree; there is no output tree).
The error *count* differs from libxml2: they report one error per broken parent,
and only pass/fail is compared. quick-xml is a fast tokenizer, not a fully
conformant well-formedness checker (for example, it does not check every XML name
character); saxes is conformant. A DTD change means re-running `gen.py` and
rebuilding.

## Xerces-J with a shared grammar pool

`java/XercesBench.java` uses the Xerces 2.12.2 jar that DITA-OT 4.2.4 ships. One
`XMLGrammarPool` and one `SynchronizedSymbolTable` are shared by every thread. Each
thread has its own `SAXParser`, with validation turned on. The DTDs are preparsed
into the pool with `XMLGrammarPreparser`.

**The stock pool key does not fit DITA.** Xerces identifies a DTD grammar by its
*expanded system ID*, which is the DOCTYPE's `"topic.dtd"` resolved against the
**document's** folder, plus the root element name. It falls back to the public ID
only when there is no system ID. So:

| Pool setup (4 threads) | DTD re-fetches | Grammars in pool | Files/s, warm |
|---|---:|---:|---:|
| `XMLGrammarPoolImpl`, preparsed then **locked** | 2,756 (every file) | 8 | 75 (cold) |
| `XMLGrammarPoolImpl`, preparsed, left **open** | 36 | 26 | 6,520 |
| **keyed by public ID** (like DITA-OT's `XMLGrammarPoolImplUtils`), locked | **0** | **8** | **6,750** |
| keyed by public ID, *original modular DTDs* via the DITA-OT catalog | 0 | 8 | 6,010 |

- **Locked stock pool:** the preparsed grammars never match a document, so every
  file re-parses its DTD. That is no better than xmllint.
- **Open stock pool:** it works, but only by accident. The user guide keeps its
  topics in a handful of folders, so the pool fills up to one copy per folder and
  root element. On the first, cold pass it is 1.6× slower than the public-ID pool
  (1,580 vs 2,600 files/s), because each copy is parsed separately. A corpus spread
  over many folders would re-parse the DTD far more often.
- **Public-ID pool:** this is the right setup. The original modular DTDs and the
  flattened ones run at the same speed once cached. Only the one-time load
  differs (0.83 s vs 0.38 s).

Xerces also flags only the DOCTYPE-less topic on the real corpus, and catches 250/250
of the broken topics. It gives a false positive on DTD-declared entities such as
`&nbsp;` when the grammar comes from the pool (see the correctness table above). JIT-warm on 4 threads it is about 0.55× libxml2-cached and
about 0.33× xmloxide.

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
  value (`translate="maybe"`). **All five validators (incl. Xerces-J) flag 250/250.**
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
./benchmark.sh   # REPS=5 by default; prints one line per run (ends with the
                 # Xerces and compiled-validator benchmarks)
./compare_detection.sh work-mutants2   # per-kind detection table, all validators
```
