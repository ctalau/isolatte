# DITA-OT profiling: Oxygen XML Editor user guide → resolved DITA

Run DITA-OT 4.3.1 (`--format=dita`, i.e. the preprocess-only "resolved DITA" transtype) on
`oxygenxml/userguide` (`DITA/UserManual.ditamap`, `editor-sa.ditaval`), profile it with JDK Flight Recorder,
and rank the hotspots.

* Input: 3388 output files (43 MB) — the resolved DITA is not committed.
* Host: 4 vCPU, OpenJDK 21.0.12, default heap, G1.
* Wall time, no profiler, no `-v`: **58.0 / 58.1 / 58.6 s** (3 runs). Outputs are byte-identical between runs.
* The build is **single-threaded**: `parallel` defaults to `false`; 99.9 % of samples are on `main`.
  (user 94 s vs real 63 s is GC + JIT threads only.)

## Hotspot table

Percentages are shares of JFR `ExecutionSample`s on the main thread (5017 samples, 5 ms period, depth 2048),
each sample attributed to its **innermost** DITA-OT/Saxon/Xerces frame (exclusive), baseline build.
Samples cover ~25 s of the 66 s profiled run (JFR drops samples on very deep stacks; GC/IO/native time is not in them),
so read them as shares of sampled Java CPU time, not of wall time.

| # | Share | Hotspot | Code that runs | Suggested fix | Measured |
|---|------:|---------|----------------|---------------|----------|
| 1 | **18.2 %** (21.2 % incl.) | Linear scan of all `FileInfo`s per link | `Job.getFileInfo(URI)` falls through to `files.values().stream().filter(fi -> file.equals(fi.src) \|\| file.equals(fi.result)).findFirst()` (Job.java:~546) for every absolute URI that is not a map key. Called per `href` from `DitaWriterFilter.replaceHREF:239/241` (10.7 %), `AbstractReaderModule.getOrCreateFileInfo:894`, `categorizeCurrentFile:587`, `TopicCleanFilter.startDocument:40`. Leaf frames are `ConcurrentHashMap$Traverser.advance`, `URI.equals`, `URI.percentNormalizedComparison`. O(links × files) with 3388 files. Dominates "Read topic files" (56 % of that phase) and "Clean preprocess" (25 %). | Keep a `src`/`result` → `FileInfo` hash index in `Job`, maintained in `add`/`remove` (patch in `patches/`). Same for the `getFileInfo(fi -> Objects.equals(fi.src, f))` predicate scan in `AbstractReaderModule.getOrCreateFileInfo` (still ~3–5 % after fix 1). | **58.3 s → 54.5 s (−6.4 %)**, share drops 18.2 % → 3.1 %, output identical. "Read topic files" 13.5 s → 7.3 s under the profiler. |
| 2 | **37 %** (42 % after fix 1) | Saxon XSLT tree walking in the preprocess XSLT steps | `XsltModule.transform → StreamStore.transformUri → Xslt30Transformer`, `TemplateRule.applyLeavingTail`, `Copy`/`CopyOf.copyAttribute` (identity-style copy of the whole tree). By phase (wall): `topicpull.xsl` 8.2 s (74–81 % Saxon), `conref.xsl` 8.1 s, move-meta 7.6 s, maplink 4.1 s, `preprocess2.post` 4.9 s. | Skip stylesheets for files that cannot change (topicpull for files with no `xref`/`link` needing pull; conref only for `hasConref` files, as already done for some steps); fuse consecutive XSLT/SAX passes so a file is parsed and serialized once; `--parallel` (see #8). | not measured |
| 3 | **17.3 %** (21 % after fix 1) | Xerces parse of every file in every step | `RelaxDefaultsParserConfiguration.parse → XML11Configuration → XMLNSDocumentScannerImpl.scanStartElement`. Flat: `XMLEntityScanner.scanLiteral/scanQName` 4.0 %, `QName.setValues`/`SymbolTable.addSymbol` 3.3 %, `XMLDTDValidator` default-attribute handling 1.5 %, DTD declaration lookup 1.0 %, RNG-defaults component ≤1.4 %. No single bad line — the cost is parsing each of 3388 files ~12 times (reader, keyref, conref, normalize, chunk, move-meta, maplink, topicpull, clean…). | Reduce the number of passes (fuse steps; keep a parsed Saxon `TinyTree` between XSLT steps). Once default attributes are materialised, later passes can use a non-validating, no-external-DTD reader and a shared `XMLGrammarPool`. | not measured; expected small (DTD part is only ~2.5 %) |
| 4 | **7.4 %** (9.2 % after fix 1) | Saxon serialization of every file after every step | `XMLEmitter.writeAttribute → StringView.tidy → StringTool.fromCharSequence/getStringLength`, `XMLEmitter.writeEscape → BMPString.indexWhere`, `UTF8Writer.write` (char by char). Plus `StreamStore.writeDocument` 5 %. | Same as #2/#3: write fewer times. Try newer Saxon-HE 12.x (the 12.5 `str.*` string layer is where the per-attribute `tidy`/length work comes from). | not measured |
| 5 | **8.2 %** (42 % of the conref phase) | Saxon regex `tokenize` backtracking | `conrefImpl.xsl`: `conref:isValid` (line 627) → `checkValid` → `tokenize($sourceDomains, '\)\s*?')` and `tokenize($output, '(s?\()\|\)\s*?\(\|\)')`, run for every conref'd element on the same long `@domains` strings. Stack: `ATokenIterator.next → REMatcher.match → OpSequence.advance` with `java.util.Stack`/`Vector` (synchronized) in the leaf frames. Also 16–19 % of `preprocess2.post`. | Memoise: `cache="yes"` on `conref:isValid`; better, compute the constraint list once per source document and replace the reluctant-quantifier regexes with `substring-before`/`string-join`. | **54.5 s → 52.6 s (further −3.5 %)**, combined −9.7 % vs baseline, output identical |
| 6 | 11.9 % | DITA-OT Java filters | `ProfilingFilter`, `DebugFilter`, `TopicFragmentFilter`, `DitaWriterFilter` plus `DitaClass.getInstance:82` (1.3 %, parses `@class` on every element), `URLUtils.setFragment/toURI` (1.6 %), `FilterUtils.getFlags`. | Intern `DitaClass` by the `@class` string (HashMap); avoid `URI` re-creation per attribute; drop `DebugFilter` unless debugging. | not measured |
| 7 | ~1.2 % wall | GC | 88 collections, 0.77 s total pause. | Not a hotspot. | – |
| 8 | – | Single-threaded pipeline | `parallel=false` (build_init.xml:76). `--parallel=true`. | – | **58.1 s → 50.2 s (−14 %) but unsafe in 4.3.1 on this input**: 566 `Error: Failed to move *.temp … does not exist` messages and 45 output files differ (generated ids `d628e325` vs `d5050e325`). Not recommended until the race is fixed upstream. |

### Per-phase wall time (profiled baseline run, 66.1 s)

| Phase | s | % | Dominant cost |
|---|---:|---:|---|
| Read topic files | 13.5 | 20.4 | `getFileInfo` scan 56 %, DITA-OT Java 23 %, Xerces 16 % |
| Pull metadata (topicpull.xsl) | 8.2 | 12.4 | Saxon 81 % |
| Resolve conref | 8.1 | 12.3 | Saxon 49 %, regex 42 % |
| Move metadata | 7.6 | 11.4 | Saxon 63 %, Xerces 25 % |
| Preprocess post | 4.9 | 7.3 | Saxon 53 %, regex 16 % |
| Clean preprocess | 4.2 | 6.3 | `getFileInfo` 25 %, Xerces 25 % |
| Related links | 4.1 | 6.3 | Saxon 50 % |
| Process chunks | 3.4 | 5.1 | DITA-OT Java 50 % |
| Keyref | 3.5 | 5.3 | Xerces 35 % |
| Normalize fragments | 3.3 | 5.0 | Xerces 40 % |
| everything else | 5.3 | 8 | – |

### Results of the fixes (wall, no profiler, same 3388-file output, `diff -r` = 0)

| Build | runs (s) | mean |
|---|---|---:|
| baseline 4.3.1 | 58.0, 58.1, 58.6 | 58.3 |
| + `Job` file-info index | 53.2, 53.2, 55.2, 56.1, 55.0 | 54.5 (−6.4 %) |
| + `cache="yes"` on `conref:isValid` | 53.4, 50.1, 53.2, 54.5, 52.0 | 52.6 (−9.7 %) |

The machine drifted by ~2 s between batches, so treat each figure as ±2 s.

## Honest assessment

**Worked:** the build ran, JFR with `stackdepth=2048` + `DebugNonSafepoints` gave usable attribution, and two small
changes (≈40 lines of Java, 1 XSLT attribute) give a measured ~10 % with byte-identical output.

**Did not work / caveats:**
* First attempt used JFR's default stack depth (64): Saxon recursion hid the calling module for 39 % of samples; had to re-record.
* JFR only sampled ~25 s of the 66 s run, so shares are of sampled Java time, and the profile over-estimated the
  `getFileInfo` gain (18–21 % predicted vs 6.4 % measured wall). Wall-clock A/B runs are the real numbers.
* `--parallel=true` is faster but produces errors and different output on this input.
* The `Job` index invalidates on `add`/`remove` only; it assumes `FileInfo.src/result` are not mutated after insertion
  (checked in bytecode: only `JobHandler` and `Builder` write them). Needs upstream tests before shipping.
* The Saxon (#2, #4) and Xerces (#3) fixes are suggestions, not measured.

**Next:** (1) index the `getOrCreateFileInfo` src predicate; (2) per-stylesheet timing (Saxon `-t`/`xsl:message` timestamps or one JFR per step) to split #2 by stylesheet; (3) prototype in-memory fusion of conref→keyref→normalize for one file to quantify the parse/serialize saving; (4) try Saxon-HE 12.9 and `cache="yes"` on other `tokenize` call sites.

**Opinion:** yes — resolved-DITA generation for a 3.4 k-file guide can be made meaningfully faster. The cheap fixes (#1, #5) are worth ~10 %; getting beyond ~30 % needs structural change (fewer parse/serialize passes, or safe parallelism), which is a real engineering project rather than a patch.

## Files
* `scripts/profile.sh` — reproduce (clone, download, run under JFR, per-phase analysis); `stamp.py` timestamps `==>` phase markers; `run.sh` timed A/B run; `analyze4/6/8.py` JFR JSON analysers.
* `patches/Job-getFileInfo-index.diff`, `patches/conrefImpl-cache.diff` — against DITA-OT 4.3.1.
