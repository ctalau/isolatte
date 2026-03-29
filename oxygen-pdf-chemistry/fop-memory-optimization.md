# Apache FOP memory optimization study (`topic.fo` benchmark)

This note documents a focused memory investigation for rendering the committed
`topic.fo` benchmark file under constrained heap settings.

## Scope and setup

- Benchmark input: `oxygen-pdf-chemistry/topic.fo` (committed FO, ~31 MB).
- FOP source used for code investigation: Apache `xmlgraphics-fop` trunk
  (`2.11.0-SNAPSHOT` at build time).
- JVM: OpenJDK 21.
- Memory target: `-Xmx256m`.
- Validation mode used in runs: `-r` (relaxed), because strict mode fails on
  duplicate IDs in this FO.

## Profiling infrastructure

I used two layers:

1. **RSS sampler + run harness** in this repo:
   `oxygen-pdf-chemistry/fop_memory_profile.py`
   - Runs FOP CLI with configurable heap/options.
   - Samples `/proc/<pid>/status` every 200 ms.
   - Emits JSON summary (`exit_code`, `elapsed_s`, `peak_rss_kb`).
   - Can optionally collect JFR (`--jfr`).

2. **FOP source patch prototype**:
   `oxygen-pdf-chemistry/fop-inputhandler-streaming.patch`
   - Replaces CLI FO-input identity-transform path with direct SAX parse into
     FOP’s default handler.

## What consumed memory (findings)

### 1) FO input path used an identity XSLT transformer

In stock CLI flow, FO input still goes through `TransformerFactory.newTransformer()`
(identity transform) before SAX events reach FOP. On the benchmark under
`-Xmx256m`, this path OOMed in Xalan/XSLTC transform code.

Observed failure signature (baseline run log):

- `java.lang.OutOfMemoryError: Java heap space`
- stack in `com.sun.org.apache.xalan.internal.xsltc.trax.TransformerImpl.transform(...)`

### 2) Even after bypassing identity transform, FO tree/layout still dominates

After patching `InputHandler` to stream FO directly by SAX, OOM moved from
Xalan transform into SAX/FOP processing (`InputHandler.parseFOInput(...)` path),
which indicates the dominant live set is still in FO tree + layout state for
this large document under a 256 MB heap.

## Fixes applied

### Fix A: direct SAX parse for FO CLI input (source patch)

Patch file: `oxygen-pdf-chemistry/fop-inputhandler-streaming.patch`.

Summary:
- Detect FO input (`xsltSource == null`) with `SAXResult` destination.
- Bypass identity transformer.
- Parse source directly via `XMLReader.parse(...)` and feed FOP handler.

Expected effect:
- Removes identity-transform overhead and its temporary structures.
- Improves failure mode and reduces one unnecessary processing stage.

### Fix B: reproducible memory profiler script

File: `oxygen-pdf-chemistry/fop_memory_profile.py`.

This gives repeatable measurements for regressions/optimizations without relying
on `/usr/bin/time -v`.

## Measured runs (this environment)

All runs used the committed `topic.fo`, `-Xmx256m`, relaxed validation (`-r`).

| Variant | Exit | Peak RSS | Elapsed | Notes |
|---|---:|---:|---:|---|
| Baseline CLI (identity transform path) | 1 | ~385 MB | ~43 s | OOM in Xalan `TransformerImpl.transform` |
| Patched CLI (direct SAX FO parse) | 1 | ~381 MB | ~42 s | OOM later in SAX/FOP processing |
| Patched + `-conserve` | 1 | ~401 MB | ~41 s | Still OOM on this benchmark |

## Conclusion

- The investigation identified and removed one concrete inefficiency in FOP CLI
  FO handling (identity XSLT on FO input).
- On this benchmark, that optimization alone is **not sufficient** to complete
  rendering at `-Xmx256m`; the dominant memory pressure remains in FOP FO/layout
  processing for this document size/complexity.
- The provided profiler + patch make further work straightforward (e.g., deeper
  area-tree and page-viewport retention analysis in `fop-core` layout pipeline).

## Reproduction commands

Build FOP modules:

```bash
cd /workspace/isolatte/.tmp/fop-src
mvn -DskipTests package -pl fop-core,fop-events,fop-util,fop -am
```

Run profile:

```bash
python3 oxygen-pdf-chemistry/fop_memory_profile.py \
  --cp-file /workspace/isolatte/.tmp/fop-src/fop/cp.txt \
  --prepend-jar /workspace/isolatte/.tmp/fop-src/fop-core/target/fop-core-2.11.0-SNAPSHOT.jar \
  --prepend-jar /workspace/isolatte/.tmp/fop-src/fop-util/target/fop-util-2.11.0-SNAPSHOT.jar \
  --prepend-jar /workspace/isolatte/.tmp/fop-src/fop-events/target/fop-events-2.11.0-SNAPSHOT.jar \
  --fo /workspace/isolatte/oxygen-pdf-chemistry/topic.fo \
  --pdf /workspace/isolatte/oxygen-pdf-chemistry/profiling/patched-256m.pdf \
  --xmx 256m --relaxed --log /workspace/isolatte/oxygen-pdf-chemistry/profiling/patched-256m.log
```


## Heap dump + near-OOM histogram analysis

I captured an OOM heap dump with:

```bash
java -Xmx256m -Xms256m   -XX:+HeapDumpOnOutOfMemoryError   -XX:HeapDumpPath=oxygen-pdf-chemistry/profiling/fop-oom.hprof   -XX:+PrintClassHistogram   -cp <classpath> org.apache.fop.cli.Main -r -fo topic.fo -pdf out.pdf
```

Artifacts from this run:
- Heap dump: `oxygen-pdf-chemistry/profiling/fop-oom.hprof` (~402 MB)
- OOM log: `oxygen-pdf-chemistry/profiling/oom-run.log`
- Near-OOM class histogram (captured via `jcmd GC.class_histogram`):
  `oxygen-pdf-chemistry/profiling/class-histo-near-oom.txt`

Top objects by retained bytes near OOM were overwhelmingly layout/text shaping
structures, not image payloads:

- `org.apache.fop.fonts.GlyphMapping`
- `org.apache.fop.layoutmgr.NonLeafPosition`
- `org.apache.fop.layoutmgr.KnuthGlue`
- `org.apache.fop.layoutmgr.LeafPosition`
- `org.apache.fop.layoutmgr.inline.KnuthInlineBox`
- `org.apache.fop.layoutmgr.KnuthPenalty`
- `org.apache.fop.area.inline.WordArea`
- many `ArrayList`, `TreeMap$Entry`, `SpaceProperty`, `MinOptMax`

Interpretation: the hot memory path is line-breaking/layout state and inline
area retention while processing a very large FO tree.

## Working strategy to reduce memory

Based on the heap profile, a realistic strategy is:

1. **Eliminate avoidable front-door overhead** (done/prototyped)
   - Keep direct SAX FO parse for FO CLI input (avoid identity XSLT path).

2. **Reduce live layout state in core** (needed for 256 MB success)
   - Add a low-memory mode that aggressively clears per-paragraph/per-page
     Knuth and Position lists right after line/page finalization.
   - Audit lifetimes in `LineLayoutManager`, `TextLayoutManager`,
     `PageSequenceLayoutManager`, and unresolved-element lists.

3. **Operational fallback that works now**
   - Render in chunks (per page-sequence or chapter) and merge PDFs.
   - This avoids one giant in-memory layout problem and is the fastest path to
     practical 256 MB operation without deep invasive FOP surgery.

If strict single-process, single-pass full-document rendering at `-Xmx256m` is
non-negotiable, it likely requires non-trivial refactoring in FOP layout internals.


## Implemented chunked rendering prototype

I implemented `oxygen-pdf-chemistry/chunked_fop_render.py`.

What it does:
- Parses `topic.fo`.
- Splits document by `fo:page-sequence` into chunk FO files.
- Optional pre-split of each page-sequence by `fo:flow` top-level children.
- Renders each chunk with FOP under fixed heap (e.g. `-Xmx256m`).
- Measures per-chunk peak RSS.
- Merges successful chunk PDFs with `pypdf`.

### Test run on provided `topic.fo`

Command (abridged):

```bash
python3 oxygen-pdf-chemistry/chunked_fop_render.py   --fo oxygen-pdf-chemistry/topic.fo   --chunk-size 1 --flow-split-size 120   --xmx 256m --relaxed --conserve ...
```

Observed behavior:
- Chunks 1-9 rendered successfully.
- Chunk 10 failed with OOM (`exit_code=1`) even with page-sequence chunking.
- Peak RSS for some successful chunks was high (300MB+), and failed chunk hit ~388MB RSS.

Interpretation:
- Chunking by page-sequence alone is not sufficient for this input because at
  least one individual page-sequence is itself too memory-heavy for 256MB heap.
- Additional intra-sequence splitting would need to be semantic-aware (not only
  top-level flow child splitting) to avoid invalid/broken FO.


## Iterative OOM split strategy (implemented)

To follow the requested approach, `chunked_fop_render.py` now supports an
adaptive retry mode:

- When a chunk OOMs, take ~1 MB from the **beginning** (`--probe-bytes`).
- Render that probe fragment to determine a stable split boundary candidate.
- Split the failed original chunk into two smaller chunks at that boundary.
- Retry recursively.

CLI flags:
- `--adaptive-oom-split`
- `--probe-bytes 1048576`

### Result on the provided FO

- The adaptive logic triggers on the previously failing chunk.
- For the worst chunk, splitting at top-level flow nodes was not enough, so the
  script now also supports splitting inside a single giant nested block.
- In practice, this still needs longer runs and stronger stop criteria to finish
  robustly in this environment; partial runs show OOM moving into
  `CachedRenderPagesModel.savePage(...)` for some fragments.

Interpretation:
- The split strategy is directionally correct, but this input likely needs
  semantic split boundaries + additional memory controls (especially around page
  caching/serialization in area tree handling).
