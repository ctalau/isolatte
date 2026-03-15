# QMD DITA Indexing & Search Benchmark

Benchmarking [QMD](https://github.com/tobi/qmd) (on-device hybrid search engine) against
2740 DITA topics from the [Oxygen XML userguide](https://github.com/oxygenxml/userguide).

## Benchmark Results

### Indexing

| Metric | Value |
|---|---|
| **Topics indexed** | 2740 `.dita` files |
| **Chunks created** | ~7839 (3694 embedded, 4145 not attempted — see [analysis](#embedding-failure-analysis)) |
| **Indexing time (FTS5)** | ~5 seconds |
| **Embedding time (CPU)** | ~30 minutes (embeddinggemma-300M, Q8_0, no GPU) |
| **Index size (FTS5 only)** | 41 MB |
| **Index size (with vectors)** | 53 MB |

### Models downloaded (on-device, all GGUF)

| Model | Size | Purpose |
|---|---|---|
| embeddinggemma-300M-Q8_0 | 329 MB | Vector embeddings |
| qmd-query-expansion-1.7B-q4_k_m | 1.28 GB | Query expansion (HyDE + variants) |
| Qwen3-Reranker-0.6B-Q8_0 | 639 MB | Cross-encoder reranking |

### Search Performance

| Mode | Query | Time | Results | Top Match |
|---|---|---|---|---|
| **BM25** (`search`) | `"How to enable Oxygen Feedback for a webhelp deliverable built with Oxygen Content Fusion"` | ~30s | 0 | — |
| **BM25** (`search`) | `"enable Oxygen Feedback webhelp Content Fusion"` | 1.6s | 4 | reusables-webhelp-output-parameters.dita |
| **BM25** (`search`) | `"webhelp feedback integration"` | 0.4s | 10 | ofb-feedback-comments-manager-overview.dita |
| **BM25** (`search`) | `"Oxygen Feedback site configuration webhelp transformation"` | 1.3s | 5 | dita-to-webhelp-responsive-with-oxygen-feedback-from-authoring-to-publishing.dita |
| **Vector** (`vsearch`) | full NL query | 3.7s* | 5 | dita-to-webhelp-responsive-with-oxygen-feedback-from-authoring-to-publishing.dita (0.74) |
| **Hybrid+rerank** (`query`) | full NL query | 41s* | 7 | dita-to-webhelp-responsive-with-oxygen-feedback-from-authoring-to-publishing.dita (0.93) |

\* First run includes model loading (~30s for query expansion model). Subsequent runs with warm models: vsearch ~3.7s, query ~41s (reranking is CPU-bound with Qwen3-0.6B).

## Search Query: "How to enable Oxygen Feedback for a webhelp deliverable built with Oxygen Content Fusion?"

### Key Finding

**Vector search succeeds where BM25 fails.** The full natural-language query returned 0 results
with BM25 (stop-word sensitivity), but vector search (`vsearch`) found the correct topic as
result #1 with score 0.74, and hybrid search with reranking (`query`) boosted it to 0.93.

QMD's query expansion is particularly effective — it automatically generates:
- Lexical variants: `"guide to turning"`, `"steps to activate"`
- Vector variants: `"guide to turning on oxygen feedback for specific projects"`
- HyDE (hypothetical document): `"The topic of handle oxygen feedback for enhanced webhelp deliverables..."`

### Answer

The best matching topic is **`dita-to-webhelp-responsive-with-oxygen-feedback-from-authoring-to-publishing.dita`** — *"DITA to WebHelp with Oxygen Feedback: From Authoring to Publishing"*.

> To enable Oxygen Feedback for a WebHelp deliverable:
>
> 1. **Create an Oxygen Feedback site configuration** in the [Feedback administration
>    interface](https://feedback.oxygenxml.com) — choose between Oxygen Feedback Cloud (SaaS)
>    or Oxygen Feedback Enterprise (self-hosted).
> 2. **Copy the HTML installation fragment** generated at the end of the site creation process.
> 3. **Paste it into the Feedback tab** in the WebHelp Responsive transformation scenario
>    dialog box in Oxygen XML Editor/Author.
> 4. **Run the WebHelp Responsive transformation** — the output will include the Oxygen Feedback
>    commenting component at the bottom of each page.
>
> For Content Fusion specifically: Content Fusion uses DITA-OT under the hood to build WebHelp
> deliverables. The `webhelp.product.id` and `webhelp.product.version` parameters must be set
> in the WebHelp transformation to connect to the correct Feedback site configuration. The edit
> link can point back to Content Fusion using the `editlink.remote.ditamap.url` parameter.

**Note:** No single topic covers the exact intersection of "Oxygen Feedback + Content Fusion WebHelp deliverable". The answer requires combining:

- `dita-to-webhelp-responsive-with-oxygen-feedback-from-authoring-to-publishing.dita` — End-to-end workflow
- `whr-feedback-system.dita` — How to add Feedback to WebHelp output
- `cf-projects-deliverables.dita` — Content Fusion deliverable configuration
- `reusables-webhelp-output-parameters.dita` — WebHelp parameters including edit links to Content Fusion

## Observations

1. **Vector search handles NL queries well** — While BM25 returned 0 results for the full
   natural-language question (too many stop words), vector search found the right topic
   immediately. The query expansion (HyDE) further improves retrieval quality.

2. **DITA XML is indexed as raw XML** — QMD indexes the full XML source including tags. BM25
   still works because the text content is present, but XML tags add noise to the index.
   A DITA-aware preprocessor (stripping tags, extracting `<title>`, `<shortdesc>`, `<keyword>`)
   would improve both BM25 and embedding quality.

3. **Embedding "failures" are a 30-minute timeout, not actual errors** — See
   [detailed analysis](#embedding-failure-analysis) below. QMD's `generateEmbeddings` enforces
   a hard 30-minute `maxDuration` session limit. On CPU, embedding 1318 of 2740 documents
   (3694 chunks) took the full 30 minutes before the timer fired. The remaining 1422 documents
   were never attempted. Running `qmd embed` again would continue from where it left off.

4. **CPU performance is usable but slow** — Embedding 1318 documents (3694 chunks) took 30
   minutes on 4 CPU cores (~0.49s per chunk). Reranking 40 chunks takes ~3s per query. Full
   embedding of all 2740 docs would require ~2 runs of `qmd embed` (~60 min total on CPU).
   With GPU, this would be 10-50x faster.

5. **BM25 stop-word sensitivity** — FTS5 tokenizer treats common English words as meaningful,
   causing the full NL query to fail entirely. Keyword-extracted queries work well.

6. **Title extraction** — QMD has title extractors for `.md` and `.org` files but not for DITA.
   Document titles fall back to filenames, which are less useful for display.

## Embedding Failure Analysis

The `qmd embed` output reported "4145 chunks failed", but investigation shows these are **not
actual embedding failures**. They are chunks that were **never attempted** due to a session
timeout.

### Root cause: 30-minute `maxDuration` session limit

QMD's `generateEmbeddings()` function ([store.ts:1439](qmd-tool/src/store.ts)) wraps the
embedding loop in a `withLLMSession` call with `maxDuration: 30 * 60 * 1000` (30 minutes).
When this timer fires, it triggers an `AbortController` that causes a `SessionReleasedError`
on all subsequent `embed()`/`embedBatch()` calls ([llm.ts:1362-1364](qmd-tool/src/llm.ts)).

### Evidence

1. **Clean alphabetical cutoff** — Documents are processed in path order. The last successfully
   embedded doc was `topics/eppo-installation-linux-server.dita`, and the first "failed" doc was
   `topics/eppo-installation-linux.dita`. There is exactly **1 status switch** across all 2740
   documents — no interleaved successes and failures.

2. **Identical size distributions** — Average size of embedded docs (5349 bytes) vs pending docs
   (5564 bytes) shows no meaningful difference. The pending docs aren't unusually large or
   malformed.

3. **Consistent throughput** — 3694 chunks embedded in 30m 19s = ~0.49s per chunk. At this rate,
   the remaining ~4145 chunks would need ~34 more minutes, matching the need for a second run.

### Resolution

Run `qmd embed` a second time. It will pick up where it left off (only processes docs without
vectors). Two runs of 30 minutes each would embed all 2740 documents.

```bash
# First run embeds ~1318 docs (30 min on CPU)
bun src/cli/qmd.ts embed

# Second run embeds the remaining ~1422 docs
bun src/cli/qmd.ts embed
```

## Reproducibility

```bash
# 1. Run setup (clones repos, installs deps)
./setup.sh

# 2. Run benchmark (indexes and searches — BM25 only, fast)
./benchmark.sh

# 3. Run embedding (CPU, ~30 min per run, need 2 runs for full coverage)
cd qmd-tool
bun src/cli/qmd.ts embed   # first pass: embeds ~1318 docs
bun src/cli/qmd.ts embed   # second pass: embeds remaining ~1422 docs

# 4. Run vector/hybrid search
bun src/cli/qmd.ts vsearch "How to enable Oxygen Feedback for a webhelp deliverable built with Oxygen Content Fusion" --json -n 10
bun src/cli/qmd.ts query "How to enable Oxygen Feedback for a webhelp deliverable built with Oxygen Content Fusion" --json -n 10

# Results are saved to results.txt
```

### Requirements

- Node.js >= 18 or Bun
- Git
- ~200MB disk space for the userguide repo + index
- ~2.3GB disk space for GGUF models (downloaded on first use)
- ~1GB RAM for embedding/reranking models
