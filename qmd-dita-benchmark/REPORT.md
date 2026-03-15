# QMD DITA Indexing & Search Benchmark

Benchmarking [QMD](https://github.com/tobi/qmd) (on-device hybrid search engine) against
2740 DITA topics from the [Oxygen XML userguide](https://github.com/oxygenxml/userguide).

## Benchmark Results

| Metric | Value |
|---|---|
| **Topics indexed** | 2740 `.dita` files |
| **Indexing time** | ~5 seconds (wall-clock) |
| **Index size** | 41 MB (SQLite FTS5) |
| **Query time (BM25, keyword)** | 400ms–2s depending on query |
| **Query time (BM25, full NL sentence)** | ~30s (degrades with many stop words) |

## Search Query: "How to enable Oxygen Feedback for a webhelp deliverable built with Oxygen Content Fusion?"

### Finding

QMD's BM25 full-text search works well with **keyword queries** but degrades significantly
with **full natural-language questions** containing many stop words ("How", "to", "for", "a",
"built", "with"). The full NL query returned **0 results in ~30s**, while the keyword-extracted
version returned relevant results in **~1.6s**.

### Best search strategies

| Query | Time | Results |
|---|---|---|
| `"How to enable Oxygen Feedback for a webhelp deliverable built with Oxygen Content Fusion"` | ~30s | 0 results |
| `"enable Oxygen Feedback webhelp Content Fusion"` | ~1.6s | 4 results |
| `"webhelp feedback integration"` | ~0.4s | 10 results |
| `"Oxygen Feedback site configuration webhelp transformation"` | ~1.3s | 5 results |

### Answer

The best matching topic is **`whr-feedback-system.dita`** — *"Adding Oxygen Feedback to
WebHelp Responsive Documentation"*. The answer from the indexed documentation:

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

**Note:** The Oxygen XML userguide does not contain a single dedicated topic that covers the
exact intersection of "enabling Oxygen Feedback on a Content Fusion–built WebHelp deliverable".
The answer requires combining information from:

- `whr-feedback-system.dita` — How to add Feedback to WebHelp output
- `dita-to-webhelp-responsive-with-oxygen-feedback-from-authoring-to-publishing.dita` — End-to-end workflow
- `cf-projects-deliverables.dita` — Content Fusion deliverable configuration
- `reusables-webhelp-output-parameters.dita` — WebHelp parameters including edit links to Content Fusion

## Observations

1. **DITA XML is indexed as raw XML** — QMD indexes the full XML source including tags. BM25
   still works because the text content is present, but XML tags add noise to the index.
   A DITA-aware preprocessor (stripping tags, extracting `<title>`, `<shortdesc>`, `<keyword>`)
   would improve relevance.

2. **No vector/semantic search tested** — `qmd embed` requires downloading ~300MB+ GGUF models
   via `node-llama-cpp`. Only BM25 (keyword) search was benchmarked. Semantic search (`qmd vsearch`)
   and hybrid search with reranking (`qmd query`) would likely handle the full NL query better.

3. **Stop-word sensitivity** — The full natural-language query failed entirely with BM25.
   QMD's FTS5 tokenizer treats common English words as meaningful tokens, leading to very poor
   recall when the query is dominated by stop words.

4. **Title extraction** — QMD has title extractors for `.md` and `.org` files but not for DITA.
   Document titles fall back to filenames, which are less useful for result display.

## Reproducibility

```bash
# 1. Run setup (clones repos, installs deps)
./setup.sh

# 2. Run benchmark (indexes and searches)
./benchmark.sh

# Results are saved to results.txt
```

### Requirements

- Node.js >= 18 or Bun
- Git
- ~200MB disk space for the userguide repo + index
