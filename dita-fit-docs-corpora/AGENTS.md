# AGENTS.md — dita-fit-docs-corpora

## Overarching goal

Port **all Microsoft Learn content** (starting with `MicrosoftDocs/sql-docs` and
`MicrosoftDocs/azure-docs`, then the rest of the ~190 `MicrosoftDocs` repositories) to DITA, so that:

1. **every existing strength is kept** — nothing a reader, author, contributor or the build
   pipeline relies on today may be lost (version ranges, reader-side tabs and pivots, includes,
   `:::code` snippets from sample repos, redirects, `ms.*` metadata, PR validation, localization
   controls, the Markdown pull-request experience for public contributors); and
2. **real benefits are added** on top — keys instead of paths and tiny includes, element-level
   reuse, controlled vocabularies via subject schemes, branch filtering, Schematron checks with
   quick fixes, typed topics, and so on.

If a step would trade away an existing strength for a DITA benefit, that is a regression. Record
it as an open problem; do not quietly accept it.

## Two steps

### Step 1 — syntactical port (lossless)

- Map each source file almost one-to-one to (a specialization of) DITA: one `.md` → one topic,
  one `toc.yml` → one map, one include → one reusable topic or warehouse fragment, one
  `docfx.json` / `.openpublishing.*.json` → map metadata + build configuration.
- Every Learn Markdown extension gets a dedicated element or attribute in a **Learn
  specialization** (working name: `learn-dita`) instead of being approximated by a generic DITA
  construct. Example: `::: zone pivot` → `<zone pivot="…">`, `monikerRange` → `@moniker-range`
  with the original expression kept verbatim.
- The port must be **mechanical and reversible**: a converter (Markdown → DITA) plus a reverse
  converter (DITA → Markdown) whose round-trip yields the same rendered output. Diffs against the
  original Markdown must be explainable whitespace/normalization only.
- Parity is checked against rendered output (HTML from the DITA build vs. the published Learn
  page, per moniker / pivot / tab), not by eye.
- No restructuring, retyping, deduplication or renaming in this step.

### Step 2 — quality refactorings (one at a time)

Each refactoring is a separate, measured change on top of the step-1 output, for example:

- tiny "variable" includes → `keyref` text keys; path links → key-based links;
- version/moniker ranges → subject-scheme hierarchy + DITAVAL / branch filtering, with ranges
  kept as the authoring form and expanded by the build;
- hand-pasted duplicates → conref/conkeyref from warehouse topics;
- free-form articles → typed `task` / `concept` / `reference` / `troubleshooting` topics where
  the classification is reliable;
- cross-file rules (pivot declared, moniker subset, terminology, case-exact paths) → Schematron
  with SQF quick fixes.

For every refactoring, record: what it improves (with a count from the corpus), what it costs
authors, whether rendered output stays identical (it should, unless the change is the intended
fix), and how to roll it back.

## Rules for work in this folder

- Keep everything for this experiment inside `dita-fit-docs-corpora/`.
- Pin corpus commits (see `README.md`); every number must be reproducible from a script in
  `tools/` or from `run.sh`.
- Clone corpora into a scratch/work directory, never into the repo.
- Reference material lives in `docs/` (e.g. `docs/learn-features-to-dita.html`, the catalogue of
  Learn features, their build/test infra and their DITA mapping). Update it when a mapping
  decision changes.
- `docs/learn-style-ai-to-dita.html` covers the style guide, Copilot instructions, skills,
  `ai-usage` metadata and style build rules: each rule, its measured breakage
  (`tools/style_signals.py` → `results/style-*.tsv`) and where it lives after the port
  (made impossible by markup, semantic markup, Schematron, or prose for AI/Acrolinx).
- AI instructions and skills for this work follow the same principle: a rule a schema or
  Schematron can decide belongs in a check the agent runs, not in prompt text. Step 1 keeps the
  existing Markdown-oriented instructions unchanged, because they still govern the generated
  Markdown.
- Report honestly: what worked, what did not, what to try next, and whether it can work.
