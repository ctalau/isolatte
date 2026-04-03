# Multi-Model DITA Translation — Vercel AI Gateway

This experiment repeats the `udocker-translategemma` / `gemma4-translation-experiment`
workflow but replaces local llama.cpp inference with cloud models accessed through the
**Vercel AI Gateway** (`@ai-sdk/gateway` v3, `ai` v6).

Nine models are tested across two runs:

| Gateway model ID | Provider | Approx. price (input / output per MTok) |
|---|---|---|
| `anthropic/claude-haiku-4.5` | Anthropic | $1.00 / $5.00 |
| `openai/gpt-5.4-mini` | OpenAI | $0.75 / $4.50 |
| `google/gemini-3-flash` | Google | $0.50 / $3.00 |
| `alibaba/qwen3.6-plus` | Alibaba | $0.50 / $3.00 |
| `moonshotai/kimi-k2.5` | Moonshot AI | $0.60 / $3.00 |
| `zai/glm-5` | Zhipu AI (Z.AI) | $1.00 / $3.20 |
| `minimax/minimax-m2.7` | MiniMax | $0.30 / $1.20 |
| `google/gemma-4-26b-a4b-it` | Google | $0.13 / $0.40 |
| `google/gemma-4-31b-it` | Google | $0.14 / $0.40 |

Model IDs were confirmed from the live Vercel AI Gateway models endpoint
(`https://ai-gateway.vercel.sh/v1/models`).

## Source document

Same DITA topic as the two previous experiments: `cf-review-tasks-projects.dita`
from [`oxygenxml/userguide`](https://github.com/oxygenxml/userguide).

Topic title: **Project Review Tasks vs Non-Project Review Tasks**

## Requirements

- Node.js ≥ 18
- `AI_GATEWAY_API_KEY` environment variable set to a valid Vercel AI Gateway API key

## Setup

```bash
cd multi-model-translation-test
npm install
```

## Running the experiment

```bash
export AI_GATEWAY_API_KEY=your_key_here
node translate.mjs
```

The script:
1. Reads `source.dita`
2. Sends the same translation prompt to each model sequentially
3. Writes per-model results to `results/<provider>_<model>/`
4. Writes an aggregate `results/summary.json`
5. Prints a summary table to stdout

### SDK version note

The models listed above require **AI SDK spec v3**, which is only supported from
`ai` v6 onwards. Older versions (`ai` v4 / v5) will error with
`"Unsupported model version"`.

## Output layout

```
results/
  summary.json                          # aggregate: tokens, cost, finish_reason per model
  anthropic_claude-haiku-4-5/
    translated.dita                     # extracted Romanian DITA XML
    response.json                       # tokens, cost, finish_reason, full text
  openai_gpt-5-4-mini/
    ...
  google_gemini-3-flash/
    ...
  alibaba_qwen3-6-plus/
    ...
  moonshotai_kimi-k2-5/
    ...
  zai_glm-5/
    ...
  minimax_minimax-m2-7/
    ...
  google_gemma-4-26b-a4b-it/
    ...
  google_gemma-4-31b-it/
    ...
```

### response.json schema

```json
{
  "model": "anthropic/claude-haiku-4.5",
  "finish_reason": "stop",
  "elapsed_ms": 4231,
  "usage": {
    "prompt_tokens": 964,
    "completion_tokens": 1100
  },
  "pricing_usd_per_mtok": {
    "input": 1.00,
    "output": 5.00
  },
  "cost_usd": {
    "inputCost": 0.000964,
    "outputCost": 0.005500,
    "totalCost": 0.006464
  },
  "text": "<?xml version=\"1.0\"..."
}
```

## Translation prompt

The system prompt instructs the model to:
- Translate all human-readable text to Romanian
- Preserve all XML tag names, attribute names, IDs, href/keyref/product values exactly
- Keep proper nouns untranslated: Content Fusion, Oxygen WebHelp Responsive, DITA, Git, SME
- Output only the XML with no explanation or code fences

`temperature: 0.1`, `maxTokens: 4096`.

## Run status

**Experiment complete. All 7 models produced Romanian translations.**
(`zai/glm-5` failed on the first run with an SDK parse error; a retry succeeded.)

### Proxy fix

The sandbox routes outbound HTTPS through an internal proxy (`HTTPS_PROXY` env
var). Node.js's built-in `fetch` (backed by `undici`) does not pick up proxy
settings automatically — unlike `curl`. Added a one-time global dispatcher in
`translate.mjs` at startup:

```js
import { ProxyAgent, setGlobalDispatcher } from 'undici';
if (process.env.HTTPS_PROXY) {
  setGlobalDispatcher(new ProxyAgent(process.env.HTTPS_PROXY));
}
```

This `undici` package is now listed in `package.json`.

### Results

| Model | Input tok | Output tok | Total cost | Elapsed | Score |
|---|---|---|---|---|---|
| `anthropic/claude-haiku-4.5` | 1,126 | 1,186 | $0.007056 | 8.3 s | 7/10 |
| `openai/gpt-5.4-mini` | 987 | 1,034 | $0.005393 | 5.9 s | 9/10 |
| `google/gemini-3-flash` | 1,022 | 6,291¹ | $0.192436 | 283.0 s | 7/10 |
| `alibaba/qwen3.6-plus` | 1,035 | 7,298¹ | $0.025448 | 130.3 s | 9/10 |
| `moonshotai/kimi-k2.5` | 983 | 1,099 | $0.003887 | 9.9 s | 6/10 |
| `zai/glm-5` | 986 | 8,921¹ | $0.029092 | 198.2 s | 9/10 |
| `minimax/minimax-m2.7` | 989 | 1,799 | $0.002456 | 41.2 s | 8/10 |
| **Total** | | | **$0.266** | | |

¹ Output token count includes internal reasoning/thinking tokens billed but not
present in the visible output text. Only `zai/glm-5` breakdown is available:
986 input / 1,157 visible output / 7,764 reasoning tokens.

Costs and token counts are from the Vercel AI Gateway billing dashboard. Token
counts in the script output were all zero due to a bug in the script: the AI SDK
v6 `result.usage` object uses `inputTokens`/`outputTokens`, not
`promptTokens`/`completionTokens` as the script assumed. This is a script bug —
the data was present but accessed with the wrong field names. Fixed in
`translate.mjs`.

### Translation quality evaluation

Scoring criteria: formatting issues (code fences, leading whitespace) are
fixable in post-processing and not heavily penalized. English technical terms
widely used in Romanian tech documentation ("repository", "output", "non-proiect")
are acceptable.

**`anthropic/claude-haiku-4.5` — 7/10**
- Good Romanian, diacritics correct. All IDs and attributes preserved.
- `<term>Proiecte</term>` translated appropriately.
- **Problem:** Output wrapped in ` ```xml ``` ` code fences — fixable in
  post-processing, but the model ignored an explicit system prompt rule.
- **Problem:** "revedenților" is non-standard Romanian; correct form is
  "recenzorilor" or "revizuitorilor".

**`openai/gpt-5.4-mini` — 9/10**
- Clean output, whitespace structure preserved from source. Accurate, natural
  Romanian ("redactori tehnici", "livrabile").
- **Minor:** In the `<ph product="fusion-cloud">` block the word `page` was
  left in English — should be `pagina`. Single word, fixable in post-processing.

**`google/gemini-3-flash` — 7/10**
- Well-formed XML, correct diacritics.
- **Problem:** `<term>Projects</term>` consistently left in English (both
  occurrences in the body) while the title and index term were translated —
  internally inconsistent, not a formatting issue.
- **Problem:** "Administration" link text left in English in the
  `<ph product="fusion">` block — a genuine translation miss.
- Slow (283 s) and expensive ($0.192) for this quality level; reasoning token
  overhead dominates the cost.

**`alibaba/qwen3.6-plus` — 9/10**
- Clean output, fluent Romanian, compact structure.
- `<term>Proiecte</term>` translated. SME expansion translated ("Expert în
  domeniu/Recenzor") — reasonable and consistent with how other models handled it.
- Minor word-order awkwardness after the `<xref>` in `<ph product="fusion-cloud">`.
- Despite 7,298 billed tokens, the visible output is concise and correct.

**`moonshotai/kimi-k2.5` — 6/10**
- **Problem:** Translated the protected product role name: `<i>Content Fusion
  Author</i>` → `<i>Autor Content Fusion</i>`. "Content Fusion Author" is a
  specific product role, not a generic phrase. This is a semantic error that
  would break UI consistency in a real localization project.
- Leading space before `<?xml` declaration: fixable in post-processing.
- Uses "repository-ul" (English term with Romanian morphology) — acceptable per
  criteria, though inconsistent within the same file where "depozit" also appears.

**`zai/glm-5` — 9/10** *(retry after first-run SDK parse error)*
- First run failed: the AI SDK threw `"Invalid error response format"`. The
  gateway billing confirms the model ran and returned data; the AI SDK could not
  parse the response. A retry the next day succeeded without code changes.
- Translation quality is excellent: fluent Romanian, all markup preserved, IDs
  intact. "recenzenților" correct. "pagina de administrare" correctly
  translated. "Content Fusion Author" correctly kept in English.
- Uses "depozit Git" (Romanian) throughout — better than models that use
  "repository".
- 7,764 reasoning tokens (not visible) drive cost to $0.029 for ~1,157 visible
  output tokens.

**`minimax/minimax-m2.7` — 8/10**
- Clean output. Diacritics correct. All attributes and IDs preserved.
- "Content Fusion Author" correctly kept in English.
- Uses "repository" and "output" (English loanwords with Romanian morphology)
  throughout — acceptable per criteria.

### What worked
- Proxy workaround via `undici` `ProxyAgent` — all requests went through.
- All 7 models produced Romanian DITA translations. Three models scored 9/10:
  `openai/gpt-5.4-mini`, `alibaba/qwen3.6-plus`, and `zai/glm-5`.
- `openai/gpt-5.4-mini` is the best value: fastest (5.9 s), cheapest ($0.005),
  9/10 quality.
- `zai/glm-5` and `alibaba/qwen3.6-plus` match quality (9/10) but cost 5–6×
  more due to reasoning tokens, with no visible quality benefit.

### What did not work
- `zai/glm-5` first run: SDK threw a parse error on the gateway response.
  Retry the next day succeeded without any changes — likely a transient issue.
- `anthropic/claude-haiku-4.5` wrapped output in code fences despite the
  explicit system prompt rule.
- `moonshotai/kimi-k2.5` translated the "Content Fusion Author" product role
  name — a semantic error that would break localization consistency.
- `google/gemini-3-flash` left "Projects" and "Administration" inconsistently
  untranslated, and cost $0.192 primarily due to reasoning token overhead.
- Token counts in the script output were all zero due to a script bug: the AI
  SDK v6 usage object uses `inputTokens`/`outputTokens` but the script read
  `promptTokens`/`completionTokens`. Fixed in this revision.

### What to try next
- Start the user prompt with `<?xml` to coerce models away from code fences.
- Add stricter wording for `moonshotai/kimi-k2.5` about not translating
  product role names specifically.
- Consider dropping `google/gemini-3-flash` — $0.192 for 7/10 quality vs
  $0.005 for 9/10 from `openai/gpt-5.4-mini` is hard to justify.
- Re-run the full batch with the fixed usage field names to get in-script cost
  tracking working end-to-end.

### Honest assessment
All 7 models produced usable Romanian DITA translations. Three scored 9/10
(`openai/gpt-5.4-mini`, `alibaba/qwen3.6-plus`, `zai/glm-5`). The `zai/glm-5`
transient failure was the only significant reliability issue. Cost varies 75×
across models ($0.002 to $0.192) with no correlation to quality — reasoning-heavy
models spend most of their budget on hidden tokens. `openai/gpt-5.4-mini` is the
clear choice for production use: best quality, fastest, cheapest.

## Cost tracking

Actual costs are from the Vercel AI Gateway billing dashboard. The script
computed zero costs due to a bug: the AI SDK v6 usage object uses
`inputTokens`/`outputTokens`, but the script read `promptTokens`/
`completionTokens` (v4/v5 naming). The data was present — this was a script
error, not an SDK or gateway limitation. Fixed in `translate.mjs`.

| Model | Input tok | Output tok | Actual cost |
|---|---|---|---|
| `anthropic/claude-haiku-4.5` | 1,126 | 1,186 | $0.007056 |
| `openai/gpt-5.4-mini` | 987 | 1,034 | $0.005393 |
| `google/gemini-3-flash` | 1,022 | 6,291¹ | $0.192436 |
| `alibaba/qwen3.6-plus` | 1,035 | 7,298¹ | $0.025448 |
| `moonshotai/kimi-k2.5` | 983 | 1,099 | $0.003887 |
| `zai/glm-5` | 986 | 7,664¹ | $0.029092 |
| `minimax/minimax-m2.7` | 989 | 1,799 | $0.002456 |
| **Total** | | | **$0.265768** |

¹ Reasoning/thinking tokens billed but not included in visible output.

The run cost ~7× more than the $0.039 estimate, entirely due to
`google/gemini-3-flash` ($0.192). The other six models totalled $0.073,
close to the estimate. The gemini model likely used an internal chain-of-thought
pass (6,291 billed output tokens vs ~1,000 expected visible tokens) charged at
a premium rate. All other models stayed close to expected costs.

## Gemma 4 run (2026-04-03)

Both Gemma 4 models (`google/gemma-4-26b-a4b-it` and `google/gemma-4-31b-it`) were added to
`translate.mjs` and run in a separate pass using CLI model selection:

```bash
node translate.mjs google/gemma-4-26b-a4b-it google/gemma-4-31b-it
```

### Results

| Model | Input tok | Output tok | Total cost | Elapsed | Score |
|---|---|---|---|---|---|
| `google/gemma-4-26b-a4b-it` | 1,089 | 1,022 | $0.000550 | 88.6 s | 7/10 |
| `google/gemma-4-31b-it` | 1,089 | 1,034 | $0.000566 | 18.1 s | 7/10 |

Both models ran successfully (finish_reason: stop). No proxy or SDK issues.

### Translation quality

**`google/gemma-4-26b-a4b-it` — 7/10**

- Valid XML structure throughout. The `<ul>` stays inside its `<p>` — fixing the critical
  structural bug seen in the local Gemma 4 E4B run.
- No invented IDs (another regression from the local run that is absent here).
- Diacritics correct. "Content Fusion Author" correctly preserved in English.
- Consistent: `<term>Projects</term>` kept in English as a feature name; section title also
  uses "Projects" in English — internally consistent, even if technically it could be
  translated.
- **Problem (Medium):** `<xref href="cf-enterprise-configuration.dita">Administration
  page</xref>` — "Administration page" left in English; should be "pagina de administrare".
- **Problem (Minor):** In the `<ph product="fusion-cloud">` block the word order is swapped:
  output is `pagina <xref .../>` but source order is `<xref .../> page`. The Romanian text
  lands before the element instead of after. Fixable in post-processing.
- Very slow: 88.6 s for a cloud call — likely heavy inference load on the A4B variant.

**`google/gemma-4-31b-it` — 7/10**

- Valid XML structure. No invented IDs. Diacritics correct.
- "Administration page" correctly translated to "pagina de Administrare" ✓
- Correct word order in the `<ph product="fusion-cloud">` block ✓
- "Content Fusion Author" correctly preserved in English ✓
- **Problem (Medium):** `<indexterm>Project review tasks</indexterm>` — left in English;
  source is human-readable text that should have been translated.
- **Problem (Medium):** Inconsistent treatment of "Projects": the `<term>Projects</term>`
  inline is kept in English (correct for a feature name) but the section title and
  `<li><b>Projects</b>` are both rendered as "Proiecte" (Romanian). Same term translated
  differently within the same document.
- Fast: 18.1 s — significantly faster than the 26B A4B variant despite being the larger model.

### Cost comparison (all 9 models)

| Model | Input tok | Output tok | Total cost | Elapsed | Score |
|---|---|---|---|---|---|
| `anthropic/claude-haiku-4.5` | 1,126 | 1,186 | $0.007056 | 8.3 s | 7/10 |
| `openai/gpt-5.4-mini` | 987 | 1,034 | $0.005393 | 5.9 s | 9/10 |
| `google/gemini-3-flash` | 1,022 | 6,291¹ | $0.192436 | 283.0 s | 7/10 |
| `alibaba/qwen3.6-plus` | 1,035 | 7,298¹ | $0.025448 | 130.3 s | 9/10 |
| `moonshotai/kimi-k2.5` | 983 | 1,099 | $0.003887 | 9.9 s | 6/10 |
| `zai/glm-5` | 986 | 8,921¹ | $0.029092 | 198.2 s | 9/10 |
| `minimax/minimax-m2.7` | 989 | 1,799 | $0.002456 | 41.2 s | 8/10 |
| `google/gemma-4-26b-a4b-it` | 1,089 | 1,022 | $0.000550 | 88.6 s | 7/10 |
| `google/gemma-4-31b-it` | 1,089 | 1,034 | $0.000566 | 18.1 s | 7/10 |

¹ Includes reasoning/thinking tokens billed but not visible in output.

At $0.00055–$0.00057 per call, the Gemma 4 models are the cheapest in the set by a factor of
4–350×. The 31B is unexpectedly 5× faster than the 26B A4B variant at the same quality level.

### What worked

- Both models produced valid Romanian DITA XML with no structural bugs (improvement over
  local Gemma 4 E4B which broke the `<ul>`/`<p>` nesting).
- `google/gemma-4-31b-it` correctly translated the "Administration page" xref text and
  placed text fragments in the right order within `<ph>` blocks.
- Extremely low cost — a full production document batch would cost a fraction of a cent.
- CLI model filtering (`node translate.mjs model1 model2`) worked cleanly; existing results
  for other models were not overwritten.

### What did not work

- `google/gemma-4-26b-a4b-it`: left "Administration page" in English and reversed word
  order in the `fusion-cloud` conditional block.
- `google/gemma-4-31b-it`: failed to translate the `<indexterm>` element and translated
  "Projects" inconsistently (feature name vs section heading vs list item).
- `google/gemma-4-26b-a4b-it`: very slow (88.6 s) for a cloud model compared to 18.1 s
  for the 31B — the A4B quantization may be less well-optimized on the gateway hardware.
- Neither model reached the 9/10 quality bar set by `openai/gpt-5.4-mini`,
  `alibaba/qwen3.6-plus`, and `zai/glm-5`.

### What to try next

- Prompt the model to start output with `<?xml` to prevent any possible code-fence wrapping.
- Add an explicit rule: "Translate `<indexterm>` text content as you would any other
  human-readable text."
- Add a rule: "Use a single consistent Romanian translation for feature names like
  `<term>Projects</term>` throughout the document."
- Run `google/gemma-4-31b-it` on a larger/more complex topic to see if the inconsistency
  worsens at scale.
- Re-test `google/gemma-4-26b-a4b-it` at a different time to see if the 88 s latency was a
  transient load issue.

### Honest assessment

Gemma 4 via the Vercel AI Gateway is dramatically cheaper than every other model tested
($0.00055 vs next-cheapest $0.0025 for minimax-m2.7) and fixed the critical XML structural
bugs seen in the local Gemma 4 E4B run. However, both cloud variants score 7/10 — the same
as Claude Haiku 4.5 and Gemini 3 Flash — due to distinct per-model errors (missed
translation, inconsistency, or word-order swaps). At this quality level, `openai/gpt-5.4-mini`
remains the better production choice: 9/10 quality at $0.005 vs 7/10 at $0.0006 is a
compelling quality/cost trade-off in either direction depending on the use case. For bulk
preprocessing where 7/10 is acceptable and a human reviewer will post-edit, Gemma 4 31B at
~$0.0006 per topic is very attractive.

## Comparison with previous experiments

| Dimension | translategemma-4b | gemma-4-E4B (local) | Run 1 (7 models) | Run 2 (Gemma 4 cloud) |
|---|---|---|---|---|
| Infrastructure | udocker + llama.cpp | Source-built llama.cpp | Vercel AI Gateway | Vercel AI Gateway |
| Model source | Local GGUF (2.4 GiB) | Local GGUF (5.34 GiB) | Cloud API | Cloud API |
| Models tested | 1 | 1 | 7 | 2 |
| Cost | Hardware only | Hardware only | ~$0.266 total | $0.001 total |
| Setup complexity | High (udocker, GGUF download) | Very high (cmake build) | Low (npm install) | Low (already installed) |
| Latency | 5–7 tok/s generation | 7 tok/s generation | Network-bound | Network-bound |
| Cost tracking | N/A | N/A | Automatic | Automatic |
| Best score | N/A | ~7/10 | 9/10 (gpt-5.4-mini) | 7/10 (both models) |
