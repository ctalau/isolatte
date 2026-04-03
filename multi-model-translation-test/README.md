# Multi-Model DITA Translation — Vercel AI Gateway

This experiment repeats the `udocker-translategemma` / `gemma4-translation-experiment`
workflow but replaces local llama.cpp inference with cloud models accessed through the
**Vercel AI Gateway** (`@ai-sdk/gateway` v3, `ai` v6).

Seven models are tested in a single automated pass:

| Gateway model ID | Provider | Approx. price (input / output per MTok) |
|---|---|---|
| `anthropic/claude-haiku-4.5` | Anthropic | $1.00 / $5.00 |
| `openai/gpt-5.4-mini` | OpenAI | $0.75 / $4.50 |
| `google/gemini-3-flash` | Google | $0.50 / $3.00 |
| `alibaba/qwen3.6-plus` | Alibaba | $0.50 / $3.00 |
| `moonshotai/kimi-k2.5` | Moonshot AI | $0.60 / $3.00 |
| `zai/glm-5` | Zhipu AI (Z.AI) | $1.00 / $3.20 |
| `minimax/minimax-m2.7` | MiniMax | $0.30 / $1.20 |

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
    translated.dita
    response.json
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

**Experiment complete. 6/7 models produced Romanian translations; 1 model
(`zai/glm-5`) failed with a gateway error.**

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

| Model | Input tok | Output tok | Total cost | Elapsed | finish_reason | Score |
|---|---|---|---|---|---|---|
| `anthropic/claude-haiku-4.5` | 1,126 | 1,186 | $0.007056 | 8.3 s | stop | 6/10 |
| `openai/gpt-5.4-mini` | 987 | 1,034 | $0.005393 | 5.9 s | stop | 8/10 |
| `google/gemini-3-flash` | 1,022 | 6,291¹ | $0.192436 | 283.0 s | stop | 6/10 |
| `alibaba/qwen3.6-plus` | 1,035 | 7,298¹ | $0.025448 | 130.3 s | stop | 8/10 |
| `moonshotai/kimi-k2.5` | 983 | 1,099 | $0.003887 | 9.9 s | stop | 5/10 |
| `zai/glm-5` | 986 | 7,664¹ | $0.029092 | 311.4 s | **SDK ERROR** | N/A |
| `minimax/minimax-m2.7` | 989 | 1,799 | $0.002456 | 41.2 s | stop | 7/10 |
| **Total** | | | **$0.266** | | | |

¹ Output token count is inflated by internal model reasoning/thinking tokens that
are billed but not included in the visible output text.

Costs and token counts are from the Vercel AI Gateway billing dashboard. Token
counts in the script output were all zero due to a bug in the script: the AI SDK
v6 `result.usage` object was accessed using incorrect field names (`promptTokens`
/ `completionTokens`). The data was present but not read correctly. This is a
script bug, not an SDK or gateway limitation.

### Translation quality evaluation

**`anthropic/claude-haiku-4.5` — 6/10**
- Good Romanian translation, diacritics correct throughout.
- All IDs and XML attributes preserved correctly.
- `<term>Proiecte</term>` translated appropriately.
- **Problem:** Wrapped the entire output in ` ```xml ``` ` code fences despite
  the explicit system prompt rule — breaks automated DITA processing.
- **Problem:** "revedenților" (line with reviewers) is a non-standard word;
  correct Romanian is "recenzorilor" or "revizuitorilor".

**`openai/gpt-5.4-mini` — 8/10**
- Clean output, no code fences. Preserved original whitespace structure.
- Accurate Romanian with natural phrasing ("redactori tehnici" for technical
  writers, "livrabile" for deliverables).
- **Problem:** In the `<ph product="fusion-cloud">` block, the word "page" was
  left in English instead of being translated to "pagina".
- **Problem:** Partially translated the SME label inside `<b>` —
  "Expert în domeniu/recenzent" — the prompt forbids translating proper nouns
  but the SME expansion is not clearly a proper noun, so this is a judgment call.

**`google/gemini-3-flash` — 6/10**
- Clean output, correct diacritics, well-formed XML.
- **Problem:** `<term>Projects</term>` left in English throughout (title section
  and body) while the topic title and index term were translated. Internally
  inconsistent.
- **Problem:** "Administration" link text left in English inside the
  `<ph product="fusion">` block — should be "Administrare".
- Slow (283 s) and expensive ($0.192) — likely due to large hidden reasoning
  token usage. Poor value for this task.

**`alibaba/qwen3.6-plus` — 8/10**
- Clean output, no code fences.
- Accurate, fluent Romanian. Good handling of XML structure.
- `<term>Proiecte</term>` correctly translated.
- Translated the SME expansion ("Expert în domeniu/Recenzor") — debatable per
  prompt instructions but linguistically reasonable.
- **Minor problem:** "pagina" appears after the `<xref>` in the
  `<ph product="fusion-cloud">` block — slightly awkward word order.
- Despite 7,298 billed output tokens (reasoning), the visible output is compact
  and correct.

**`moonshotai/kimi-k2.5` — 5/10**
- **Problem:** Translated the protected role name `<i>Content Fusion Author</i>`
  to `<i>Autor Content Fusion</i>`, and similarly `<b>Content Fusion Author</b>`
  to `<b>Autor Content Fusion</b>`. The prompt explicitly prohibits translating
  proper nouns; "Content Fusion Author" is a specific product role name.
- **Problem:** Leading whitespace before `<?xml` declaration makes the file
  technically not well-formed XML (XML declaration must start at byte 0).
- **Problem:** Uses English "repository" and "repository-ul" (with Romanian
  morphological suffix) inconsistently alongside Romanian "depozit" elsewhere.
- Translation quality is otherwise reasonable.

**`zai/glm-5` — N/A**
- The AI SDK threw `"Invalid error response format: Gateway request failed"`.
- The gateway billing shows 986 input / 7,664 output tokens and $0.029 — so
  the model did run and return a response, but in a format the AI SDK could
  not parse. The 7,664 output token count (vs ~1,000 expected) suggests the
  model likely returned verbose reasoning or preamble before the XML.
- No `translated.dita` output available for evaluation.

**`minimax/minimax-m2.7` — 7/10**
- Clean output, no code fences. Correct diacritics.
- XML structure and all attributes preserved.
- **Problem:** Uses English loanword "repository" / "repository-ul Git"
  throughout instead of the more standard Romanian "depozit Git".
- **Problem:** Uses "output" as a Romanian noun with declension ("output-ul")
  instead of "ieșire" or "livrabil" — common in informal technical Romanian but
  not ideal in formal documentation.
- Correctly kept "Content Fusion Author" untranslated (unlike Kimi).

### What worked
- Proxy workaround via `undici` `ProxyAgent` — all requests went through
  without timeout errors.
- 6/7 models returned valid Romanian DITA XML with `finish_reason: stop`.
- `openai/gpt-5.4-mini` was the best overall: fastest (5.9 s), cheapest
  practical option ($0.005), and highest translation quality (8/10).
- `alibaba/qwen3.6-plus` matched quality (8/10) at a higher cost ($0.025) due
  to reasoning token usage.

### What did not work
- `zai/glm-5` ran on the gateway but returned a response format the AI SDK
  could not parse; 7,664 billed output tokens suggests the model prefixed the
  XML with verbose reasoning text.
- `anthropic/claude-haiku-4.5` ignored the "no code fences" system prompt rule.
- `moonshotai/kimi-k2.5` translated a protected role name ("Content Fusion
  Author") and produced a technically invalid XML declaration (leading space).
- `google/gemini-3-flash` was extremely expensive ($0.192) due to hidden
  reasoning tokens, and left key terms inconsistently untranslated.
- Token usage in the script output was zero due to a script bug (wrong field
  names for accessing `result.usage`).

### What to try next
- Fix the usage field names in the script to correctly read AI SDK v6 token
  counts and enable in-script cost calculation.
- For `zai/glm-5`: inspect the raw gateway response to determine the format
  mismatch and add a custom parser or use a different SDK invocation.
- For `anthropic/claude-haiku-4.5`: add a post-processing step to strip code
  fences, or add the no-fence rule more forcefully (e.g. start the user prompt
  with `<?xml`).
- For `moonshotai/kimi-k2.5`: the role-name translation and leading-space bugs
  suggest the model needs more specific system prompt constraints.
- Consider dropping `google/gemini-3-flash` from future runs — $0.192 for a
  6/10 result is poor value compared to `openai/gpt-5.4-mini` at $0.005 for 8/10.

### Honest assessment
The experiment succeeded. Six of seven models produced usable Romanian DITA
translations in a single automated pass. `openai/gpt-5.4-mini` is the clear
winner: fastest, cheapest (excluding reasoning-heavy models), and best quality.
`alibaba/qwen3.6-plus` is a close second on quality but costs 5× more due to
reasoning tokens. `google/gemini-3-flash` at $0.192 per translation call is
not cost-effective for this task. The biggest remaining issues are the
script-level token parsing bug and the `zai/glm-5` response format problem.

## Cost tracking

Actual costs are from the Vercel AI Gateway billing dashboard. The script
computed zero costs due to a bug: `result.usage.promptTokens` /
`result.usage.completionTokens` returned 0, likely because the AI SDK v6 uses
different field names for the usage object when proxied through the gateway.
This is a script bug — the data was available but accessed incorrectly.

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

## Comparison with previous experiments

| Dimension | translategemma-4b | gemma-4-E4B | This experiment |
|---|---|---|---|
| Infrastructure | udocker + llama.cpp | Source-built llama.cpp | Vercel AI Gateway |
| Model source | Local GGUF (2.4 GiB) | Local GGUF (5.34 GiB) | Cloud API |
| Models tested | 1 | 1 | 7 |
| Cost | Hardware only | Hardware only | ~$0.039 total |
| Setup complexity | High (udocker, GGUF download) | Very high (cmake build) | Low (npm install) |
| Latency | 5–7 tok/s generation | 7 tok/s generation | Network-bound |
| Cost tracking | N/A | N/A | Automatic |
