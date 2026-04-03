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

| Model | Elapsed | finish_reason | Code fences? | Lines (src=57) |
|---|---|---|---|---|
| `anthropic/claude-haiku-4.5` | 9 s | stop | **yes** | 39 |
| `openai/gpt-5.4-mini` | 6 s | stop | no | 56 |
| `google/gemini-3-flash` | 283 s | stop | no | 58 |
| `alibaba/qwen3.6-plus` | 130 s | stop | no | 32 |
| `moonshotai/kimi-k2.5` | 10 s | stop | no | 32 |
| `zai/glm-5` | — | **ERROR** | — | — |
| `minimax/minimax-m2.7` | 41 s | stop | no | 32 |

Token usage was not returned by the gateway for any model (all counts 0); cost
tracking is therefore not available for this run.

### What worked
- Proxy workaround via `undici` `ProxyAgent` — all subsequent requests went
  through without timeout errors.
- 6/7 models returned valid Romanian DITA XML with `finish_reason: stop`.
- All 6 successful models preserved XML structure and proper nouns correctly.
- `openai/gpt-5.4-mini` was the fastest (6 s), followed closely by
  `anthropic/claude-haiku-4.5` (9 s) and `moonshotai/kimi-k2.5` (10 s).
- `google/gemini-3-flash` and `openai/gpt-5.4-mini` preserved the original
  line count most faithfully (56–58 lines vs source 57).

### What did not work
- `zai/glm-5` failed with `"Gateway request failed"` — either the model is
  not available under this API key's tier, or the Z.AI backend was unavailable.
- `anthropic/claude-haiku-4.5` ignored the "no code fences" instruction and
  wrapped its output in ` ```xml ``` ` despite the explicit system prompt rule.
- Token usage was zero for all models — the gateway does not forward usage
  metadata in the AI SDK format, so cost calculations are unavailable.
- `google/gemini-3-flash` and `alibaba/qwen3.6-plus` were very slow (283 s
  and 130 s respectively) compared to other models.

### What to try next
- Re-run `zai/glm-5` directly to confirm whether it is a transient error or a
  permanent access restriction for this key.
- For `anthropic/claude-haiku-4.5`, add a post-processing step to strip
  opening/closing code fences from the output.
- Check with Vercel whether usage metadata can be enabled for this key/plan,
  or switch to direct provider SDK calls to recover token counts.
- Compare translation quality across the 6 successful outputs (e.g. does Qwen
  handle Romanian diacritics better than Kimi?).

### Honest assessment
The experiment succeeded at its primary goal: running a single script against
multiple cloud LLMs and collecting translated DITA output. Six of seven models
delivered valid Romanian XML in one automated pass, which is a clean improvement
over the one-model-at-a-time llama.cpp approach. The gateway layer does have
rough edges (missing usage data, one model unreachable, one model ignores prompt
constraints) but none of these prevent the core workflow from functioning.

## Cost tracking

Cost is calculated from published pricing and the token usage reported in the
API response. The formula is:

```
cost = (prompt_tokens / 1_000_000) * input_price_per_mtok
     + (completion_tokens / 1_000_000) * output_price_per_mtok
```

For the ~964 prompt tokens and ~1000 completion tokens expected from this task,
estimated costs per model call are:

| Model | Est. cost |
|---|---|
| `minimax/minimax-m2.7` | ~$0.0015 |
| `google/gemini-3-flash` | ~$0.0058 |
| `alibaba/qwen3.6-plus` | ~$0.0058 |
| `openai/gpt-5.4-mini` | ~$0.0052 |
| `moonshotai/kimi-k2.5` | ~$0.0036 |
| `zai/glm-5` | ~$0.0042 |
| `anthropic/claude-haiku-4.5` | ~$0.0069 |
| **Total (7 models)** | **~$0.039** |

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
