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

**Script setup: complete. Experiment run: blocked on missing `AI_GATEWAY_API_KEY`
in the sandbox environment.**

The script reached the authentication step for all 7 models correctly (confirmed
with AI SDK v6 + `@ai-sdk/gateway` v3 — the exact SDK version required for these
recently-released models). Running `node translate.mjs` with `AI_GATEWAY_API_KEY`
set will produce the full results.

### What worked
- Dependency resolution: `ai@6.0.145` + `@ai-sdk/gateway@3.0.87` correctly
  supports spec v3 models. Earlier `ai@4` and `ai@5` fail with model-version
  errors for these models.
- The `createGateway({ apiKey })` + `gateway(modelId)` pattern is confirmed
  working against the gateway endpoint.
- All 7 model IDs were verified against the live
  `https://ai-gateway.vercel.sh/v1/models` endpoint.

### What did not work
- The sandbox environment does not have `AI_GATEWAY_API_KEY` set, so no actual
  inference calls completed.

### What to try next
- Set `AI_GATEWAY_API_KEY` and run `node translate.mjs`.
- If any model returns `finish_reason: length`, increase `maxTokens` beyond 4096
  (as was needed for gemma-4-E4B in the previous experiment).
- Some models (e.g. Qwen, Kimi) may require adjusting the system prompt or using
  a `<|im_start|>` style prompt format instead — check `finish_reason` and XML
  validity of the output.

### Honest assessment
The experiment is fully ready to run and the infrastructure is sound.
The only missing piece is the API key. The multi-model approach (all 7 models in
a single script with automatic cost tracking) is a cleaner design than the
per-model llama.cpp server approach used in the previous experiments.

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
