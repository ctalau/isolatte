# Gemma 4 E4B — DITA Translation to Romanian using llama.cpp (source build)

This experiment repeats the `udocker-translategemma` experiment (translateGemma 4B → Romanian)
but uses the new **Gemma 4 E4B** model (`google/gemma-4-E4B-it`, released 2026-04-02),
built against the latest llama.cpp source to obtain `gemma4` architecture support.

## Model

- **Model**: `google/gemma-4-E4B-it` — Gemma 4 multimodal instruction model (text + vision)
- **GGUF source**: `ggml-org/gemma-4-E4B-it-GGUF`
- **Quantization**: `Q4_K_M` (5.34 GiB on disk)
- **Architecture**: `gemma4`, 42 transformer blocks, 131072 token context, 7.52 B params
- **llama.cpp**: built from source commit `a1cfb64` — required because the Docker image
  (build 8628) predates `gemma4` architecture support

## Source document

Same DITA topic as the previous experiment: `cf-review-tasks-projects.dita`
from [`oxygenxml/userguide`](https://github.com/oxygenxml/userguide).

Topic title: **Project Review Tasks vs Non-Project Review Tasks**

## Commands used

1. Build llama.cpp from source (needed for gemma4 support):

```bash
git clone --depth=1 https://github.com/ggml-org/llama.cpp /tmp/llama.cpp-src
cmake -B /tmp/llama.cpp-src/build -DLLAMA_BUILD_SERVER=ON -DCMAKE_BUILD_TYPE=Release \
  -S /tmp/llama.cpp-src
cmake --build /tmp/llama.cpp-src/build -j$(nproc) --target llama-server
```

2. Download the GGUF model:

```bash
wget -c -O gemma4-translation-experiment/models/gemma-4-e4b-it-Q4_K_M.gguf \
  "https://huggingface.co/ggml-org/gemma-4-E4B-it-GGUF/resolve/main/gemma-4-e4b-it-Q4_K_M.gguf"
```

Note: The first download attempt completed with the wrong byte count (5,300,081,792 instead
of 5,335,285,440). Running wget again with `-c` resumed and completed the remaining ~33 MB.

3. Start the llama.cpp server:

```bash
/tmp/llama.cpp-src/build/bin/llama-server \
  -m gemma4-translation-experiment/models/gemma-4-e4b-it-Q4_K_M.gguf \
  --jinja -c 8192 -t -1 --host 0.0.0.0 --port 8003
```

Note: `--no-jinja` (used in the previous experiment) causes a fatal startup error with
Gemma 4's complex Jinja chat template. The `--jinja` flag (full Jinja engine) is required.
The `/v1/chat/completions` endpoint is used instead of the raw `/completion` endpoint.

4. Send translation request:

```bash
curl -s http://localhost:8003/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "gemma4",
    "messages": [{"role": "user", "content": "Translate the following DITA XML..."}],
    "max_tokens": 4096,
    "temperature": 0.1
  }' > results/translation-response.json
```

Note: First attempt used `max_tokens: 2048` and hit the limit (finish_reason: length).
Retried with 4096, which completed successfully (finish_reason: stop, 3213 tokens generated).

## Measured results

- **Prompt tokens**: 964
- **Generated tokens**: 3213 (3.2× more than translategemma-4b's 1008)
- **Prompt throughput**: **11.67 tokens/s**
- **Generation throughput**: **7.16 tokens/s**
- **Stop reason**: `stop` (model produced a complete output)

### RAM breakdown

| Component | Size |
|---|---|
| Model buffers (AMX) | 2,917 MiB |
| Model buffers (CPU_Mapped) | 5,073 MiB |
| KV cache (non-SWA, 8192 cells) | — |
| KV cache (SWA, 2560 cells) | — |
| Compute buffer | 572 MiB |
| **Process RSS total** | **8,526 MiB (8.51 GiB)** |

## Comparison with translategemma-4b-it (previous experiment)

| Metric | translategemma-4b | gemma-4-E4B |
|---|---|---|
| Model | Gemma 3 4B fine-tuned | Gemma 4 E4B (7.52B params) |
| GGUF size | 2.4 GiB | 5.34 GiB |
| Prompt throughput | 69.62 tok/s | 11.67 tok/s |
| Generation speed | 5.05 tok/s | **7.16 tok/s** |
| Generated tokens | 1,008 | 3,213 |
| Process RAM | ~4 GiB (est.) | **8.51 GiB** |

Gemma 4 is **+42% faster** at generation (7.16 vs 5.05 tok/s) but **6× slower** at
prompt processing (11.67 vs 69.62 tok/s). The prompt slowdown is likely due to the larger
model size (7.52B vs 4B params) and the 8192-cell non-SWA KV cache being pre-allocated.
RAM usage is roughly double. Generated output is 3× longer due to more verbose formatting.

## Translation quality

### What was correct

- Preserved all XML tag names, attribute names, and IDs exactly
- Translated all human-readable text to Romanian
- Kept proper nouns untranslated: "Content Fusion", "Oxygen WebHelp Responsive", "Git", "DITA", "SME"
- `<i>`, `<b>`, `<ph>`, `<xref>`, `<term>`, `<ul>`, `<li>` inline markup preserved
- **Fixed vs translategemma-4b**: "page" is now correctly translated to "pagină"
- **Fixed vs translategemma-4b**: "non-project based" → "non-proiect" (the `non-` prefix is preserved)
- **Improved vs translategemma-4b**: "technical writers" → "scriitorii tehnici" (more accurate)

Sample translated title:
> **Sarcini de Revizuire de Proiect vs Sarcini de Revizuire Non-Proiect**

### Corrections needed (top 5)

Full analysis: `results/translation-analysis.md`

| # | Severity | Location | Issue |
|---|---|---|---|
| 1 | **Critical** | `<p id="p_fvr_c32_z1c">` and `user_roles` section | **Broken XML structure** — The `<ul>` was moved *outside* its enclosing `<p>`, splitting one paragraph into a `<p>` + a free-floating `<ul>`. Invalid DITA. |
| 2 | **High** | `<section id="user_roles">` | **Invented IDs** — Added `id="ul_user_roles"`, `id="li_sme"`, `id="li_author"` which do not exist in the source. Breaks DITA ID uniqueness guarantees. |
| 3 | Medium | `<p id="p_o2t_pl3_vxb">` | **"output" dropped** — "Oxygen WebHelp Responsive output" became just "Oxygen WebHelp Responsive" with no translation of "output" (previous experiment also failed here). |
| 4 | Medium | `<p id="p_o2t_pl3_vxb">` | **"browser interface" → "interfața browserului"** — "browserului" is a Romanian-ized borrowing; "interfața web" or "interfața browser-ului" would be more natural. |
| 5 | Low | `<ph product="fusion-cloud">` | **"pagină" placed after `</ph>` closing tag** — `<xref .../> pagină</ph>` puts the word inside the `<ph>`, but the `)` punctuation lands outside. Minor formatting mismatch. |

## Output files

- `results/translation-response.json` — raw `/v1/chat/completions` API response
- `results/translated.dita` — extracted translated DITA topic
- `results/server.log` — llama.cpp server startup and inference log

## Notes

- The `ggml-org/llama.cpp:server` Docker image (build 8628) does **not** support the `gemma4`
  architecture. Building from source is currently required. The `ggml-org/gemma-4-E4B-it-GGUF`
  repo is the only GGUF source available on day one; third-party quantizations (mradermacher,
  bartowski) had not appeared yet at time of writing.
- The model's GGUF uses a non-standard tensor naming convention (`bid=-1 xid=-1`) that
  produces a benign warning during loading but does not affect inference.
- Context was set to `-c 8192` to match the previous experiment; the model supports up to 131072.
