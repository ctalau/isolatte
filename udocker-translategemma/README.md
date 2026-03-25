# translateGemma 4B — DITA Translation to Romanian using `udocker`

This experiment uses the `google/translategemma-4b-it` model (via GGUF + llama.cpp)
to translate an Oxygen XML Content Fusion DITA topic from English to Romanian,
preserving the full DITA structure.

## Model

- **Model**: `google/translategemma-4b-it` — a Gemma 3 4B model fine-tuned by Google
  for multilingual translation across 55 languages.
- **GGUF source**: `mradermacher/translategemma-4b-it-GGUF`
- **Quantization**: `Q4_K_M` (2.4 GiB on disk, 2.31 GiB reported)
- **Architecture**: `gemma3`, 34 transformer blocks, 131072 token context

## Source document

DITA topic: `cf-review-tasks-projects.dita` from [`oxygenxml/userguide`](https://github.com/oxygenxml/userguide)
(path: `DITA/topics/cf-review-tasks-projects.dita`)

Topic title: **Project Review Tasks vs Non-Project Review Tasks**

## Commands used

1. Install and initialize `udocker`:

```bash
python3 -m pip install --user udocker
~/.local/bin/udocker --allow-root install
```

2. Pull and prepare llama.cpp server image:

```bash
~/.local/bin/udocker --allow-root pull ghcr.io/ggml-org/llama.cpp:server
~/.local/bin/udocker --allow-root create --name=translategemma-4b ghcr.io/ggml-org/llama.cpp:server
~/.local/bin/udocker --allow-root setup --execmode=P1 translategemma-4b
```

3. Download the GGUF model:

```bash
wget -c -O udocker-translategemma/models/translategemma-4b-it.Q4_K_M.gguf \
  "https://huggingface.co/mradermacher/translategemma-4b-it-GGUF/resolve/main/translategemma-4b-it.Q4_K_M.gguf"
```

4. Start the llama.cpp server:

```bash
~/.local/bin/udocker --allow-root run --publish=8001:8080 \
  --volume=/path/to/udocker-translategemma/models:/models \
  translategemma-4b \
  -m /models/translategemma-4b-it.Q4_K_M.gguf \
  --no-jinja -c 8192 -t -1 --host 0.0.0.0 --port 8080
```

Note: `--no-jinja` is required because the model's built-in Jinja chat template
expects a multimodal structured payload (`type`, `source_lang_code`, `target_lang_code`,
`text`, `image` mapping) that is incompatible with the plain-text `/completion` endpoint.
The raw Gemma instruction format (`<start_of_turn>` / `<end_of_turn>`) is used instead.

5. Send translation request:

```bash
curl -s http://localhost:8001/completion \
  -H 'Content-Type: application/json' \
  -d '{
    "prompt": "<start_of_turn>user\nTranslate the following DITA XML document from English to Romanian...\n<end_of_turn>\n<start_of_turn>model\n",
    "n_predict": 2048,
    "temperature": 0.1,
    "stop": ["<end_of_turn>", "<start_of_turn>"]
  }' \
  > udocker-translategemma/results/translation-response.json
```

## Measured results

- **Prompt tokens**: 925
- **Generated tokens**: 1008
- **Prompt throughput**: **69.62 tokens/s**
- **Generation throughput**: **5.05 tokens/s**
- **Stop reason**: `eos` (model produced a complete output)

RAM breakdown (from llama.cpp):
- Model buffers: 2407 MiB (AMX) + 2368 MiB (CPU mapped)
- KV cache (non-SWA): 160 MiB
- KV cache (SWA): 522 MiB
- Compute buffer: 522 MiB

## Translation quality

The model correctly:
- Translated all human-readable text to Romanian
- Preserved all XML tags, attribute names, attribute values (`id`, `href`, `keyref`,
  `product`, `format`, `scope`)
- Kept proper nouns like "Content Fusion", "Oxygen WebHelp Responsive", "Git", "DITA" untranslated
- Preserved the `<i>`, `<b>`, `<ph>`, `<xref>`, `<term>`, `<ul>`, `<li>` inline markup

Sample translated title:
> **Sarcini de Revizuire a Proiectelor vs. Sarcini de Revizuire Non-Proiect**

## Output files

- `results/translation-response.json` — raw llama.cpp `/completion` API response
- `results/translated.dita` — extracted translated DITA topic
- `results/server.log` — llama.cpp server startup and inference log

## Notes

- `udocker` requires `--allow-root` in this environment because commands run as root.
- The GGUF model file is excluded from the repository (`.gitignore`).
- The `--no-jinja` workaround bypasses the multimodal Jinja template; a future
  experiment could test the native structured-input path via llama.cpp's `/v1/chat/completions`
  endpoint once multimodal message encoding is supported.
