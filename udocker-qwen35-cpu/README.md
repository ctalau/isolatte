# Qwen3.5 CPU headless run using `udocker` (instead of Docker)

This folder records a reproduction of the provided `llama.cpp` server tutorial, adapted from Docker CLI to `udocker`.

## What was run

1. Install `udocker`:
   - `python3 -m pip install --user udocker`
   - `~/.local/bin/udocker --allow-root install`

2. Pull and prepare the official server image:
   - `~/.local/bin/udocker --allow-root pull ghcr.io/ggml-org/llama.cpp:server`
   - `~/.local/bin/udocker --allow-root create --name=qwen35-cpu ghcr.io/ggml-org/llama.cpp:server`
   - `~/.local/bin/udocker --allow-root setup --execmode=P1 qwen35-cpu`

3. Try direct Hugging Face auto-download mode (`--hf-repo`):
   - `~/.local/bin/udocker --allow-root run --publish=8000:8080 qwen35-cpu --hf-repo unsloth/Qwen3.5-4B-GGUF:Q4_K_M --no-mmproj -c 4096 -t -1 --host 0.0.0.0 --port 8080`
   - Result in this environment: `--hf-repo` failed to fetch HF manifest from inside the container.

4. Use the fallback from the tutorial (local model file mounted into container):
   - Downloaded public model file from HF:
     - `wget -c -O udocker-qwen35-cpu/models/Qwen3.5-4B-Q3_K_M.gguf "https://huggingface.co/unsloth/Qwen3.5-4B-GGUF/resolve/main/Qwen3.5-4B-Q3_K_M.gguf"`
   - Ran server with local model:
     - `~/.local/bin/udocker --allow-root run --publish=8000:8080 --volume=/workspace/isolatte/udocker-qwen35-cpu/models:/models qwen35-cpu -m /models/Qwen3.5-4B-Q3_K_M.gguf --no-mmproj -c 2048 -t -1 --host 0.0.0.0 --port 8080`

5. Retry prompt run and measure speed:
   - Prompted the model via `/completion`:
     - `curl -s http://localhost:8000/completion -H 'Content-Type: application/json' -d '{"prompt":"Explain Linux containers in 3 short sentences.","n_predict":60,"temperature":0.7}'`
   - Saved raw response JSON to `results/retry-response.json`.
   - Observed throughput from the response `timings` block:
     - `predicted_per_second`: **2.5586433595294347** tokens/s

## Notes

- `udocker` requires `--allow-root` in this container because commands are run as root.
- The OpenAI-compatible `/v1/chat/completions` request returned HTTP 500 in this environment; `/completion` worked.
- To keep the repo lightweight, the downloaded GGUF was removed after validation.

See `results/session-notes.md` and `results/server.log` for captured output snippets.
