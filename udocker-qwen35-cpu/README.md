# Qwen3.5 CPU headless run using `udocker` (instead of Docker)

This folder records a reproduction of the `llama.cpp` server tutorial, adapted from Docker CLI to `udocker`.

## 0.8B experiment run

Model used:

- `unsloth/Qwen3.5-0.8B-GGUF`
- file: `Qwen3.5-0.8B-Q4_K_M.gguf`

Commands used:

1. Install and initialize `udocker`:

```bash
python3 -m pip install --user udocker
~/.local/bin/udocker --allow-root install
```

2. Pull and prepare llama.cpp server image:

```bash
~/.local/bin/udocker --allow-root pull ghcr.io/ggml-org/llama.cpp:server
~/.local/bin/udocker --allow-root create --name=qwen35-08b-cpu ghcr.io/ggml-org/llama.cpp:server
~/.local/bin/udocker --allow-root setup --execmode=P1 qwen35-08b-cpu
```

3. Download public GGUF and run server:

```bash
wget -c -O udocker-qwen35-cpu/models/Qwen3.5-0.8B-Q4_K_M.gguf \
  "https://huggingface.co/unsloth/Qwen3.5-0.8B-GGUF/resolve/main/Qwen3.5-0.8B-Q4_K_M.gguf"

~/.local/bin/udocker --allow-root run --publish=8000:8080 \
  --volume=/workspace/isolatte/udocker-qwen35-cpu/models:/models \
  qwen35-08b-cpu \
  -m /models/Qwen3.5-0.8B-Q4_K_M.gguf \
  --no-mmproj -c 2048 -t -1 --host 0.0.0.0 --port 8080
```

4. Prompt the model and save the response:

```bash
curl -s http://localhost:8000/completion \
  -H 'Content-Type: application/json' \
  -d '{"prompt":"Explain Linux containers in 3 short sentences.","n_predict":80,"temperature":0.7}' \
  > udocker-qwen35-cpu/results/retry-response-0.8b.json
```

## Measured results

- Prompt throughput: **13.535352988470585 tokens/s**
- Generation throughput: **4.943740541620147 tokens/s**
- RAM usage (host, from llama memory breakdown): **1087 MiB total**
  - model: **497 MiB**
  - context: **101 MiB**
  - compute: **489 MiB**

Response excerpt:

> Linux containers are isolated virtual machine environments designed to isolate each user's work from others' work. They provide a safe sandbox where developers can develop code without affecting the host system. Each container uses the same Linux kernel and system software, ...

Notes:

- `udocker` requires `--allow-root` in this environment because commands run as root.
- The large GGUF is removed after validation to keep repository size small.
