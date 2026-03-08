# Session notes (0.8B experiment)

## Model

- Repo: `unsloth/Qwen3.5-0.8B-GGUF`
- Quant file: `Qwen3.5-0.8B-Q4_K_M.gguf`

## Prompt sent

```
Explain Linux containers in 3 short sentences.
```

## Request command

```bash
curl -s http://localhost:8000/completion \
  -H 'Content-Type: application/json' \
  -d '{"prompt":"Explain Linux containers in 3 short sentences.","n_predict":80,"temperature":0.7}'
```

## Throughput

From `results/retry-response-0.8b.json` timings:

- `prompt_per_second`: **13.535352988470585** tokens/s
- `predicted_per_second`: **4.943740541620147** tokens/s

## RAM usage

From llama.cpp memory breakdown at shutdown:

- Host total: **1087 MiB**
- Host model: **497 MiB**
- Host context: **101 MiB**
- Host compute: **489 MiB**
- CPU_REPACK: **160 MiB**

## Response excerpt

```
Linux containers are isolated virtual machine environments designed to isolate each user's work from others' work. They provide a safe sandbox where developers can develop code without affecting the host system. Each container uses the same Linux kernel and system software, ...
```
