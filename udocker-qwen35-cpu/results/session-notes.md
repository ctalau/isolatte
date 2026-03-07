# Session notes (captured outputs)

## `udocker` install

```
Info: creating repo: /root/.udocker
Info: udocker command line interface 1.3.17
Info: searching for udockertools >= 1.2.11
Info: installing udockertools 1.2.11
Info: installation of udockertools successful
```

## HF auto-download mode in-container (`--hf-repo`) failed

```
error: failed to get manifest at https://huggingface.co/v2/unsloth/Qwen3.5-4B-GGUF/manifests/Q4_K_M: error: cannot make GET request
error: failed to get manifest (check your internet connection)
```

## Local-model mode succeeded

Key startup lines:

```
main: model loaded
main: server is listening on http://0.0.0.0:8080
main: starting the main loop...
```

## Retry run (explicitly prompted model and measured throughput)

Prompt used:

```
Explain Linux containers in 3 short sentences.
```

Request used:

```
curl -s http://localhost:8000/completion \
  -H 'Content-Type: application/json' \
  -d '{"prompt":"Explain Linux containers in 3 short sentences.","n_predict":60,"temperature":0.7}'
```

Saved full JSON response to `results/retry-response.json`.

Measured throughput from response timings:

- `prompt_per_second`: **4.215265161254969** tokens/s
- `predicted_per_second`: **2.5586433595294347** tokens/s

Response excerpt:

```
Linux containers use process isolation and shared namespaces to run applications in lightweight, portable units. They share the host operating system's kernel, allowing them to be significantly smaller than virtual machines while maintaining security boundaries.
```
