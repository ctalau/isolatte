---
name: translate-ro-codeblock
description: Translate a fenced codeblock into Romanian. Use when the user asks to translate a codeblock, code snippet, or fenced ``` block into Romanian / română, or when localizing comments and string literals inside a codeblock to Romanian.
---

# Translate codeblock to Romanian

When invoked, translate the provided fenced codeblock into Romanian.

## Rules

1. Keep the fence language tag unchanged (e.g. `python`, `javascript`, `bash`).
2. Preserve executable syntax exactly: keywords, operators, indentation, and structure.
3. Translate human-readable text only:
   - comments
   - docstrings
   - user-facing string literals
   - prose that appears inside the block
4. Do **not** translate:
   - identifiers (function/class/variable names)
   - import paths, URLs, file paths
   - API keys, env var names, CLI flags
   - format placeholders such as `{name}`, `%s`, `$var`
5. Use correct Romanian diacritics: ă, â, î, ș, ț.
6. Prefer natural Romanian technical phrasing over word-for-word calques.
7. Output **only** the translated fenced codeblock — no preface, no explanation, no trailing commentary.

## Example

Input:

```python
# Calculate the total price
def total(price, tax):
    """Return price including tax."""
    return price * (1 + tax)
```

Output:

```python
# Calculează prețul total
def total(price, tax):
    """Returnează prețul inclusiv taxa."""
    return price * (1 + tax)
```
