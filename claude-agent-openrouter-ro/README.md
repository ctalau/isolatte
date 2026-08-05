# Claude Agent SDK → OpenRouter → DeepSeek V4 Flash (Romanian skill)

Self-contained experiment: run the **Claude Agent SDK** (`@anthropic-ai/claude-agent-sdk`)
through OpenRouter’s Anthropic-compatible API, forced onto
[`deepseek/deepseek-v4-flash`](https://openrouter.ai/deepseek/deepseek-v4-flash),
with a project skill that translates a fenced codeblock into Romanian.

## Layout

```
claude-agent-openrouter-ro/
├── .claude/skills/translate-ro-codeblock/SKILL.md
├── fixtures/sample.md          # English Python snippet to translate
├── run.mjs                     # Agent SDK driver
├── verify.mjs                  # Offline pass/fail against results/
├── env.example
├── package.json
└── results/                    # filled by a live run
    ├── translated.md
    ├── summary.json
    └── transcript.json
```

## Requirements

- Node.js ≥ 18
- Network access to `openrouter.ai`
- `OPENROUTER_API_KEY` set in the environment or in a local `.env` (gitignored)

## Setup

```bash
cd claude-agent-openrouter-ro
cp env.example .env   # then paste your OpenRouter key
npm install
```

The Agent SDK shells out to the Claude Code runtime bundled with the platform
package (`@anthropic-ai/claude-agent-sdk-linux-x64`). No Anthropic account is
required when routing through OpenRouter.

## Configuration

`run.mjs` sets:

| Variable | Value |
|---|---|
| `ANTHROPIC_BASE_URL` | `https://openrouter.ai/api` |
| `ANTHROPIC_AUTH_TOKEN` | `$OPENROUTER_API_KEY` |
| `ANTHROPIC_API_KEY` | `""` (must be explicitly empty) |
| `ANTHROPIC_DEFAULT_*_MODEL` | `deepseek/deepseek-v4-flash` |
| `options.model` | `deepseek/deepseek-v4-flash` |
| `settingSources` | `["project"]` (loads `.claude/skills/`) |
| `skills` | `["translate-ro-codeblock"]` |

## Run

```bash
export OPENROUTER_API_KEY=sk-or-v1-...
npm test
npm run verify
```

Expected behavior:

1. SDK init lists `translate-ro-codeblock` (or the agent invokes the Skill tool).
2. Agent writes `results/translated.md` containing a Romanian-translated codeblock.
3. Identifiers such as `greet` / `message` stay in English; comments/docstrings/strings become Romanian.

## Skill

`.claude/skills/translate-ro-codeblock/SKILL.md` instructs the agent to:

- translate comments, docstrings, and user-facing strings to Romanian
- keep syntax and identifiers unchanged
- use diacritics (ă, â, î, ș, ț)
- emit only the fenced codeblock

## Live run results (2026-08-05)

`npm test` + `npm run verify` both succeeded (`summary.ok: true`, ~16 s).

### Output (`results/translated.md`)

```python
# Salută utilizatorul după nume
def greet(name):
    """Returnează un mesaj de bun venit prietenos."""
    # Construiește mesajul și returnează-l
    message = f"Salut, {name}! Bine ai venit la atelier."
    return message


# Punctul de intrare pentru scriptul demo
if __name__ == "__main__":
    print(greet("Alex"))
```

### Checks

| Check | Result |
|---|---|
| Skill discovered in init | yes (`translate-ro-codeblock`) |
| Skill tool invoked | yes |
| Romanian diacritics / phrasing | yes |
| Identifiers preserved | yes (`greet`, `name`, `message`, `{name}`) |
| File written to experiment `results/` | yes (after absolute-path prompt) |
| `verify.mjs` | all PASS |

## Assessment

### What worked

- OpenRouter Anthropic skin accepted Claude Agent SDK traffic with
  `ANTHROPIC_BASE_URL=https://openrouter.ai/api` and an empty `ANTHROPIC_API_KEY`.
- Model override to `deepseek/deepseek-v4-flash` resolved correctly (init reported
  that model).
- Project skill discovery worked via `settingSources: ["project"]` +
  `skills: ["translate-ro-codeblock"]`; the Skill tool was actually invoked.
- DeepSeek produced natural Romanian with diacritics and kept code identifiers intact.
- End-to-end cost for the successful run was negligible (flash-tier pricing).

### What did not work

- Relative output path `results/translated.md` was resolved to
  `/workspace/results/translated.md` (repo root), not the experiment folder.
  Fixed by prompting with an absolute path.
- With `permissionMode: "bypassPermissions"`, the agent also called `Bash`
  even though `allowedTools` listed only `Read`, `Write`, and `Skill`. Treat
  tool allowlists as soft under bypass mode when using non-Anthropic models.

### What to try next

- Re-run with `permissionMode: "dontAsk"` (or without bypass) to see whether
  DeepSeek still respects `allowedTools`.
- Add a second fixture (JS/Markdown prose codeblock) to stress the skill description.
- Try `~deepseek/deepseek-v4-flash-latest` vs a pinned revision for stability.
- Measure tool-calling reliability across a small batch (10 runs) — one success
  is encouraging but not statistically meaningful.

### Honest opinion

**Yes — this experiment works.** Claude Agent SDK + OpenRouter + DeepSeek V4 Flash
is a viable path for skill-driven agent tasks. The Romanian codeblock skill was
discovered, invoked, and produced correct output. The only real footgun was path
resolution for Write; once the prompt used an absolute path, verification passed
cleanly. Non-Anthropic models may be looser about tool allowlists under
`bypassPermissions`, so lock that down before any untrusted-input use.
