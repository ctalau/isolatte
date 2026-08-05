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

The Agent SDK shells out to the Claude Code runtime bundled with the package
(or an installed `claude` CLI). No separate Anthropic account is required when
routing through OpenRouter.

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

## Results

See `results/summary.json` after a live run. Status notes are updated there and
in the assessment section below once the experiment has been executed in this
environment.

## Assessment (fill after run)

### What worked

_(pending live run)_

### What did not work

_(pending live run)_

### What to try next

_(pending live run)_

### Honest opinion

_(pending live run)_
