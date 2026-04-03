# Re-evaluation of Multi-Model Romanian Translation Quality

Date: 2026-04-03
Evaluator: Codex (fresh review)

## Scope and method

This review re-evaluates all seven `translated.dita` outputs in `multi-model-translation-test/results/*/translated.dita` against `source.dita`.

Evaluation priorities:
1. **Logical fidelity** (meaning preserved, no role/function inversions, no semantic drift)
2. **Terminology naturalness in Romanian** (what a Romanian technical writer would actually accept)
3. **Structural integrity** (XML/tag/attribute/ID/link preservation)
4. **Formatting tolerance** (minor fixable whitespace/fence issues are forgiven)

Important interpretation rule used in this re-evaluation:
- Some English terms are acceptable in Romanian technical docs when they are entrenched (for example: *output*, *repository* in many teams).
- But protected product role names (for example `Content Fusion Author`) should remain unchanged.

## Overall ranking (best to worst)

1. **zai/glm-5 — 9.2/10 — $0.029092**
2. **alibaba/qwen3.6-plus — 9.0/10 — $0.025448**
3. **openai/gpt-5.4-mini — 8.8/10 — $0.005393**
4. **moonshotai/kimi-k2.5 — 8.1/10 — $0.003887**
5. **minimax/minimax-m2.7 — 7.2/10 — $0.002456**
6. **google/gemini-3-flash — 6.8/10 — $0.192436**
7. **anthropic/claude-haiku-4.5 — 6.2/10 — $0.007056**

Cost values are copied from `results/summary.json` (`cost_usd`).

---

## Per-model assessment

## 1) zai/glm-5 — 9.2/10

**What is good**
- Meaning is consistently preserved.
- Romanian phrasing is natural in most places.
- Core terms are handled well (`Proiecte`, `recenzenților`, `pagina de administrare`).
- Product role name `Content Fusion Author` is preserved.
- XML structure and references look intact.

**Issues**
- Minor style unevenness (mix of Romanian + retained English acronym expansion text around SME), but not logically wrong.

**Verdict**
- Best balance of fidelity + Romanian naturalness in this batch.

## 2) alibaba/qwen3.6-plus — 9.0/10

**What is good**
- Very solid semantic fidelity.
- Romanian reads naturally for a technical audience.
- Good handling of core terminology (`depozit Git`, `ramură`, `livrabile`).
- Role name `Content Fusion Author` preserved.

**Issues**
- Minor local phrasing awkwardness around the cloud administration member-page fragment.
- “ieșiri PDF” is acceptable but slightly less idiomatic than “output PDF” in some tech teams (subjective, not an error).

**Verdict**
- High-quality translation, near top.

## 3) openai/gpt-5.4-mini — 8.8/10

**What is good**
- Strong logical fidelity and clean Romanian syntax.
- Terminology sounds credible to Romanian practitioners (`recenzenților`, `livrabile`, `depozit Git`).
- Preserves protected names (`Content Fusion Author`, product names).

**Issues**
- Leaves `output` and `page` in English in one place. This is acceptable in many Romanian IT contexts, but internal consistency is reduced because surrounding text is translated.

**Verdict**
- Very good and practically usable with minimal post-editing.

## 4) moonshotai/kimi-k2.5 — 8.1/10

**What is good**
- Generally faithful and readable.
- Core flow and logic are preserved.
- `Content Fusion Author` is preserved (good).

**Issues**
- Uses “Expert în materie”, which sounds less idiomatic in Romanian localization practice than “Expert în domeniu”.
- Some phrasing is slightly literal, but still understandable.

**Verdict**
- Good baseline result, but terminology polish is needed.

## 5) minimax/minimax-m2.7 — 7.2/10

**What is good**
- Structurally intact XML and mostly understandable Romanian.
- Technical borrowing (`repository`, `output`) can be acceptable in Romanian IT usage.

**Critical issue**
- Translates protected role name `Content Fusion Author` into `Autor Content Fusion` in bold role heading and inline role mentions. That is a semantic/product terminology violation for UI and role-label consistency.

**Verdict**
- Usable only after targeted terminology correction; this is a non-trivial localization risk.

## 6) google/gemini-3-flash — 6.8/10

**What is good**
- Fluent Romanian in many segments.
- XML preserved.

**Critical issues**
- Leaves `<term>Projects</term>` in English repeatedly while translating nearby occurrences to Romanian elsewhere in the document family context; this creates conceptual inconsistency.
- Leaves `Administration` untranslated in link text.

**Verdict**
- Understandable output, but terminology consistency is weak in key UI/doc terms.

## 7) anthropic/claude-haiku-4.5 — 6.2/10

**What is good**
- Much of the translation is understandable.
- Structure is mostly preserved.

**Critical issues**
- Uses non-standard Romanian form `revedenților` (should be `recenzenților` / `revizorilor`).
- Leaves `output` in English in a sentence that is otherwise translated.
- Also has markdown code fences in output (forgivable formatting issue per instructions, so not heavily penalized).

**Verdict**
- Needs clear post-editing before production use.

---

## Terminology policy notes (Romanian realism)

Applied in this re-evaluation:
- Accept both `depozit Git` and `repository Git` when context remains clear and consistent.
- Accept occasional `output` where a Romanian team commonly uses this borrowing.
- Prefer preserving official product roles and proper names exactly (`Content Fusion Author`, `Content Fusion`, `Oxygen WebHelp Responsive`).
- Penalize inconsistent treatment of central UI terms (`Projects` vs `Proiecte`, `Administration` untranslated when rest is localized).

## Best candidate for production with light post-editing

- **Primary choice:** `zai/glm-5`
- **Close alternatives:** `alibaba/qwen3.6-plus`, `openai/gpt-5.4-mini`

If cost/speed matter more than marginal quality delta, `openai/gpt-5.4-mini` remains the pragmatic choice.
