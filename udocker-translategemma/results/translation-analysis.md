# Translation Analysis: translateGemma 4B — English → Romanian

Source: `oxygenxml/userguide` — `DITA/topics/cf-review-tasks-projects.dita`
Model: `google/translategemma-4b-it` Q4_K_M

---

## Top 5 Corrections

### 1. Inverted meaning — "non-project based" → "bazate pe proiect" [CRITICAL]

| | Text |
|---|---|
| **Original** | "The main differences between working with **non-project based** review tasks and projects are:" |
| **Translated** | "Principalele diferențe dintre lucrul cu sarcini de revizuire **bazate pe proiect** și proiecte sunt:" |

The `non-` prefix was silently dropped. The translated sentence now says "project-based review tasks",
the **opposite** of the original meaning. This is the most severe error in the output — it
misrepresents the contrast the paragraph is introducing.

**Correction:** "sarcini de revizuire **non-bazate pe proiect**" or, more naturally,
"sarcini de revizuire **fără proiect**".

---

### 2. Untranslated English word — "output" left in Romanian text

| | Text |
|---|---|
| **Original** | "…for creating PDF or Oxygen WebHelp Responsive **output**." |
| **Translated** | "…pentru generarea de PDF sau Oxygen WebHelp Responsive **output**." |

The word "output" at the end of the first paragraph was not translated. It breaks
the Romanian sentence and reads as English code-switching.

**Correction:** "…pentru generarea de ieșiri PDF sau Oxygen WebHelp Responsive."
(Romanian: "ieșire" = output/result)

---

### 3. Untranslated English word — "page" inside `<ph product="fusion-cloud">`

| | Text |
|---|---|
| **Original** | `<xref href="cf-organization-members.dita"/> page</ph>)` |
| **Translated** | `<xref href="cf-organization-members.dita"/> page</ph>)` |

The plain-text word " page" following the self-closing `<xref/>` inside the
`product="fusion-cloud"` conditional phrase was not translated. The surrounding
Romanian text refers to "pagina" elsewhere, making this inconsistency visible.

**Correction:** `<xref href="cf-organization-members.dita"/> pagina</ph>)`

---

### 4. Loss of specificity — "browser interface" → "interfața de utilizator"

| | Text |
|---|---|
| **Original** | "This is managed within the Content Fusion **browser interface** through a feature…" |
| **Translated** | "Acest lucru este gestionat în **interfața de utilizator** Content Fusion prin intermediul…" |

"browser interface" (web browser UI) was rendered as "interfața de utilizator"
(user interface), dropping the "browser/web" qualifier. "User interface" is
generic and does not convey that this is a web browser feature, which is
relevant for a product that also has a desktop XML editor.

**Correction:** "**interfața web** Content Fusion" or "**interfața de browser** Content Fusion".

---

### 5. Loss of technical register — "technical writers" → "autori de documente"

| | Text |
|---|---|
| **Original** | "Provides tools for **technical writers** and **reviewers**…" |
| **Translated** | "Oferă instrumente pentru **autori de documente** și **evaluatori**…" |

Two term-level inaccuracies in one phrase:

- "technical writers" → "autori de documente" (document authors) — drops the
  "technical" qualifier. The standard Romanian term is "**autori tehnici**" or
  "**redactori tehnici**".
- "reviewers" → "evaluatori" (evaluators/assessors) — an evaluator judges
  quality/performance. The correct term for a documentation reviewer is
  "**recenzor**" or "**revizor**".

**Correction:** "autori tehnici și recenzori" (or "redactori tehnici și revizori").

---

## Summary Table

| # | Severity | Location | Type |
|---|---|---|---|
| 1 | Critical | `<p id="p_fvr_c32_z1c">` | Semantic inversion — "non-" prefix dropped |
| 2 | High | `<p id="p_o2t_pl3_vxb">` | Untranslated English word ("output") |
| 3 | Medium | `<ph product="fusion-cloud">` | Untranslated English word ("page") |
| 4 | Medium | `<p id="p_o2t_pl3_vxb">` | Loss of domain specificity ("browser" dropped) |
| 5 | Low | `<li id="li_vc1_qxf_zxb">` | Loss of technical register ("technical writers", "reviewers") |
