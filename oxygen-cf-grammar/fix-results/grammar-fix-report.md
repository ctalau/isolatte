# Oxygen CF Grammar Fix — Report

**Model:** google/gemma-4-26b-a4b-it via Vercel AI Gateway  
**Date:** 2026-04-06  
**Task:** Apply grammar corrections from `results/all_issues.json` to 5 topics of the
Oxygen Content Fusion user guide, with changes marked up as Oxygen XML tracked changes.

---

## 1. Topic Selection

Five topics were selected from `all_issues.json` by maximising the number of detected issues
while keeping the DITA file small enough to fit comfortably inside Gemma 4's output-token limit
(≈ 8 192 tokens).  Large files such as `WA-dita-topic-doc-type.dita` (38 KB) and
`cf-organization-subscription.dita` (23 KB) were excluded.

| File | Issues | File size |
|------|--------|-----------|
| cf-upgrading.dita | 8 | 7 224 B |
| CF-task-states-user-roles.dita | 9 | 7 804 B |
| content_fusion_user_interface.dita | 8 | 8 163 B |
| cf-projects-workspace_publications_view.dita | 8 | 9 034 B |
| cf-amazon-s3-connector.dita | 9 | 10 361 B |
| **Total** | **42** | |

---

## 2. Approach

The script (`fix.mjs`) calls Gemma 4 once per topic.  Each call receives:

1. **System prompt** — role description + the full Oxygen tracked-changes PI specification
   (insertion, deletion, replacement format; attribute escaping rules).
2. **User prompt** — the full DITA XML of the topic followed by the list of grammar issues
   (`original` + `suggestion` + `severity` + `issue type`).

The model is asked to output the **complete DITA file** with Oxygen change-tracking processing
instructions inline.

### Oxygen PI format (from spec)

| Change type | Format |
|-------------|--------|
| Insertion | `<?oxy_insert_start author="…" timestamp="…"?> … <?oxy_insert_end?>` |
| Deletion | `<?oxy_delete content="XML-escaped old text" author="…" timestamp="…"?>` (single self-closing PI) |
| Replacement | deletion PI immediately followed by insertion PI pair |

The `content` attribute of `<?oxy_delete …?>` must XML-escape the deleted text
(`&` → `&amp;`, `"` → `&quot;`, `<` → `&lt;`, `>` → `&gt;`).

---

## 3. Prompt Iteration

### Iteration 1 — replacement-JSON output approach

The first design asked the model to output a JSON array of `{ original, replacement }` pairs,
which were then applied programmatically.  All replacements were skipped because the `original`
values in `all_issues.json` were extracted from plain text (XML tags stripped), while the search
ran against the raw DITA source.  Text spans that crossed inline elements such as `<xref>`,
`<uicontrol>`, or `<i>` were never found verbatim.

**Fix:** switched to full-file output, so the model operates directly on the XML it sees.

### Iteration 2 — full-file output, incorrect delete format

The second design used a delete PI with start/end markers (`<?oxy_delete_start?>…<?oxy_delete_end?>`).
This is not the correct format per the Oxygen specification; the deletion PI is self-closing with
the deleted content stored in a `content` attribute.

**Fix:** updated the system prompt with the authoritative PI specification (tables, attribute
definitions, escaping rules) copied verbatim from the Oxygen documentation.

### Iteration 3 — final design (this run)

Full-file output with the correct self-closing `<?oxy_delete content="…"?>` format.  This is the
version whose results are documented below.

---

## 4. Results

### 4.1 Change-tracking markers produced

| File | Issues detected | Deletes | Inserts | Notes |
|------|----------------|---------|---------|-------|
| cf-upgrading.dita | 8 | 8 | 8 | 1 no-op (see §5) |
| CF-task-states-user-roles.dita | 9 | 6 | 3 | 3 delete-only changes (see §5) |
| content_fusion_user_interface.dita | 8 | 8 | 8 | correct XML escaping in `content` attr |
| cf-projects-workspace_publications_view.dita | 8 | 7 | 6 | 1 pure deletion (redundancy fix) |
| cf-amazon-s3-connector.dita | 9 | 10 | 8 | some issues split into 2 changes |
| **Total** | **42** | **39** | **33** | |

### 4.2 Representative correct fixes

**cf-upgrading.dita — redundancy in index term**
```
DELETE: "Upgrading Content Fusion Content Fusion Enterprise - Upgrading Upgrading"
INSERT: "Upgrading Content Fusion Enterprise"
```

**cf-upgrading.dita — passive/awkward phrasing**
```
DELETE: "Maintenance mode is needed to ensure that users are not making any changes to
         the tasks while the backup is being created."
INSERT: "Enable maintenance mode to ensure users do not make changes to tasks while the
         backup is being created."
```

**cf-amazon-s3-connector.dita — missing article**
```
DELETE: "Click Save button."
INSERT: "Click the Save button."
```

**cf-amazon-s3-connector.dita — wrong word (bigger → larger)**
```
DELETE: "If your output's size is bigger than allocated Memory and Ephemeral storage the …"
INSERT: "If your output's size is larger than the allocated Memory and Ephemeral storage, …"
```

**cf-projects-workspace_publications_view.dita — awkward phrasing**
```
DELETE: "There are some limitations in regard to the supported DITA-OT project files:"
INSERT: "There are some limitations regarding the supported DITA-OT project files:"
```

**content_fusion_user_interface.dita — hyphenation**
```
DELETE: "non-project based review tasks"
INSERT: "non-project-based review tasks"
```

---

## 5. Issues Found

### 5.1 One no-op change (cf-upgrading.dita)

For the missing-comma issue "the free space should be at least equal to the size of the data
folder", the model produced a deletion and insertion of identical text.  The comma was not added.
This is a false correction — the detection model flagged this passage but the fix model chose not
to change it, yet still emitted redundant PIs.

### 5.2 Delete-without-insert in CF-task-states-user-roles.dita

Three of the six tracked changes consist only of a `<?oxy_delete …?>` PI, with the corrected text
placed as plain (untracked) text immediately after, rather than inside
`<?oxy_insert_start …?> … <?oxy_insert_end?>`.  For example:

```xml
<?oxy_delete content="Review tasks can be created … difference between the two:" …?>
Review tasks can be created … differences between the two:
```

In Oxygen's review view the deletion appears crossed out, but the corrected sentence is invisible
as a tracked change and would be accepted silently when the deletion is accepted.  A reviewer
cannot independently accept or reject the insertion.

**Root cause:** The model interpreted "apply the deletion" correctly but then wrote the replacement
as ordinary text outside the insertion PI markers.

**Mitigation:** The fixes are still functionally correct (the grammar is improved), but the
tracking fidelity is lower than ideal for those three changes.

### 5.3 Partial application (CF-task-states-user-roles.dita)

Out of 9 detected issues only 6 tracked changes were produced.  Three issues — two
`subject-verb-agreement` and one `run-on-sentence` — appear in the deleted text of the
split-sentence fix (§5.2) and were not separately tracked.

---

## 6. What Worked

- **Full-file output** reliably handles text spans that cross inline XML elements.  The model
  correctly finds and marks up text even when it is split across `<xref>`, `<i>`, `<b>`, and
  `<uicontrol>` elements.
- **Correct PI format** (`<?oxy_delete content="…"?>` self-closing) was adopted consistently
  across all five files once the spec was included in the system prompt.
- **XML attribute escaping** in the `content` attribute was correct in every file: XML special
  characters (`<`, `>`, `"`, `&`) were properly escaped, making the output well-formed.
- The model respected the instruction to skip `<codeblock>`, `<codeph>`, `<uicontrol>` content —
  no changes were applied to code samples or UI labels.
- Token usage was well within limits (largest output: 3 884 tokens for a 10 361-byte file).

## 7. What Did Not Work

- **Replacement tracking completeness:** The model occasionally emits a deletion PI without the
  corresponding insertion PI, placing the corrected text as plain content.  This reduces review
  fidelity in Oxygen.
- **No-op changes:** One case where the detection model flagged a potential issue but the fix
  model (correctly) chose not to change the text, yet still emitted empty tracked-change markers.
- **Issue coverage:** The model applied approximately 33–39 out of 42 issues as properly tracked
  changes.  A few issues were merged into a single tracked change or were part of a larger
  sentence restructuring.

## 8. What to Try Next

1. **Strengthen the replacement rule in the system prompt:** Add an explicit constraint such as:
   *"ALWAYS wrap replacement text in `<?oxy_insert_start …?> … <?oxy_insert_end?>`. Never place
   corrected text as plain text after a deletion PI."*
2. **Validate output:** After the model returns the XML, check that every `<?oxy_delete …?>` is
   followed within 2–3 tokens by either an `<?oxy_insert_start …?>` or at minimum flag it for
   review.
3. **Separate detection issues:** If a sentence has multiple overlapping issues, provide
   issue-level granularity hints so the model tracks each change independently rather than merging
   them into one sentence-level deletion.
4. **Larger model or reasoning mode:** For complex sentence restructuring (split sentences, parallel
   structure repairs), a larger or instruction-tuned model would likely produce better-structured
   change markup.

## 9. Honest Assessment

The pipeline is viable and produces syntactically correct Oxygen change-tracked DITA output.
For the majority of fix types (article usage, wrong word, awkward phrasing, redundancy, spelling)
the model applies the corrections cleanly and a human reviewer in Oxygen can accept or reject each
change individually.  The main gap is reliable paired deletion+insertion markup for sentence-level
rewrites.  With a single prompt addition (rule 1 above) this gap can likely be closed without
changing the model or approach.
