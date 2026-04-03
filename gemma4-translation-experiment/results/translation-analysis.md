# Gemma 4 E4B Translation Analysis

Source: `cf-review-tasks-projects.dita` (English)  
Output: `translated.dita` (Romanian)  
Model: `gemma-4-E4B-it Q4_K_M`

## Issue #1 — Critical: Broken XML structure (ul outside p)

**Location**: `<p id="p_fvr_c32_z1c">` and `<section id="user_roles">`

In the source, `<ul>` is nested inside `<p>`:
```xml
<p id="p_fvr_c32_z1c">The main differences...<ul id="ul_wcv_lxf_zxb">
  ...
</ul></p>
```

Gemma 4 split this into two sibling elements:
```xml
<p id="p_fvr_c32_z1c">Principalele diferențe... sunt:</p>
<ul id="ul_wcv_lxf_zxb">
  ...
</ul>
```

Same structural change in user_roles. This is invalid DITA — the `<ul>` must be inside the `<p>`.  
Fix: Close the `<p>` after the `</ul>`, not before the `<ul>`.

## Issue #2 — High: Invented element IDs

**Location**: `<section id="user_roles">`

The model added IDs that do not exist in the source:
- `<ul id="ul_user_roles">` (source: `<ul>` with no id)
- `<li id="li_sme">` (source: `<li>` with no id)
- `<li id="li_author">` (source: `<li>` with no id)

Invented IDs risk collisions and break downstream DITA toolchains that track ID uniqueness.  
Fix: Remove the added IDs, or strip all IDs not present in source.

## Issue #3 — Medium: "output" dropped

**Location**: `<p id="p_o2t_pl3_vxb">`

Source: `...Oxygen WebHelp Responsive</b></xref> output.</p>`  
Translation: `...Oxygen WebHelp Responsive</b></xref>.</p>` — "output" was simply dropped.

Romanian: "ieșire" or "rezultat". Same error was seen in translategemma-4b-it.

## Issue #4 — Medium: "browser interface" awkward

**Location**: `<p id="p_o2t_pl3_vxb">`

Source: `managed within the Content Fusion browser interface`  
Translation: `gestionat în interfața browserului Content Fusion`

"interfața browserului" (the browser's interface) is understandable but awkward — it implies
a generic browser UI rather than the specific Content Fusion web app.  
Better: "interfața web Content Fusion" or "interfața de utilizator Content Fusion".

## Issue #5 — Low: Closing tag placement for fusion-cloud ph

**Location**: `<ph product="fusion-cloud">`

Source:
```xml
<ph product="fusion-cloud"><xref href="cf-organization-members.dita"/> page</ph>)
```

Translation:
```xml
<ph product="fusion-cloud"><xref href="cf-organization-members.dita"/> pagină</ph>)
```

This is actually correct — "pagină" is inside `<ph>` as it should be, and ")" is outside.
The prior translategemma-4b experiment left "page" untranslated here; Gemma 4 fixed it. ✓

## Summary vs translategemma-4b-it

| Issue | translategemma-4b | gemma-4-E4B |
|---|---|---|
| "non-project" prefix lost | Critical ✗ | Fixed ✓ |
| "output" not translated | High ✗ | Still missing ✗ |
| "page" not translated | Medium ✗ | Fixed ✓ |
| "browser interface" awkward | Medium ✗ | Still present ✗ |
| "technical writers" inaccurate | Low ✗ | Fixed ✓ |
| XML structure broken (ul outside p) | Not present ✓ | New issue ✗ |
| Invented IDs | Not present ✓ | New issue ✗ |

Gemma 4 fixed 3 issues from the previous run but introduced 2 new structural problems.
The structural issue (broken nesting) is the most serious since it would cause DITA
processing failures.
