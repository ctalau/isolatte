/**
 * Consolidate extracted terminology using Gemma 4.
 *
 * - Reads results/terms.json
 * - For each category, sends all terms to Gemma 4 and asks it to
 *   group near-duplicates under a canonical form
 * - Writes results/terms_consolidated.json and terms_consolidated_by_category.txt
 *   (originals untouched)
 *
 * Also writes results/terms_frequent.json (frequency filter: count >= 2)
 *
 * Usage:
 *   node consolidate.mjs                       # full consolidation
 *   node consolidate.mjs --category ROLE       # single category (for iteration)
 *
 * Requires: AI_GATEWAY_API_KEY env var
 */

import { ProxyAgent, setGlobalDispatcher } from 'undici';
import { createGateway } from '@ai-sdk/gateway';
import { generateText } from 'ai';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

if (process.env.HTTPS_PROXY) {
  setGlobalDispatcher(new ProxyAgent(process.env.HTTPS_PROXY));
}

const apiKey = process.env.AI_GATEWAY_API_KEY;
if (!apiKey) { console.error('AI_GATEWAY_API_KEY not set'); process.exit(1); }

const MODEL = 'google/gemma-4-26b-a4b-it';
const PRICE = { input: 0.13, output: 0.40 };

const __dirname = dirname(fileURLToPath(import.meta.url));
const RESULTS_DIR = join(__dirname, 'results');

// ── helpers ───────────────────────────────────────────────────────────────────
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const gateway = createGateway({ apiKey });

async function callModel(system, prompt, label) {
  process.stdout.write(`  [${label}] ... `);
  for (let attempt = 0; attempt < 5; attempt++) {
    if (attempt > 0) {
      const delay = Math.pow(2, attempt) * 1000;
      process.stdout.write(`(retry ${attempt}, ${delay/1000}s) `);
      await sleep(delay);
    }
    try {
      const result = await generateText({
        model: gateway(MODEL),
        system,
        prompt,
        maxTokens: 4096,
        temperature: 0.1,
      });
      const usage = result.usage ?? {};
      const inTok = usage.inputTokens ?? 0, outTok = usage.outputTokens ?? 0;
      const cost = ((inTok/1e6)*PRICE.input) + ((outTok/1e6)*PRICE.output);
      console.log(`✓  in=${inTok} out=${outTok} cost=$${cost.toFixed(5)}`);
      return { text: result.text, inTok, outTok, cost };
    } catch (err) {
      const msg = err.message ?? '';
      if (!msg.includes('rate limit') && !msg.includes('temporarily') && !msg.includes('429') && !msg.includes('503')) {
        throw err;
      }
      if (attempt === 4) throw err;
    }
  }
}

function parseJsonResponse(raw) {
  const cleaned = raw.trim().replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '');
  return JSON.parse(cleaned);
}

// ── frequency filter (no LLM) ─────────────────────────────────────────────────
function writeFrequent(terms) {
  const frequent = terms.filter(t => t.count >= 2);
  writeFileSync(join(RESULTS_DIR, 'terms_frequent.json'), JSON.stringify(frequent, null, 2), 'utf8');

  const cats = ['UI_ELEMENT', 'FEATURE', 'CONCEPT', 'ROLE', 'ACTION'];
  let report = `Oxygen Content Fusion – Frequent Terms (≥2 topics)\n`;
  report += `Total: ${frequent.length} terms (from ${terms.length} original)\n`;
  report += '='.repeat(60) + '\n\n';
  for (const cat of cats) {
    const items = frequent.filter(t => t.category === cat);
    if (!items.length) continue;
    report += `## ${cat} (${items.length})\n`;
    for (const t of items) report += `  ${t.term.padEnd(50)} [×${t.count}]\n`;
    report += '\n';
  }
  writeFileSync(join(RESULTS_DIR, 'terms_frequent_by_category.txt'), report, 'utf8');
  console.log(`Frequency filter: ${frequent.length} terms with count ≥ 2`);
}

// ── consolidation prompt ──────────────────────────────────────────────────────
const SYSTEM_PROMPT = `You are consolidating a technical terminology list extracted from Oxygen Content Fusion documentation.
Oxygen Content Fusion is a cloud-based content review and collaboration platform for DITA documentation.

Your task: given a list of terms in one category, identify groups of near-duplicates and output a single canonical term per group.

Rules for merging:
1. Singular/plural: use singular UNLESS the plural is the official feature name in the UI
   (e.g. "Projects" IS the official CF feature name → keep "Projects"; but "Review Tasks" → canonical is "Review Task")
2. Same element at different specificity: keep the most commonly used form from the source documentation
   (e.g. "Administration Page", "Content Fusion Administration page", "Content Fusion Enterprise Administration Page"
    → "Administration Page" is the generic canonical; keep the more specific ones only if they refer to DISTINCT pages)
3. Synonyms: keep the most official / precise term
   (e.g. "visual editor", "visual editor page", "web-based editor" → "Visual Editor")
4. Abbreviation + expansion: prefer the full form
   (e.g. "SME" → "Subject Matter Expert")
5. Terms that clearly refer to DISTINCT things must NOT be merged even if they share words:
   - For ROLES: a generic role ("Author") and a product-specific named role ("Content Fusion Author")
     are DISTINCT — do NOT merge them. Named roles with a product prefix are always distinct.
   - For ROLES: infrastructure-level roles (e.g. "Server Administrator") and
     product-level roles (e.g. "Organization Administrator") are DISTINCT.
   - A specific named feature ("Workspace Search") must NOT be merged into a generic term ("Search")
     even if one is a subset of the other. If the specific name is used as a distinct concept in the docs, keep it.
6. Phrasing variants that clearly mean the same thing SHOULD be merged:
   - "Project Review Task" and "Project-based review task" → "Project Review Task"
   - "Oxygen Content Fusion" and "Content Fusion" → "Oxygen Content Fusion"
   - "Oxygen AI Positron" and "AI Positron" → "Oxygen AI Positron"
7. Be CONSERVATIVE: when in doubt, keep terms separate.
   It is better to have two similar entries than to lose a distinct concept.
   Only merge when you are highly confident both terms refer to exactly the same on-screen element or concept.
   Do NOT merge UI elements that refer to different parts of the interface:
   - A file-browser pane and an editing pane are DISTINCT even if both called "pane"
   - A page and a button or section within that page are ALWAYS DISTINCT. NEVER merge a button or section into a page name.
   - "Projects page" and "Organization Projects page" are likely DISTINCT pages
8. Capitalise the canonical term consistently with how it appears as a proper noun in the documentation

Output format – a valid JSON array, ONE object per canonical term:
{"term": "Canonical Term", "count": <sum of counts of all merged terms>, "merged": ["variant1", "variant2"]}
where "merged" lists variant spellings that were absorbed (empty array if nothing was merged).

Output ONLY the JSON array. No explanation, no markdown, no code fences.`;

function buildPrompt(category, items) {
  const lines = items.map(t => `  {"term": ${JSON.stringify(t.term)}, "count": ${t.count}}`).join(',\n');
  return `Consolidate the following ${category} terms:\n[\n${lines}\n]`;
}

// ── per-category consolidation ────────────────────────────────────────────────
async function consolidateCategory(category, items) {
  const prompt = buildPrompt(category, items);
  const { text } = await callModel(SYSTEM_PROMPT, prompt, category);

  let consolidated;
  try {
    consolidated = parseJsonResponse(text);
    if (!Array.isArray(consolidated)) throw new Error('Not an array');
  } catch (e) {
    console.warn(`  WARNING: JSON parse failed for ${category}: ${e.message}`);
    console.warn(`  Raw: ${text.slice(0, 300)}`);
    // Fall back to original items unchanged
    return items.map(t => ({ ...t, merged: [] }));
  }

  // Attach category and ensure structure
  return consolidated.map(t => ({
    term: t.term ?? '?',
    category,
    count: typeof t.count === 'number' ? t.count : 0,
    merged: Array.isArray(t.merged) ? t.merged : [],
  })).sort((a, b) => b.count - a.count || a.term.localeCompare(b.term));
}

// ── main ──────────────────────────────────────────────────────────────────────
async function main() {
  mkdirSync(RESULTS_DIR, { recursive: true });

  const allTerms = JSON.parse(readFileSync(join(RESULTS_DIR, 'terms.json'), 'utf8'));

  // Always write frequency-filtered file (no LLM needed)
  writeFrequent(allTerms);

  // Determine which categories to consolidate
  const argIdx = process.argv.indexOf('--category');
  const singleCat = argIdx >= 0 ? process.argv[argIdx + 1] : null;
  const ALL_CATS = ['ROLE', 'FEATURE', 'UI_ELEMENT', 'CONCEPT', 'ACTION'];
  const catsToRun = singleCat ? [singleCat] : ALL_CATS;

  console.log(`\nConsolidation via ${MODEL}`);
  console.log(`Categories: ${catsToRun.join(', ')}\n`);

  // Group input by category
  const byCategory = {};
  for (const t of allTerms) byCategory[t.category] = [...(byCategory[t.category] ?? []), t];

  const consolidatedAll = {};
  let totalCost = 0;

  for (const cat of catsToRun) {
    const items = byCategory[cat] ?? [];
    if (!items.length) { console.log(`  [${cat}] no terms, skipping`); continue; }
    const result = await consolidateCategory(cat, items);
    consolidatedAll[cat] = result;
    await sleep(1000); // rate-limit buffer
  }

  if (singleCat) {
    // Print result to console for inspection
    console.log(`\n--- ${singleCat} consolidated (${consolidatedAll[singleCat]?.length ?? 0} terms) ---`);
    for (const t of consolidatedAll[singleCat] ?? []) {
      const merged = t.merged.length ? `  ← [${t.merged.join(', ')}]` : '';
      console.log(`  ${t.term.padEnd(50)} ×${t.count}${merged}`);
    }
    return; // Don't overwrite full results when iterating
  }

  // Full run: build consolidated list and write files
  const consolidated = ALL_CATS.flatMap(cat => consolidatedAll[cat] ?? byCategory[cat] ?? []);

  writeFileSync(
    join(RESULTS_DIR, 'terms_consolidated.json'),
    JSON.stringify(consolidated, null, 2),
    'utf8'
  );

  // Text report
  let report = `Oxygen Content Fusion – Consolidated Terminology\n`;
  report += `Model: ${MODEL}  |  Total unique terms: ${consolidated.length}\n`;
  report += '='.repeat(60) + '\n\n';
  for (const cat of ALL_CATS) {
    const items = consolidated.filter(t => t.category === cat);
    if (!items.length) continue;
    report += `## ${cat} (${items.length})\n`;
    for (const t of items) {
      const mergeNote = t.merged?.length ? `  ← ${t.merged.join('; ')}` : '';
      report += `  ${t.term.padEnd(50)} [×${t.count}]${mergeNote}\n`;
    }
    report += '\n';
  }
  writeFileSync(join(RESULTS_DIR, 'terms_consolidated_by_category.txt'), report, 'utf8');

  console.log(`\nConsolidated: ${consolidated.length} terms`);
  console.log(`Written to: ${RESULTS_DIR}/terms_consolidated*.json/.txt`);
}

main().catch(err => { console.error(err); process.exit(1); });
