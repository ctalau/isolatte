/**
 * Oxygen Content Fusion - Terminology Extraction via Gemma 4
 *
 * Steps:
 *  1. Parse chapter-content-fusion.ditamap, filter topics by ditaval
 *     (include product=fusion or no product; exclude product=fusion-cloud)
 *  2. Read each DITA file, strip XML to plain text
 *  3. Call Gemma 4 via Vercel AI Gateway with a terminology-extraction prompt
 *  4. Aggregate, deduplicate, and rank terms
 *
 * Usage:
 *   node extract.mjs           # full run
 *   node extract.mjs --pilot   # first 5 topics only (prompt iteration)
 *
 * Requires: AI_GATEWAY_API_KEY env var
 */

import { ProxyAgent, setGlobalDispatcher } from 'undici';
import { createGateway } from '@ai-sdk/gateway';
import { generateText } from 'ai';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { join, dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

// ── proxy ─────────────────────────────────────────────────────────────────────
if (process.env.HTTPS_PROXY) {
  setGlobalDispatcher(new ProxyAgent(process.env.HTTPS_PROXY));
}

// ── config ────────────────────────────────────────────────────────────────────
const apiKey = process.env.AI_GATEWAY_API_KEY;
if (!apiKey) {
  console.error('Error: AI_GATEWAY_API_KEY is not set.');
  process.exit(1);
}

const MODEL = 'google/gemma-4-26b-a4b-it';
const PILOT = process.argv.includes('--pilot');

const __dirname = dirname(fileURLToPath(import.meta.url));
const DITA_BASE  = join(__dirname, 'userguide', 'DITA');
const DITAMAP    = join(DITA_BASE, 'maps', 'chapter-content-fusion.ditamap');
const OUT_DIR    = join(__dirname, 'results');

// ── pricing ───────────────────────────────────────────────────────────────────
const PRICE = { input: 0.13, output: 0.40 }; // USD per million tokens (gemma-4-27b)

// ── ditamap parser ────────────────────────────────────────────────────────────
/**
 * Extract unique topic file paths from the ditamap, applying ditaval rules:
 *  - include if no product attr OR product="fusion"
 *  - exclude if product="fusion-cloud" (or any other excluded product)
 */
function getTopicsFromMap(ditamapPath) {
  const base = dirname(ditamapPath);
  const content = readFileSync(ditamapPath, 'utf8');
  const seen = new Set();
  const topics = [];

  // Match every <topicref ...> tag (may span multiple attrs)
  // We grab the full opening tag text so we can parse both href and product.
  const tagRe = /<topicref\b([^>]*?)(?:\/>|>)/g;
  let m;
  while ((m = tagRe.exec(content)) !== null) {
    const attrs = m[1];
    const hrefM = attrs.match(/href="([^"]+\.dita)"/);
    if (!hrefM) continue;
    const href = hrefM[1];

    const productM = attrs.match(/product="([^"]*)"/);
    const product = productM ? productM[1] : '';

    // Exclude topics that are fusion-cloud only
    if (product === 'fusion-cloud') continue;
    // Exclude topics that have a product attr listing only non-fusion products
    // (e.g. product="author") – safe to exclude anything that isn't empty or fusion
    if (product && product !== 'fusion') continue;

    // Resolve path relative to ditamap location; strip copy-to patterns
    const absPath = resolve(base, href);

    if (!seen.has(absPath)) {
      seen.add(absPath);
      topics.push(absPath);
    }
  }

  return topics;
}

// ── DITA → plain text ─────────────────────────────────────────────────────────
function ditaToText(filePath) {
  if (!existsSync(filePath)) return null;
  let xml = readFileSync(filePath, 'utf8');

  // Strip XML declaration / DOCTYPE
  xml = xml.replace(/<\?[^>]*\?>/g, '');
  xml = xml.replace(/<!DOCTYPE[^>]*>/g, '');
  // Strip CDATA (keep content)
  xml = xml.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1');
  // Strip comments
  xml = xml.replace(/<!--[\s\S]*?-->/g, '');
  // Strip all tags
  xml = xml.replace(/<[^>]+>/g, ' ');
  // Decode entities
  xml = xml
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#[0-9]+;/g, ' ');
  // Normalise whitespace
  xml = xml.replace(/\s+/g, ' ').trim();
  return xml;
}

// ── prompt ────────────────────────────────────────────────────────────────────
const SYSTEM_PROMPT = `You are a precise technical terminology extractor for software documentation.
Your job is to identify domain-specific terms from Oxygen Content Fusion documentation.
Oxygen Content Fusion is a cloud-based content review and collaboration platform for DITA documentation.

Output ONLY a valid JSON array. No explanation, no markdown, no code fences.
Each element must have exactly two string fields: "term" and "category".

Categories:
  UI_ELEMENT  – named, Content-Fusion-specific UI components: named views, pages, editors, dialogs, panes
                (e.g. "Tasks Manager view", "Profile Settings page", "Task Details panel")
  FEATURE     – product features or capabilities specific to Content Fusion
                (e.g. "Review Tasks", "Projects", "Deliverables", "AI Positron integration")
  CONCEPT     – domain or technical concepts relevant to Content Fusion's domain
                (e.g. "DITA map", "Git repository", "review cycle", "ditaval filter")
  ROLE        – user roles or personas within Content Fusion
                (e.g. "Content Fusion Author", "Reviewer", "SME")
  ACTION      – named workflow actions a user performs inside Content Fusion
                (e.g. "Finish Task", "Unlock File", "Commit Changes")

Strict rules:
- Only include terms that are SPECIFIC to Oxygen Content Fusion; skip generic UI primitives
- Do NOT include: dropdown menus, breadcrumbs, checkboxes, scrollbars, generic navigation links
- Do NOT include: names of other Oxygen products (Oxygen XML Author, Oxygen XML Editor, Oxygen XML Developer)
- Do NOT include: generic authentication terms unless they name a CF-specific feature (e.g. "OIDC" is OK)
- Do NOT include: version numbers, URLs, file paths, email addresses
- Use SINGULAR form for all nouns (e.g. "reviewer" not "reviewers", "Review Task" not "Review Tasks")
  unless the plural IS the canonical product name (e.g. "Projects" is the feature name)
- Prefer the most specific/distinctive form from the text (e.g. "Content Fusion Author" over "author")
- All terms must be SHORT NOUN PHRASES (1–5 words), never full sentences or verb phrases
- If a term has both an abbreviation and a full form (e.g. "SME" and "Subject Matter Expert"), output only the full form
- Protocols and standards (OIDC, LDAP, SAML) are CONCEPT, not FEATURE
- Return at most 40 terms per topic; quality over quantity`;

const USER_PROMPT_TEMPLATE = (text) =>
  `Extract terminology from the following Oxygen Content Fusion documentation text:\n\n${text}`;

// ── Gemma 4 call ──────────────────────────────────────────────────────────────
const gateway = createGateway({ apiKey });

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function extractTerms(text, topicFile) {
  const shortName = topicFile.split('/').pop();
  process.stdout.write(`  [${shortName}] calling ${MODEL} ... `);

  let result;
  let lastErr;
  // Retry up to 5 times with exponential backoff for rate limit / transient errors
  for (let attempt = 0; attempt < 5; attempt++) {
    if (attempt > 0) {
      const delay = Math.pow(2, attempt) * 1000; // 2s, 4s, 8s, 16s
      process.stdout.write(`(retry ${attempt}, wait ${delay/1000}s) `);
      await sleep(delay);
    }
    try {
      result = await generateText({
        model: gateway(MODEL),
        system: SYSTEM_PROMPT,
        prompt: USER_PROMPT_TEMPLATE(text.slice(0, 6000)), // cap at ~6k chars
        maxTokens: 1024,
        temperature: 0.1,
      });
      lastErr = null;
      break; // success
    } catch (err) {
      lastErr = err;
      const msg = err.message ?? '';
      // Only retry on rate limit or transient errors
      if (!msg.includes('rate limit') && !msg.includes('temporarily') && !msg.includes('429') && !msg.includes('503')) {
        break; // non-retryable
      }
    }
  }

  if (lastErr) {
    console.error(`ERROR: ${lastErr.message}`);
    return { terms: [], error: lastErr.message, usage: {} };
  }

  const usage = result.usage ?? {};
  const inTok  = usage.inputTokens  ?? 0;
  const outTok = usage.outputTokens ?? 0;
  const cost   = ((inTok / 1e6) * PRICE.input) + ((outTok / 1e6) * PRICE.output);
  console.log(`✓  in=${inTok} out=${outTok} cost=$${cost.toFixed(5)}`);

  // Parse JSON from the model response
  let terms = [];
  try {
    const raw = result.text.trim();
    // Strip markdown code fence if present
    const cleaned = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '');
    terms = JSON.parse(cleaned);
    if (!Array.isArray(terms)) terms = [];
  } catch (e) {
    console.warn(`  WARNING: JSON parse failed for ${shortName}: ${e.message}`);
    console.warn(`  Raw output: ${result.text.slice(0, 200)}`);
  }

  return {
    terms,
    usage: { inputTokens: inTok, outputTokens: outTok, costUsd: cost },
    finishReason: result.finishReason,
  };
}

// ── aggregation ───────────────────────────────────────────────────────────────
function aggregateTerms(topicResults) {
  // term → { category, count, topics[] }
  const map = new Map();

  for (const { file, terms } of topicResults) {
    const topicName = file.split('/').pop().replace('.dita', '');
    for (const { term, category } of terms) {
      if (!term || !category) continue;
      // Normalise key: lowercase for dedup, but keep original capitalisation
      const key = term.trim().toLowerCase();
      if (!map.has(key)) {
        map.set(key, { term: term.trim(), category, count: 0, topics: [] });
      }
      const entry = map.get(key);
      entry.count += 1;
      if (!entry.topics.includes(topicName)) entry.topics.push(topicName);
      // Prefer capitalised form (longer/more specific)
      if (term.trim().length > entry.term.length) entry.term = term.trim();
    }
  }

  return [...map.values()].sort((a, b) => b.count - a.count || a.term.localeCompare(b.term));
}

// ── main ──────────────────────────────────────────────────────────────────────
async function main() {
  mkdirSync(OUT_DIR, { recursive: true });

  // 1. Get topic list
  const allTopics = getTopicsFromMap(DITAMAP);
  const topics = PILOT ? allTopics.slice(0, 5) : allTopics;

  console.log(`\nOxygen Content Fusion – Terminology Extraction`);
  console.log(`Model : ${MODEL}`);
  console.log(`Mode  : ${PILOT ? 'PILOT (first 5 topics)' : 'FULL'}`);
  console.log(`Topics: ${topics.length} / ${allTopics.length} total\n`);

  // 2. Extract per topic
  const topicResults = [];
  let totalTokensIn = 0, totalTokensOut = 0, totalCost = 0;

  for (const topicPath of topics) {
    const text = ditaToText(topicPath);
    if (!text || text.length < 50) {
      console.log(`  [${topicPath.split('/').pop()}] skipped (no content)`);
      continue;
    }

    const res = await extractTerms(text, topicPath);
    topicResults.push({ file: topicPath, ...res });
    // Small inter-request delay to avoid rate limits
    await sleep(800);

    totalTokensIn  += res.usage.inputTokens  ?? 0;
    totalTokensOut += res.usage.outputTokens ?? 0;
    totalCost      += res.usage.costUsd ?? 0;
  }

  // 3. Aggregate
  const allTerms = aggregateTerms(topicResults);

  // 4. Write results
  const suffix = PILOT ? '_pilot' : '';

  // Full terms JSON
  writeFileSync(
    join(OUT_DIR, `terms${suffix}.json`),
    JSON.stringify(allTerms, null, 2),
    'utf8'
  );

  // Terms by category text report
  const categories = ['UI_ELEMENT', 'FEATURE', 'CONCEPT', 'ROLE', 'ACTION'];
  let report = `Oxygen Content Fusion – Extracted Terminology\n`;
  report += `Model: ${MODEL}  |  Mode: ${PILOT ? 'PILOT' : 'FULL'}  |  Topics: ${topics.length}\n`;
  report += `Total unique terms: ${allTerms.length}\n`;
  report += `=`.repeat(60) + '\n\n';

  for (const cat of categories) {
    const catTerms = allTerms.filter(t => t.category === cat);
    if (!catTerms.length) continue;
    report += `## ${cat} (${catTerms.length})\n`;
    for (const t of catTerms) {
      report += `  ${t.term.padEnd(45)} [×${t.count}]\n`;
    }
    report += '\n';
  }

  writeFileSync(join(OUT_DIR, `terms_by_category${suffix}.txt`), report, 'utf8');

  // Run summary
  const summary = {
    model: MODEL,
    mode: PILOT ? 'pilot' : 'full',
    topicsProcessed: topicResults.length,
    topicsTotal: allTopics.length,
    uniqueTerms: allTerms.length,
    totalInputTokens: totalTokensIn,
    totalOutputTokens: totalTokensOut,
    totalCostUsd: totalCost,
    topicResults: topicResults.map(r => ({
      file: r.file.split('/').pop(),
      termsExtracted: r.terms?.length ?? 0,
      error: r.error ?? null,
      usage: r.usage,
    })),
  };
  writeFileSync(join(OUT_DIR, `run_summary${suffix}.json`), JSON.stringify(summary, null, 2), 'utf8');

  // Console summary
  console.log('\n' + '─'.repeat(60));
  console.log(`Topics processed : ${topicResults.length}`);
  console.log(`Unique terms     : ${allTerms.length}`);
  console.log(`Total tokens in  : ${totalTokensIn}`);
  console.log(`Total tokens out : ${totalTokensOut}`);
  console.log(`Total cost       : $${totalCost.toFixed(5)}`);
  console.log('─'.repeat(60));
  console.log(`\nResults written to: ${OUT_DIR}`);

  if (PILOT) {
    console.log('\n--- PILOT SAMPLE (first 20 terms) ---');
    for (const t of allTerms.slice(0, 20)) {
      console.log(`  [${t.category.padEnd(10)}] ${t.term}  (×${t.count})`);
    }
  }
}

main().catch(err => { console.error(err); process.exit(1); });
