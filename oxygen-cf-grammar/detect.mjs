/**
 * Oxygen Content Fusion – Grammar & Style Problem Detection via Gemma 4
 *
 * Steps:
 *  1. Parse chapter-content-fusion.ditamap, filter topics by ditaval
 *     (include product=fusion or no product; exclude product=fusion-cloud)
 *  2. Read each DITA file, strip XML to plain text
 *  3. Call Gemma 4 via Vercel AI Gateway with a grammar/style detection prompt
 *  4. Aggregate findings across all topics and write results
 *
 * Usage:
 *   node detect.mjs           # full run
 *   node detect.mjs --pilot   # first 5 topics only (prompt iteration)
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

  const tagRe = /<topicref\b([^>]*?)(?:\/>|>)/g;
  let m;
  while ((m = tagRe.exec(content)) !== null) {
    const attrs = m[1];
    const hrefM = attrs.match(/href="([^"]+\.dita)"/);
    if (!hrefM) continue;
    const href = hrefM[1];

    const productM = attrs.match(/product="([^"]*)"/);
    const product = productM ? productM[1] : '';

    if (product === 'fusion-cloud') continue;
    if (product && product !== 'fusion') continue;

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

  xml = xml.replace(/<\?[^>]*\?>/g, '');
  xml = xml.replace(/<!DOCTYPE[^>]*>/g, '');
  xml = xml.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1');
  xml = xml.replace(/<!--[\s\S]*?-->/g, '');

  // Expand keyref="product" before stripping tags so the LLM sees the product name.
  // Self-closing form: <ph keyref="product"/> <keyword keyref="product"/> etc.
  xml = xml.replace(/<\w+\b[^>]*\bkeyref="product"[^>]*\/>/g, 'Oxygen Content Fusion');
  // Open/close form with optional fallback content: <ph keyref="product">fallback</ph>
  xml = xml.replace(/<(\w+)\b[^>]*\bkeyref="product"[^>]*>[\s\S]*?<\/\1>/g, 'Oxygen Content Fusion');

  xml = xml.replace(/<[^>]+>/g, ' ');
  xml = xml
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#[0-9]+;/g, ' ');
  xml = xml.replace(/\s+/g, ' ').trim();
  return xml;
}

// ── prompt ────────────────────────────────────────────────────────────────────
const SYSTEM_PROMPT = `You are a professional technical editor reviewing software documentation for grammar and style problems.
The text comes from Oxygen Content Fusion documentation — a cloud-based content review and collaboration platform for DITA documentation.

Your job is to find REAL grammar, style, and clarity problems. Be selective and precise.

Output ONLY a valid JSON array. No explanation, no markdown, no code fences.
Each element must have exactly these string fields: "issue", "original", "suggestion", "severity".

Field definitions:
  "issue"      – short label for the problem type (see categories below)
  "original"   – the verbatim problematic text fragment (10–80 words, enough context to locate it)
  "suggestion" – the corrected version of ONLY the problematic fragment
  "severity"   – one of: "error", "warning", "suggestion"

Issue categories (use these exact labels):
  subject-verb-agreement   – verb does not agree with its subject
  article-usage            – wrong, missing, or unnecessary article (a/an/the)
  pronoun-agreement        – pronoun does not agree with its antecedent
  parallel-structure       – list or series items are not grammatically parallel
  dangling-modifier        – modifier lacks a clear referent
  comma-splice             – two independent clauses joined only by a comma
  run-on-sentence          – fused independent clauses without proper punctuation
  missing-comma            – comma required but absent (e.g. after introductory phrase)
  redundancy               – words that repeat the same meaning unnecessarily
  wrong-word               – word used where a different word is intended (e.g. affect/effect)
  unclear-antecedent       – pronoun reference is ambiguous
  awkward-phrasing         – grammatically correct but unusually awkward or convoluted
  tense-inconsistency      – tense shifts within a passage without reason
  word-order               – words are in an order that causes confusion or ambiguity
  spelling                 – apparent misspelling (not a product name or technical term)

Strict rules:
- ONLY report genuine, clear problems – do not flag style preferences or debatable usages
- Do NOT flag: UI element names, product names, technical terms, command names, file paths
- Do NOT flag: intentional short imperative sentences (common in UI docs)
- Do NOT flag: Oxford comma presence or absence (both are acceptable)
- Severity "error"      = clear grammatical error (wrong form, broken sentence)
- Severity "warning"    = likely error or strong style problem affecting clarity
- Severity "suggestion" = minor improvement, questionable phrasing
- Return at most 15 issues per topic; prefer errors and warnings over suggestions
- If the text has NO genuine problems, return an empty array []`;

const USER_PROMPT_TEMPLATE = (text) =>
  `Find grammar and style problems in the following Oxygen Content Fusion documentation text:\n\n${text}`;

// ── Gemma 4 call ──────────────────────────────────────────────────────────────
const gateway = createGateway({ apiKey });

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function detectProblems(text, topicFile) {
  const shortName = topicFile.split('/').pop();
  process.stdout.write(`  [${shortName}] calling ${MODEL} ... `);

  let result;
  let lastErr;
  for (let attempt = 0; attempt < 5; attempt++) {
    if (attempt > 0) {
      const delay = Math.pow(2, attempt) * 1000;
      process.stdout.write(`(retry ${attempt}, wait ${delay/1000}s) `);
      await sleep(delay);
    }
    try {
      result = await generateText({
        model: gateway(MODEL),
        system: SYSTEM_PROMPT,
        prompt: USER_PROMPT_TEMPLATE(text.slice(0, 6000)),
        maxTokens: 1500,
        temperature: 0.1,
      });
      lastErr = null;
      break;
    } catch (err) {
      lastErr = err;
      const msg = err.message ?? '';
      if (!msg.includes('rate limit') && !msg.includes('temporarily') && !msg.includes('429') && !msg.includes('503')) {
        break;
      }
    }
  }

  if (lastErr) {
    console.error(`ERROR: ${lastErr.message}`);
    return { issues: [], error: lastErr.message, usage: {} };
  }

  const usage = result.usage ?? {};
  const inTok  = usage.inputTokens  ?? 0;
  const outTok = usage.outputTokens ?? 0;
  const cost   = ((inTok / 1e6) * PRICE.input) + ((outTok / 1e6) * PRICE.output);
  console.log(`✓  in=${inTok} out=${outTok} cost=$${cost.toFixed(5)}`);

  let issues = [];
  try {
    const raw = result.text.trim();
    const cleaned = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '');
    issues = JSON.parse(cleaned);
    if (!Array.isArray(issues)) issues = [];
    // Validate structure
    issues = issues.filter(i => i.issue && i.original && i.suggestion && i.severity);
  } catch (e) {
    console.warn(`  WARNING: JSON parse failed for ${shortName}: ${e.message}`);
    console.warn(`  Raw output: ${result.text.slice(0, 200)}`);
  }

  return {
    issues,
    usage: { inputTokens: inTok, outputTokens: outTok, costUsd: cost },
    finishReason: result.finishReason,
  };
}

// ── main ──────────────────────────────────────────────────────────────────────
async function main() {
  mkdirSync(OUT_DIR, { recursive: true });

  const allTopics = getTopicsFromMap(DITAMAP);
  const topics = PILOT ? allTopics.slice(0, 5) : allTopics;

  console.log(`\nOxygen Content Fusion – Grammar & Style Detection`);
  console.log(`Model : ${MODEL}`);
  console.log(`Mode  : ${PILOT ? 'PILOT (first 5 topics)' : 'FULL'}`);
  console.log(`Topics: ${topics.length} / ${allTopics.length} total\n`);

  const topicResults = [];
  let totalTokensIn = 0, totalTokensOut = 0, totalCost = 0;

  for (const topicPath of topics) {
    const text = ditaToText(topicPath);
    if (!text || text.length < 50) {
      console.log(`  [${topicPath.split('/').pop()}] skipped (no content)`);
      continue;
    }

    const res = await detectProblems(text, topicPath);
    topicResults.push({ file: topicPath, ...res });
    await sleep(800);

    totalTokensIn  += res.usage.inputTokens  ?? 0;
    totalTokensOut += res.usage.outputTokens ?? 0;
    totalCost      += res.usage.costUsd ?? 0;
  }

  const suffix = PILOT ? '_pilot' : '';

  // ── Per-topic issues JSON (detailed) ─────────────────────────────────────────
  const detailedResults = topicResults.map(r => ({
    file: r.file.split('/').pop(),
    issueCount: r.issues?.length ?? 0,
    error: r.error ?? null,
    usage: r.usage,
    issues: r.issues ?? [],
  }));

  writeFileSync(
    join(OUT_DIR, `issues${suffix}.json`),
    JSON.stringify(detailedResults, null, 2),
    'utf8'
  );

  // ── Flat all-issues list with file reference ──────────────────────────────────
  const allIssues = [];
  for (const r of topicResults) {
    for (const issue of (r.issues ?? [])) {
      allIssues.push({ file: r.file.split('/').pop(), ...issue });
    }
  }

  writeFileSync(
    join(OUT_DIR, `all_issues${suffix}.json`),
    JSON.stringify(allIssues, null, 2),
    'utf8'
  );

  // ── Human-readable report ─────────────────────────────────────────────────────
  const SEVERITIES = ['error', 'warning', 'suggestion'];
  const issueTypes = [...new Set(allIssues.map(i => i.issue))].sort();

  let report = `Oxygen Content Fusion – Grammar & Style Report\n`;
  report += `Model: ${MODEL}  |  Mode: ${PILOT ? 'PILOT' : 'FULL'}  |  Topics: ${topics.length}\n`;
  report += `Total issues found: ${allIssues.length}\n`;

  // Counts by severity
  for (const sev of SEVERITIES) {
    const n = allIssues.filter(i => i.severity === sev).length;
    report += `  ${sev.padEnd(12)}: ${n}\n`;
  }
  report += `\n`;

  // Counts by issue type
  report += `## Issue type summary\n`;
  for (const type of issueTypes) {
    const n = allIssues.filter(i => i.issue === type).length;
    report += `  ${type.padEnd(30)} ${n}\n`;
  }
  report += `\n${'='.repeat(70)}\n\n`;

  // Per-severity details
  for (const sev of SEVERITIES) {
    const sevIssues = allIssues.filter(i => i.severity === sev);
    if (!sevIssues.length) continue;
    report += `## ${sev.toUpperCase()} (${sevIssues.length})\n\n`;
    for (const issue of sevIssues) {
      report += `[${issue.file}] [${issue.issue}]\n`;
      report += `  Original  : ${issue.original}\n`;
      report += `  Suggestion: ${issue.suggestion}\n\n`;
    }
  }

  writeFileSync(join(OUT_DIR, `report${suffix}.txt`), report, 'utf8');

  // ── Run summary ───────────────────────────────────────────────────────────────
  const summary = {
    model: MODEL,
    mode: PILOT ? 'pilot' : 'full',
    topicsProcessed: topicResults.length,
    topicsTotal: allTopics.length,
    totalIssues: allIssues.length,
    issuesBySeverity: Object.fromEntries(
      SEVERITIES.map(s => [s, allIssues.filter(i => i.severity === s).length])
    ),
    issuesByType: Object.fromEntries(
      issueTypes.map(t => [t, allIssues.filter(i => i.issue === t).length])
    ),
    totalInputTokens: totalTokensIn,
    totalOutputTokens: totalTokensOut,
    totalCostUsd: totalCost,
    topicResults: topicResults.map(r => ({
      file: r.file.split('/').pop(),
      issueCount: r.issues?.length ?? 0,
      error: r.error ?? null,
      usage: r.usage,
    })),
  };
  writeFileSync(
    join(OUT_DIR, `run_summary${suffix}.json`),
    JSON.stringify(summary, null, 2),
    'utf8'
  );

  // ── Console summary ───────────────────────────────────────────────────────────
  console.log('\n' + '─'.repeat(60));
  console.log(`Topics processed : ${topicResults.length}`);
  console.log(`Total issues     : ${allIssues.length}`);
  for (const sev of SEVERITIES) {
    const n = allIssues.filter(i => i.severity === sev).length;
    console.log(`  ${sev.padEnd(12)} : ${n}`);
  }
  console.log(`Total tokens in  : ${totalTokensIn}`);
  console.log(`Total tokens out : ${totalTokensOut}`);
  console.log(`Total cost       : $${totalCost.toFixed(5)}`);
  console.log('─'.repeat(60));
  console.log(`\nResults written to: ${OUT_DIR}`);

  if (PILOT) {
    console.log('\n--- PILOT SAMPLE (first 20 issues) ---');
    for (const issue of allIssues.slice(0, 20)) {
      console.log(`  [${issue.severity.padEnd(10)}] [${issue.issue.padEnd(25)}] ${issue.file}`);
      console.log(`    "${issue.original.slice(0, 80)}"`);
      console.log(`    → "${issue.suggestion.slice(0, 80)}"`);
    }
  }
}

main().catch(err => { console.error(err); process.exit(1); });
