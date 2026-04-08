/**
 * Oxygen Content Fusion – Full-corpus Grammar Fix with Oxygen Change Tracking
 *
 * Processes ALL topics from results/all_issues.json (80 topics, 346 issues).
 * For each topic:
 *  1. Reads the original DITA file from userguide/DITA/topics/
 *  2. Calls Gemma 4 26B via Vercel AI Gateway with:
 *     - The complete Oxygen tracked-changes PI specification
 *     - The full DITA XML of the topic
 *     - The list of detected grammar issues for that topic
 *  3. Gemma 4 returns the COMPLETE DITA with Oxygen change-tracking PIs inline.
 *  4. Writes the fixed DITA to fixed-topics/<filename>
 *  5. Tracks per-topic latency, token usage, and cost.
 *
 * Output:
 *   fixed-topics/          – fixed DITA files (committed to git)
 *   fix-all-results/
 *     run_summary.json     – per-topic metrics (latency, tokens, cost, markers)
 *
 * Usage:
 *   node fix-all.mjs              # process all 80 topics with issues
 *   node fix-all.mjs --pilot      # first 5 topics only (prompt validation)
 *   node fix-all.mjs --dry-run    # print prompt sizes, no API calls
 *   node fix-all.mjs --resume     # skip topics already in fixed-topics/
 *
 * Requires: AI_GATEWAY_API_KEY env var
 */

import { ProxyAgent, setGlobalDispatcher } from 'undici';
import { createGateway } from '@ai-sdk/gateway';
import { generateText } from 'ai';
import {
  readFileSync, writeFileSync, mkdirSync, existsSync,
} from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

// ── proxy ─────────────────────────────────────────────────────────────────────
if (process.env.HTTPS_PROXY) {
  setGlobalDispatcher(new ProxyAgent(process.env.HTTPS_PROXY));
}

// ── config ────────────────────────────────────────────────────────────────────
const DRY_RUN = process.argv.includes('--dry-run');
const PILOT   = process.argv.includes('--pilot');
const RESUME  = process.argv.includes('--resume');

if (!DRY_RUN && !process.env.AI_GATEWAY_API_KEY) {
  console.error('Error: AI_GATEWAY_API_KEY is not set.');
  process.exit(1);
}

const MODEL = 'google/gemma-4-26b-a4b-it';

// Gemma 4 26B pricing (USD per million tokens)
const PRICE = { input: 0.13, output: 0.40 };

const __dirname   = dirname(fileURLToPath(import.meta.url));
const TOPICS_DIR  = join(__dirname, 'userguide', 'DITA', 'topics');
const ALL_ISSUES  = join(__dirname, 'results', 'all_issues.json');
const FIXED_DIR   = join(__dirname, 'fixed-topics');
const OUT_DIR     = join(__dirname, 'fix-all-results');

// ── load issues index (keyed by filename) ─────────────────────────────────────
const allIssuesFlat = JSON.parse(readFileSync(ALL_ISSUES, 'utf8'));

const issuesByFile = {};
for (const issue of allIssuesFlat) {
  issuesByFile[issue.file] = issuesByFile[issue.file] ?? [];
  issuesByFile[issue.file].push(issue);
}

// Topics that have at least one issue, sorted by file size ascending
// (process small files first so we can validate quickly)
const topicsWithIssues = Object.keys(issuesByFile)
  .filter(f => issuesByFile[f].length > 0)
  .sort((a, b) => {
    const sza = existsSync(join(TOPICS_DIR, a)) ? readFileSync(join(TOPICS_DIR, a)).length : 0;
    const szb = existsSync(join(TOPICS_DIR, b)) ? readFileSync(join(TOPICS_DIR, b)).length : 0;
    return sza - szb;
  });

// ── system prompt ─────────────────────────────────────────────────────────────
// Includes the official Oxygen XML tracked-changes PI specification
// (source: https://www.oxygenxml.com/doc/versions/28.1/ug-editor/topics/track-changes-format.html)
const SYSTEM_PROMPT = `You are a precise XML editor for DITA documentation. \
You apply grammar corrections using Oxygen XML Author change-tracking processing instructions (PIs).

## Oxygen XML Tracked Changes – PI Specification
(Source: Oxygen XML Editor 28.1 documentation, track-changes-format)

### Insertion
  <?oxy_insert_start author="AUTHOR" timestamp="TIMESTAMP"?>
  ... inserted text ...
  <?oxy_insert_end?>

### Deletion
Deletion uses a SINGLE self-closing PI. The deleted content goes in the \`content\` attribute (XML-escaped):
  <?oxy_delete content="XML-ESCAPED DELETED TEXT" author="AUTHOR" timestamp="TIMESTAMP"?>

### Replacement (delete old text, insert new text)
Place a deletion PI IMMEDIATELY followed by an insertion PI pair — no plain text between them:
  <?oxy_delete content="XML-ESCAPED OLD TEXT" author="AUTHOR" timestamp="TIMESTAMP"?><?oxy_insert_start author="AUTHOR" timestamp="TIMESTAMP"?>new text<?oxy_insert_end?>

CRITICAL RULE: For EVERY replacement change, the new text MUST be wrapped in
<?oxy_insert_start …?> … <?oxy_insert_end?> immediately after the <?oxy_delete …?> PI.
NEVER place corrected text as plain text after a deletion PI — it must always be inside insertion PI markers.

### Common Attributes
  - author     – name of the author making the change
  - timestamp  – ISO-like timestamp: YYYYMMDDTHHmmss+0000

### XML-escaping rules for the \`content\` attribute
The \`content\` attribute value must be XML-attribute-escaped:
  &  →  &amp;
  "  →  &quot;
  <  →  &lt;
  >  →  &gt;

### Author and timestamp to use for ALL changes in this session
  author="Gemma4"  timestamp="20260408T120000+0000"

## Your task

1. Read the DITA XML file provided.
2. Apply EVERY grammar correction from the issue list using the PI format above.
3. Output the COMPLETE DITA XML file — every single line — with the tracked changes embedded.
4. Do NOT apply any changes inside: <codeblock>, <codeph>, <filepath>, <apiname>, <varname>,
   <uicontrol>, <menucascade>, <wintitle> elements.
5. Do NOT modify element or attribute names, only prose text content.
6. Output ONLY the XML. No explanation, no markdown fences (no \`\`\`), no preamble.
7. Start your output directly with the XML declaration or DOCTYPE or root element.`;

// ── user prompt builder ───────────────────────────────────────────────────────
function buildUserPrompt(ditaXml, issues) {
  const issueList = issues.map((iss, i) =>
    `${i + 1}. [${iss.severity}] ${iss.issue}\n   Original  : "${iss.original}"\n   Correction: "${iss.suggestion}"`
  ).join('\n\n');

  return `Apply the following grammar corrections to the DITA file using Oxygen change-tracking PIs.\n` +
    `For each correction: place <?oxy_delete content="…"?> for the old text, then IMMEDIATELY\n` +
    `<?oxy_insert_start …?>corrected text<?oxy_insert_end?> for the new text.\n` +
    `Output the COMPLETE fixed DITA XML.\n\n` +
    `## Grammar issues to fix\n\n${issueList}\n\n## DITA file\n\n${ditaXml}`;
}

// ── select maxTokens based on file size ───────────────────────────────────────
// Larger files need more output tokens to reproduce the full XML with embedded PIs.
function maxTokensForSize(byteLen) {
  if (byteLen > 25000) return 24576;
  if (byteLen > 15000) return 16384;
  if (byteLen > 8000)  return 12288;
  return 8192;
}

// ── API call ──────────────────────────────────────────────────────────────────
const gateway = DRY_RUN ? null : createGateway({ apiKey: process.env.AI_GATEWAY_API_KEY ?? '' });

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function fixTopic(filename, issues) {
  const topicPath = join(TOPICS_DIR, filename);
  if (!existsSync(topicPath)) {
    return { skipped: true, reason: 'file not found' };
  }

  const ditaXml    = readFileSync(topicPath, 'utf8');
  const userPrompt = buildUserPrompt(ditaXml, issues);
  const maxTok     = maxTokensForSize(ditaXml.length);

  if (DRY_RUN) {
    console.log(`  DRY-RUN [${filename}]: sys=${SYSTEM_PROMPT.length}c usr=${userPrompt.length}c issues=${issues.length} maxTok=${maxTok}`);
    return { original: ditaXml, fixed: null, issues, dryRun: true };
  }

  process.stdout.write(`  [${filename}] ${ditaXml.length}B/${issues.length}iss → `);
  const t0 = Date.now();

  // Per-call timeout: 3 minutes via Promise.race (AbortController not supported through proxy)
  const CALL_TIMEOUT_MS = 3 * 60 * 1000;

  let result, lastErr;
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) {
      const delay = Math.pow(2, attempt) * 1000;
      process.stdout.write(`(retry ${attempt} ${delay/1000}s) `);
      await sleep(delay);
    }
    try {
      const apiCall   = generateText({
        model: gateway(MODEL),
        system: SYSTEM_PROMPT,
        prompt: userPrompt,
        maxTokens: maxTok,
        temperature: 0.05,
      });
      const timeoutP  = new Promise((_, rej) =>
        setTimeout(() => rej(new Error('timeout')), CALL_TIMEOUT_MS)
      );
      result  = await Promise.race([apiCall, timeoutP]);
      lastErr = null;
      break;
    } catch (err) {
      lastErr = err;
      const msg = err.message ?? '';
      if (!msg.includes('rate limit') && !msg.includes('429') &&
          !msg.includes('503') && !msg.includes('temporarily') &&
          !msg.includes('timeout')) break;
    }
  }

  const latencyMs = Date.now() - t0;

  if (lastErr) {
    console.log(`ERROR (${latencyMs}ms): ${lastErr.message}`);
    return { original: ditaXml, fixed: null, issues, error: lastErr.message, latencyMs };
  }

  const { inputTokens = 0, outputTokens = 0 } = result.usage ?? {};
  const costUsd = ((inputTokens / 1e6) * PRICE.input) + ((outputTokens / 1e6) * PRICE.output);
  const truncated = result.finishReason !== 'stop';

  console.log(`✓ in=${inputTokens} out=${outputTokens} cost=$${costUsd.toFixed(5)} lat=${latencyMs}ms${truncated ? ' ⚠TRUNC' : ''}`);

  let fixedXml = result.text.trim();
  // Strip accidental markdown fences
  fixedXml = fixedXml.replace(/^```(?:xml)?\s*/i, '').replace(/\s*```$/, '').trim();

  return {
    original: ditaXml,
    fixed: fixedXml,
    issues,
    usage: { inputTokens, outputTokens, costUsd },
    finishReason: result.finishReason,
    latencyMs,
    truncated,
  };
}

// ── main ──────────────────────────────────────────────────────────────────────
async function main() {
  mkdirSync(FIXED_DIR, { recursive: true });
  mkdirSync(OUT_DIR,   { recursive: true });

  const topics = PILOT ? topicsWithIssues.slice(0, 5) : topicsWithIssues;

  console.log(`\nOxygen CF Grammar Fix – Full corpus (all topics)`);
  console.log(`Model  : ${MODEL}`);
  console.log(`Mode   : ${DRY_RUN ? 'DRY-RUN' : PILOT ? 'PILOT (5)' : 'FULL'}`);
  console.log(`Topics : ${topics.length} (${topicsWithIssues.length} total with issues)`);
  console.log(`Resume : ${RESUME}`);
  console.log();

  const summary = [];
  let totalIn = 0, totalOut = 0, totalCost = 0, totalLat = 0;
  let skipped = 0, errors = 0, truncations = 0;

  for (let i = 0; i < topics.length; i++) {
    const filename = topics[i];
    const issues   = issuesByFile[filename] ?? [];
    const outPath  = join(FIXED_DIR, filename);
    const prefix   = `[${String(i + 1).padStart(2)}/${topics.length}]`;

    if (RESUME && existsSync(outPath)) {
      console.log(`${prefix} SKIP (already fixed): ${filename}`);
      skipped++;
      continue;
    }

    console.log(`${prefix} ${filename}`);
    const res = await fixTopic(filename, issues);

    if (res.skipped) {
      console.log(`       skipped: ${res.reason}`);
      skipped++;
      summary.push({ file: filename, skipped: true, reason: res.reason });
      continue;
    }

    if (res.dryRun) {
      summary.push({ file: filename, issueCount: issues.length, dryRun: true });
      continue;
    }

    const rec = {
      file: filename,
      issueCount: issues.length,
      originalBytes: res.original?.length ?? 0,
      latencyMs: res.latencyMs ?? 0,
      error: res.error ?? null,
      usage: res.usage ?? null,
      truncated: res.truncated ?? false,
      oxyInserts: 0,
      oxyDeletes: 0,
    };

    if (res.error) {
      errors++;
    } else if (res.fixed) {
      writeFileSync(outPath, res.fixed, 'utf8');

      rec.fixedBytes  = res.fixed.length;
      rec.oxyInserts  = (res.fixed.match(/oxy_insert_start/g)  ?? []).length;
      rec.oxyDeletes  = (res.fixed.match(/oxy_delete\b/g)      ?? []).length;

      if (rec.truncated) truncations++;

      totalIn   += res.usage?.inputTokens  ?? 0;
      totalOut  += res.usage?.outputTokens ?? 0;
      totalCost += res.usage?.costUsd      ?? 0;
      totalLat  += res.latencyMs ?? 0;
    }

    summary.push(rec);

    // Polite inter-call delay (avoid burst rate-limit)
    if (!DRY_RUN && i < topics.length - 1) await sleep(800);
  }

  if (!DRY_RUN) {
    const runSummary = {
      model: MODEL,
      mode: PILOT ? 'pilot' : 'full',
      timestamp: new Date().toISOString(),
      topicsRequested: topics.length,
      topicsFixed: summary.filter(s => s.fixedBytes).length,
      topicsSkipped: skipped,
      topicsErrored: errors,
      topicsTruncated: truncations,
      totalIssues: summary.reduce((a, s) => a + (s.issueCount ?? 0), 0),
      totalOxyInserts: summary.reduce((a, s) => a + (s.oxyInserts ?? 0), 0),
      totalOxyDeletes: summary.reduce((a, s) => a + (s.oxyDeletes ?? 0), 0),
      totalInputTokens: totalIn,
      totalOutputTokens: totalOut,
      totalCostUsd: totalCost,
      totalLatencyMs: totalLat,
      avgLatencyMs: summary.filter(s => s.latencyMs).length
        ? Math.round(totalLat / summary.filter(s => s.latencyMs).length)
        : 0,
      topicResults: summary,
    };

    writeFileSync(join(OUT_DIR, 'run_summary.json'), JSON.stringify(runSummary, null, 2), 'utf8');

    console.log('\n' + '─'.repeat(70));
    console.log(`Topics fixed    : ${runSummary.topicsFixed}`);
    console.log(`Topics skipped  : ${skipped}`);
    console.log(`Errors          : ${errors}`);
    console.log(`Truncated       : ${truncations}`);
    console.log(`Oxy inserts     : ${runSummary.totalOxyInserts}`);
    console.log(`Oxy deletes     : ${runSummary.totalOxyDeletes}`);
    console.log(`Total tokens in : ${totalIn}`);
    console.log(`Total tokens out: ${totalOut}`);
    console.log(`Total cost      : $${totalCost.toFixed(5)}`);
    console.log(`Total latency   : ${(totalLat / 1000).toFixed(1)}s`);
    console.log(`Avg latency/top : ${runSummary.avgLatencyMs}ms`);
    console.log('─'.repeat(70));
    console.log(`Fixed topics → ${FIXED_DIR}`);
    console.log(`Summary      → ${join(OUT_DIR, 'run_summary.json')}`);
  }
}

main().catch(err => { console.error(err); process.exit(1); });
