/**
 * Oxygen Content Fusion – Grammar Fix via Gemma 4 with Oxygen Change Tracking
 *
 * For each of 5 selected topics (small files with many issues), this script:
 *  1. Reads the original DITA file from the userguide
 *  2. Collects the list of detected issues for that topic
 *  3. Calls Gemma 4 via Vercel AI Gateway – the model receives the full DITA XML
 *     plus the issue list and outputs the COMPLETE fixed DITA XML with Oxygen
 *     change-tracking processing instructions applied.
 *  4. Saves: original.dita, fixed.dita, issues.json, diff.txt per topic
 *
 * Usage:
 *   node fix.mjs              # run all 5 topics
 *   node fix.mjs --topic N    # run only topic N (0-4)
 *   node fix.mjs --dry-run    # show prompt sizes, do not call API
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
import { execSync } from 'child_process';

// ── proxy ─────────────────────────────────────────────────────────────────────
if (process.env.HTTPS_PROXY) {
  setGlobalDispatcher(new ProxyAgent(process.env.HTTPS_PROXY));
}

// ── config ────────────────────────────────────────────────────────────────────
const DRY_RUN = process.argv.includes('--dry-run');
const TOPIC_ARG = (() => {
  const idx = process.argv.indexOf('--topic');
  return idx >= 0 ? parseInt(process.argv[idx + 1], 10) : null;
})();

if (!DRY_RUN && !process.env.AI_GATEWAY_API_KEY) {
  console.error('Error: AI_GATEWAY_API_KEY is not set.');
  process.exit(1);
}

const MODEL = 'google/gemma-4-26b-a4b-it';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DITA_TOPICS = join(__dirname, 'userguide', 'DITA', 'topics');
const ALL_ISSUES  = join(__dirname, 'results', 'all_issues.json');
const OUT_DIR     = join(__dirname, 'fix-results');

// ── selected topics ───────────────────────────────────────────────────────────
// Chosen for small file size (fits comfortably in model output token limit)
// while having a high number of detected issues.
// File sizes: 7224, 7804, 8163, 9034, 10361 chars
const TOPICS = [
  'cf-upgrading.dita',                           //  8 issues, 7224 chars
  'CF-task-states-user-roles.dita',              //  9 issues, 7804 chars
  'content_fusion_user_interface.dita',          //  8 issues, 8163 chars
  'cf-projects-workspace_publications_view.dita',//  8 issues, 9034 chars
  'cf-amazon-s3-connector.dita',                 //  9 issues, 10361 chars
];

// ── load all issues ───────────────────────────────────────────────────────────
const allIssues = JSON.parse(readFileSync(ALL_ISSUES, 'utf8'));

function getIssuesForFile(filename) {
  return allIssues.filter(i => i.file === filename);
}

// ── system prompt ─────────────────────────────────────────────────────────────
// Includes the official Oxygen XML tracked-changes PI specification.
const SYSTEM_PROMPT = `You are a precise XML editor for DITA documentation. You apply grammar corrections using Oxygen XML Author change-tracking processing instructions.

## Oxygen XML Tracked Changes – PI Specification

### Insertion
  <?oxy_insert_start author="AUTHOR" timestamp="TIMESTAMP"?>
  ... inserted text ...
  <?oxy_insert_end?>

### Deletion
Deletion uses a SINGLE self-closing PI. The deleted content goes in the \`content\` attribute (XML-escaped):
  <?oxy_delete content="XML-ESCAPED DELETED TEXT" author="AUTHOR" timestamp="TIMESTAMP"?>

### Replacement (delete old text, insert new text)
Place a deletion PI immediately followed by an insertion PI pair:
  <?oxy_delete content="XML-ESCAPED OLD TEXT" author="AUTHOR" timestamp="AUTHOR"?><?oxy_insert_start author="AUTHOR" timestamp="TIMESTAMP"?>new text<?oxy_insert_end?>

### Common Attributes
  - author     – name of the author making the change
  - timestamp  – ISO-like timestamp: YYYYMMDDTHHmmss+0000

### Important rules for the content attribute
The \`content\` attribute value must be XML-attribute-escaped:
  &  →  &amp;
  "  →  &quot;
  <  →  &lt;
  >  →  &gt;

Use: author="Gemma4", timestamp="20260406T120000+0000" for ALL changes.

## Your task

1. Read the DITA XML file provided.
2. Apply EVERY grammar correction from the issue list using the PI format above.
3. Output the COMPLETE DITA XML file — every line — with the tracked changes embedded.
4. Do NOT fix text inside: <codeblock>, <codeph>, <filepath>, <apiname>, <varname>, <uicontrol>, <menucascade>, <wintitle> elements.
5. Output ONLY the XML. No explanation, no markdown fences, no preamble.`;

// ── user prompt ───────────────────────────────────────────────────────────────
function buildUserPrompt(ditaXml, issues) {
  const issueList = issues.map((iss, i) =>
    `${i + 1}. [${iss.severity}] ${iss.issue}\n   Original  : "${iss.original}"\n   Correction: "${iss.suggestion}"`
  ).join('\n\n');

  return `Apply the following grammar corrections to the DITA file using Oxygen change-tracking PIs.\nOutput the COMPLETE fixed DITA XML.\n\n## Grammar issues to fix\n\n${issueList}\n\n## DITA file\n\n${ditaXml}`;
}

// ── call Gemma 4 ──────────────────────────────────────────────────────────────
const gateway = DRY_RUN ? null : createGateway({ apiKey: process.env.AI_GATEWAY_API_KEY ?? '' });

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function fixTopic(filename, issues) {
  const topicPath = join(DITA_TOPICS, filename);
  if (!existsSync(topicPath)) {
    console.error(`  MISSING: ${topicPath}`);
    return null;
  }

  const ditaXml   = readFileSync(topicPath, 'utf8');
  const userPrompt = buildUserPrompt(ditaXml, issues);

  if (DRY_RUN) {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`DRY RUN: ${filename}`);
    console.log(`  System prompt : ${SYSTEM_PROMPT.length} chars`);
    console.log(`  User prompt   : ${userPrompt.length} chars`);
    console.log(`  Issues        : ${issues.length}`);
    console.log(`  DITA XML      : ${ditaXml.length} chars`);
    return { original: ditaXml, fixed: null, issues };
  }

  process.stdout.write(`  Calling ${MODEL} (${ditaXml.length} chars in) ... `);

  let result, lastErr;
  for (let attempt = 0; attempt < 5; attempt++) {
    if (attempt > 0) {
      const delay = Math.pow(2, attempt) * 1000;
      process.stdout.write(`(retry ${attempt}, wait ${delay / 1000}s) `);
      await sleep(delay);
    }
    try {
      result = await generateText({
        model: gateway(MODEL),
        system: SYSTEM_PROMPT,
        prompt: userPrompt,
        maxTokens: 8192,
        temperature: 0.05,
      });
      lastErr = null;
      break;
    } catch (err) {
      lastErr = err;
      const msg = err.message ?? '';
      if (!msg.includes('rate limit') && !msg.includes('temporarily') &&
          !msg.includes('429') && !msg.includes('503')) break;
    }
  }

  if (lastErr) {
    console.error(`  ERROR: ${lastErr.message}`);
    return { original: ditaXml, fixed: null, issues, error: lastErr.message };
  }

  const { inputTokens = 0, outputTokens = 0 } = result.usage ?? {};
  console.log(`✓  in=${inputTokens} out=${outputTokens} finish=${result.finishReason}`);

  let fixedXml = result.text.trim();
  // Strip any accidental markdown fences
  fixedXml = fixedXml.replace(/^```(?:xml)?\s*/i, '').replace(/\s*```$/, '').trim();

  return {
    original: ditaXml,
    fixed: fixedXml,
    issues,
    usage: { inputTokens, outputTokens },
    finishReason: result.finishReason,
  };
}

// ── diff helper ───────────────────────────────────────────────────────────────
function computeDiff(original, fixed, filename) {
  const a = `/tmp/orig_${filename}`;
  const b = `/tmp/fixed_${filename}`;
  writeFileSync(a, original, 'utf8');
  writeFileSync(b, fixed,    'utf8');
  try {
    return execSync(`diff -u "${a}" "${b}"`, { encoding: 'utf8' });
  } catch (e) {
    return e.stdout ?? '';
  }
}

// ── main ──────────────────────────────────────────────────────────────────────
async function main() {
  mkdirSync(OUT_DIR, { recursive: true });

  const topics = TOPIC_ARG !== null ? [TOPICS[TOPIC_ARG]] : TOPICS;

  console.log(`\nOxygen CF Grammar Fix – Full-file output with Oxygen Change Tracking`);
  console.log(`Model  : ${MODEL}`);
  console.log(`Mode   : ${DRY_RUN ? 'DRY RUN' : 'LIVE'}`);
  console.log(`Topics : ${topics.length}\n`);

  const summary = [];

  for (const filename of topics) {
    const issues      = getIssuesForFile(filename);
    const slug        = filename.replace(/\.dita$/, '');
    const topicOutDir = join(OUT_DIR, slug);
    mkdirSync(topicOutDir, { recursive: true });

    console.log(`\n[${filename}] — ${issues.length} issues`);

    const res = await fixTopic(filename, issues);
    if (!res) continue;

    writeFileSync(join(topicOutDir, 'original.dita'), res.original, 'utf8');
    writeFileSync(join(topicOutDir, 'issues.json'),   JSON.stringify(issues, null, 2), 'utf8');

    if (DRY_RUN || !res.fixed) {
      summary.push({ file: filename, issueCount: issues.length, dryRun: true });
      continue;
    }

    writeFileSync(join(topicOutDir, 'fixed.dita'), res.fixed, 'utf8');

    const diff = computeDiff(res.original, res.fixed, filename);
    writeFileSync(join(topicOutDir, 'diff.txt'), diff, 'utf8');

    const inserts = (res.fixed.match(/oxy_insert_start/g) ?? []).length;
    const deletes = (res.fixed.match(/oxy_delete\b/g)    ?? []).length;
    const truncated = res.finishReason !== 'stop';

    console.log(`  Oxygen markers: ${inserts} inserts, ${deletes} deletes | truncated=${truncated}`);
    if (truncated) console.warn(`  WARNING: model output was cut off (finish=${res.finishReason})`);

    summary.push({
      file: filename,
      issueCount: issues.length,
      oxyInserts: inserts,
      oxyDeletes: deletes,
      truncated,
      usage: res.usage,
    });

    await sleep(1200);
  }

  if (!DRY_RUN) {
    writeFileSync(join(OUT_DIR, 'summary.json'), JSON.stringify(summary, null, 2), 'utf8');
    console.log(`\n${'─'.repeat(60)}`);
    for (const s of summary) {
      if (s.dryRun) continue;
      const trunc = s.truncated ? ' ⚠ TRUNCATED' : '';
      console.log(`  ${s.file}: ${s.issueCount} issues → ${s.oxyInserts} inserts, ${s.oxyDeletes} deletes${trunc}`);
    }
    console.log(`\nResults: ${OUT_DIR}`);
  }
}

main().catch(err => { console.error(err); process.exit(1); });
