/**
 * Multi-model DITA translation experiment via Vercel AI Gateway.
 *
 * Models tested:
 *   anthropic/claude-haiku-4.5
 *   openai/gpt-5.4-mini
 *   google/gemini-3-flash
 *   alibaba/qwen3.6-plus
 *   moonshotai/kimi-k2.5
 *   zai/glm-5
 *   minimax/minimax-m2.7
 *
 * Requires AI_GATEWAY_API_KEY env var.
 * Usage: node translate.mjs
 */

import { ProxyAgent, setGlobalDispatcher } from 'undici';
import { createGateway } from '@ai-sdk/gateway';
import { generateText } from 'ai';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';

// Route Node.js fetch through the system HTTPS proxy (if set).
// The AI SDK uses undici-based fetch which does not pick up HTTPS_PROXY
// automatically; we need to install a global ProxyAgent.
if (process.env.HTTPS_PROXY) {
  setGlobalDispatcher(new ProxyAgent(process.env.HTTPS_PROXY));
}

const apiKey = process.env.AI_GATEWAY_API_KEY;
if (!apiKey) {
  console.error('Error: AI_GATEWAY_API_KEY environment variable is not set.');
  process.exit(1);
}

const gateway = createGateway({ apiKey });

const sourceDita = readFileSync('./source.dita', 'utf8');

const SYSTEM_PROMPT = `You are a professional technical translator. Translate the provided DITA XML document from English to Romanian.

Rules:
- Translate all human-readable text content to Romanian
- Preserve ALL XML tags, attribute names, and attribute values exactly as they are
- Do NOT translate: XML tag names, attribute names, XML IDs (id="..."), keyref values, href values, product attribute values, format attribute values, scope attribute values
- Do NOT translate proper nouns: Content Fusion, Oxygen WebHelp Responsive, DITA, Git, SME, WebHelp, PDF
- Preserve inline markup exactly: <i>, <b>, <ph>, <xref>, <term>, <ul>, <li>, <section>, <p>, etc.
- Output ONLY the translated XML, no explanation, no code fences, no markdown`;

const USER_PROMPT = `Translate the following DITA XML document from English to Romanian:\n\n${sourceDita}`;

// Pricing in USD per million tokens (input / output)
const PRICING = {
  'anthropic/claude-haiku-4.5':  { input: 1.00, output: 5.00 },
  'openai/gpt-5.4-mini':         { input: 0.75, output: 4.50 },
  'google/gemini-3-flash':       { input: 0.50, output: 3.00 },
  'alibaba/qwen3.6-plus':        { input: 0.50, output: 3.00 },
  'moonshotai/kimi-k2.5':        { input: 0.60, output: 3.00 },
  'zai/glm-5':                   { input: 1.00, output: 3.20 },
  'minimax/minimax-m2.7':        { input: 0.30, output: 1.20 },
};

const MODELS = Object.keys(PRICING);

function calcCost(modelId, promptTokens, completionTokens) {
  const p = PRICING[modelId];
  if (!p) return null;
  const inputCost  = (promptTokens  / 1_000_000) * p.input;
  const outputCost = (completionTokens / 1_000_000) * p.output;
  return { inputCost, outputCost, totalCost: inputCost + outputCost };
}

async function translateWithModel(modelId) {
  console.log(`\n=== ${modelId} ===`);
  const startMs = Date.now();

  let result;
  try {
    result = await generateText({
      model: gateway(modelId),
      system: SYSTEM_PROMPT,
      prompt: USER_PROMPT,
      maxTokens: 4096,
      temperature: 0.1,
    });
  } catch (err) {
    console.error(`  ERROR: ${err.message}`);
    return { modelId, error: err.message };
  }

  const elapsedMs = Date.now() - startMs;
  const usage = result.usage ?? {};
  const promptTokens     = usage.promptTokens     ?? 0;
  const completionTokens = usage.completionTokens ?? 0;
  const cost = calcCost(modelId, promptTokens, completionTokens);

  console.log(`  prompt_tokens:     ${promptTokens}`);
  console.log(`  completion_tokens: ${completionTokens}`);
  console.log(`  elapsed_ms:        ${elapsedMs}`);
  if (cost) {
    console.log(`  cost_usd:          $${cost.totalCost.toFixed(6)} (in: $${cost.inputCost.toFixed(6)}, out: $${cost.outputCost.toFixed(6)})`);
  }
  console.log(`  finish_reason:     ${result.finishReason}`);

  const slug = modelId.replace('/', '_').replace(/\./g, '-');
  const outDir = join('./results', slug);
  mkdirSync(outDir, { recursive: true });

  // Save translated DITA
  const translatedText = result.text ?? '';
  writeFileSync(join(outDir, 'translated.dita'), translatedText, 'utf8');

  // Save structured response metadata
  const meta = {
    model: modelId,
    finish_reason: result.finishReason,
    elapsed_ms: elapsedMs,
    usage: { prompt_tokens: promptTokens, completion_tokens: completionTokens },
    pricing_usd_per_mtok: PRICING[modelId],
    cost_usd: cost,
    text: translatedText,
  };
  writeFileSync(join(outDir, 'response.json'), JSON.stringify(meta, null, 2), 'utf8');

  return meta;
}

async function main() {
  const results = [];
  for (const modelId of MODELS) {
    const r = await translateWithModel(modelId);
    results.push(r);
  }

  // Write summary
  const summary = results.map(r => ({
    model: r.modelId ?? r.model,
    error: r.error ?? null,
    prompt_tokens:      r.usage?.prompt_tokens ?? null,
    completion_tokens:  r.usage?.completion_tokens ?? null,
    elapsed_ms:         r.elapsed_ms ?? null,
    cost_usd:           r.cost_usd?.totalCost ?? null,
    finish_reason:      r.finish_reason ?? null,
  }));
  writeFileSync('./results/summary.json', JSON.stringify(summary, null, 2), 'utf8');
  console.log('\n=== SUMMARY ===');
  console.table(summary);
}

main().catch(err => { console.error(err); process.exit(1); });
