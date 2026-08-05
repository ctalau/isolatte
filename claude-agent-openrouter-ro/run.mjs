#!/usr/bin/env node
/**
 * Run Claude Agent SDK against OpenRouter (DeepSeek V4 Flash) with a
 * project skill that translates fenced codeblocks into Romanian.
 */
import { query } from "@anthropic-ai/claude-agent-sdk";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const MODEL = process.env.OPENROUTER_MODEL || "deepseek/deepseek-v4-flash";
const RESULTS_DIR = join(__dirname, "results");

function loadDotEnv() {
  // Minimal .env loader so the key need not sit in shell history.
  return readFile(join(__dirname, ".env"), "utf8")
    .then((text) => {
      for (const line of text.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const eq = trimmed.indexOf("=");
        if (eq <= 0) continue;
        const key = trimmed.slice(0, eq).trim();
        let value = trimmed.slice(eq + 1).trim();
        if (
          (value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))
        ) {
          value = value.slice(1, -1);
        }
        if (process.env[key] === undefined) process.env[key] = value;
      }
    })
    .catch(() => {
      /* .env is optional */
    });
}

function configureOpenRouter() {
  const key = process.env.OPENROUTER_API_KEY;
  if (!key) {
    console.error(
      "Missing OPENROUTER_API_KEY. Copy env.example to .env or export the key.",
    );
    process.exit(1);
  }

  // Claude Agent SDK / Claude Code Anthropic-compatible routing via OpenRouter.
  // Base URL must be https://openrouter.ai/api (no /v1 suffix).
  process.env.ANTHROPIC_BASE_URL = "https://openrouter.ai/api";
  process.env.ANTHROPIC_AUTH_TOKEN = key;
  process.env.ANTHROPIC_API_KEY = "";
  process.env.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1";

  // Route every Claude Code model tier to DeepSeek V4 Flash on OpenRouter.
  process.env.ANTHROPIC_DEFAULT_OPUS_MODEL = MODEL;
  process.env.ANTHROPIC_DEFAULT_SONNET_MODEL = MODEL;
  process.env.ANTHROPIC_DEFAULT_HAIKU_MODEL = MODEL;
  process.env.CLAUDE_CODE_SUBAGENT_MODEL = MODEL;
}

function extractText(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((block) => {
      if (!block || typeof block !== "object") return "";
      if (block.type === "text" && typeof block.text === "string") {
        return block.text;
      }
      return "";
    })
    .join("");
}

function extractCodeblock(text) {
  const match = text.match(/```[\w+-]*\n([\s\S]*?)```/);
  return match ? match[0] : null;
}

async function main() {
  await loadDotEnv();
  configureOpenRouter();
  await mkdir(RESULTS_DIR, { recursive: true });

  const sample = await readFile(join(__dirname, "fixtures", "sample.md"), "utf8");
  const translatedPath = join(RESULTS_DIR, "translated.md");
  const prompt = [
    "Use the translate-ro-codeblock skill to translate the codeblock in the",
    "sample below into Romanian. Write the translated fenced codeblock to the",
    `exact absolute path \`${translatedPath}\` using the Write tool.`,
    "Do not modify identifiers. Do not write anywhere else.",
    "",
    sample,
  ].join("\n");

  const started = Date.now();
  const messages = [];
  let initSkills = [];
  let skillToolUsed = false;
  let assistantText = "";
  let resultSubtype = null;
  let resultText = null;
  let error = null;

  console.log(`Model: ${MODEL}`);
  console.log(`OpenRouter base: ${process.env.ANTHROPIC_BASE_URL}`);
  console.log("Starting Claude Agent SDK query...\n");

  try {
    for await (const message of query({
      prompt,
      options: {
        cwd: __dirname,
        model: MODEL,
        settingSources: ["project"],
        skills: ["translate-ro-codeblock"],
        allowedTools: ["Read", "Write", "Skill"],
        permissionMode: "bypassPermissions",
        maxTurns: 8,
      },
    })) {
      messages.push(message);

      if (message.type === "system" && message.subtype === "init") {
        initSkills = Array.isArray(message.skills) ? message.skills : [];
        console.log("Init skills:", JSON.stringify(initSkills));
        if (message.model) console.log("Resolved model:", message.model);
      }

      if (message.type === "assistant") {
        const content = message.message?.content;
        const text = extractText(content);
        if (text) {
          assistantText += (assistantText ? "\n" : "") + text;
          console.log("--- assistant ---");
          console.log(text);
        }
        if (Array.isArray(content)) {
          for (const block of content) {
            if (
              block?.type === "tool_use" &&
              (block.name === "Skill" ||
                block.name === "skill" ||
                String(block.name || "").toLowerCase().includes("skill"))
            ) {
              skillToolUsed = true;
              console.log("Skill tool invoked:", JSON.stringify(block.input));
            }
            if (block?.type === "tool_use") {
              console.log(`Tool use: ${block.name}`);
            }
          }
        }
      }

      if (message.type === "result") {
        resultSubtype = message.subtype;
        resultText = message.result ?? null;
        if (message.is_error) {
          error = message.result || message.errors || "result error";
        }
        console.log("\nResult subtype:", resultSubtype);
        if (resultText) console.log("Result text:\n", resultText);
      }
    }
  } catch (err) {
    error = err instanceof Error ? err.stack || err.message : String(err);
    console.error("Query failed:", error);
  }

  const elapsedMs = Date.now() - started;

  let translatedFile = null;
  try {
    translatedFile = await readFile(
      join(RESULTS_DIR, "translated.md"),
      "utf8",
    );
  } catch {
    translatedFile = null;
  }

  const combinedText = [assistantText, resultText, translatedFile]
    .filter(Boolean)
    .join("\n");
  const codeblock = extractCodeblock(translatedFile || combinedText);

  const romanianMarkers = [
    /[ăâîșțĂÂÎȘȚ]/,
    /\b(Salut|Bună|Bine ai venit|Calculează|Returnează|mesaj|utilizator|atelier|prietenos|punctul de intrare)\b/i,
  ];
  const hasRomanian = romanianMarkers.some((re) => re.test(combinedText));
  const skillDiscovered =
    initSkills.includes("translate-ro-codeblock") ||
    initSkills.some((s) => String(s).includes("translate-ro-codeblock"));

  // Also treat Skill tool use OR explicit instruction-following as evidence
  // when the model embeds skill guidance without a formal tool call.
  const skillMentioned = /translate-ro-codeblock/i.test(
    JSON.stringify(messages),
  );

  const summary = {
    ok: Boolean(
      !error &&
        (skillDiscovered || skillToolUsed || skillMentioned) &&
        hasRomanian &&
        (translatedFile || codeblock),
    ),
    model: MODEL,
    elapsed_ms: elapsedMs,
    error: error ? String(error) : null,
    skill: {
      name: "translate-ro-codeblock",
      discovered_in_init: skillDiscovered,
      init_skills: initSkills,
      tool_used: skillToolUsed,
      mentioned_in_transcript: skillMentioned,
    },
    output: {
      wrote_translated_md: Boolean(translatedFile),
      has_romanian_markers: hasRomanian,
      extracted_codeblock: codeblock,
      assistant_text_preview: assistantText.slice(0, 2000),
      translated_file: translatedFile,
    },
    result_subtype: resultSubtype,
    message_count: messages.length,
  };

  await writeFile(
    join(RESULTS_DIR, "summary.json"),
    JSON.stringify(summary, null, 2) + "\n",
  );
  await writeFile(
    join(RESULTS_DIR, "transcript.json"),
    JSON.stringify(messages, null, 2) + "\n",
  );

  console.log("\n=== SUMMARY ===");
  console.log(JSON.stringify(summary, null, 2));
  console.log(`\nWrote ${join(RESULTS_DIR, "summary.json")}`);

  process.exit(summary.ok ? 0 : 2);
}

main();
