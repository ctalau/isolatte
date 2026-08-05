#!/usr/bin/env node
/**
 * Offline checks against results/summary.json produced by run.mjs.
 */
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const summaryPath = join(__dirname, "results", "summary.json");

const summary = JSON.parse(await readFile(summaryPath, "utf8"));

const checks = [
  {
    name: "run reported ok",
    pass: summary.ok === true,
  },
  {
    name: "no error",
    pass: !summary.error,
    detail: summary.error,
  },
  {
    name: "skill discovered or used",
    pass:
      summary.skill?.discovered_in_init ||
      summary.skill?.tool_used ||
      summary.skill?.mentioned_in_transcript,
  },
  {
    name: "Romanian markers present",
    pass: summary.output?.has_romanian_markers === true,
  },
  {
    name: "translated output present",
    pass: Boolean(
      summary.output?.wrote_translated_md || summary.output?.extracted_codeblock,
    ),
  },
];

let failed = 0;
for (const check of checks) {
  const status = check.pass ? "PASS" : "FAIL";
  if (!check.pass) failed += 1;
  console.log(`${status}: ${check.name}`);
  if (!check.pass && check.detail) console.log(`  detail: ${check.detail}`);
}

console.log(
  failed === 0
    ? "\nAll verification checks passed."
    : `\n${failed} verification check(s) failed.`,
);
process.exit(failed === 0 ? 0 : 1);
