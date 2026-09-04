#!/usr/bin/env node
/**
 * Production manifest generator + consistency check.
 *
 *   npm run manifest
 *
 * Emits docs/production-manifest.json (machine-readable, for future automated
 * iteration on this film) and prints a human summary. Also fails if the
 * narration audio has drifted from the narration copy — the one place where a
 * silent inconsistency would ship a wrong-sounding film.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const read = (p) => readFileSync(path.join(root, p), 'utf8');

const FPS = 30;
const LEAD_IN = 14;
const LEAD_OUT = 20;

const script = JSON.parse(read('src/film/narration.json'));
const voicePath = 'public/audio/voice/manifest.json';
const voice = existsSync(path.join(root, voicePath))
  ? JSON.parse(read(voicePath))
  : { status: 'missing', entries: {} };

/**
 * Scene metadata is authored in TypeScript (src/film/contentFusionFilm.ts).
 * Rather than compiling it, the fields the manifest needs are extracted with a
 * narrow parse of the spec array — enough to keep the two in step, and it fails
 * loudly if the shape changes.
 */
const filmSrc = read('src/film/contentFusionFilm.ts');
const sceneBlocks = filmSrc
  .slice(filmSrc.indexOf('const specs: SceneSpec[] = ['))
  .split(/\n  \{\n/)
  .slice(1);

const field = (block, name) => {
  const m = block.match(new RegExp(`${name}:\\s*'([^']*)'`));
  return m ? m[1] : undefined;
};
const numField = (block, name) => {
  const m = block.match(new RegExp(`${name}:\\s*(?:seconds\\(([\\d.]+)\\)|(\\d+))`));
  if (!m) return undefined;
  return m[1] ? Math.round(Number(m[1]) * FPS) : Number(m[2]);
};
const listField = (block, name) => {
  const m = block.match(new RegExp(`${name}:\\s*\\[([^\\]]*)\\]`));
  if (!m) return [];
  return [...m[1].matchAll(/'([^']*)'/g)].map((x) => x[1]);
};

const scenes = sceneBlocks
  .map((block) => {
    const id = field(block, 'id');
    if (!id) return null;
    const narrationId = field(block, 'narrationId');
    const fallback = numField(block, 'fallbackDurationInFrames') ?? 0;
    const entry = narrationId ? voice.entries?.[narrationId] : undefined;
    const voiceFrames = entry ? Math.round(entry.durationInSeconds * FPS) : null;
    const duration = entry
      ? Math.max(fallback, LEAD_IN + voiceFrames + LEAD_OUT)
      : fallback;
    return {
      id,
      title: field(block, 'title'),
      frames: duration,
      seconds: Number((duration / FPS).toFixed(2)),
      voiceFile: entry?.file ?? null,
      voiceSeconds: entry?.durationInSeconds ?? null,
      narration: entry?.text ?? (narrationId ? '(not generated)' : null),
      headline: listField(block, 'headline'),
      visualMode: field(block, 'visualMode'),
      background: field(block, 'background'),
      productState: field(block, 'productState') ?? null,
      cameraType: field(block, 'cameraType'),
      sfx: listField(block, 'sfx'),
      transitionIn: field(block.split('transitionIn:')[1] ?? '', 'kind') ?? null,
      transitionOut: field(block.split('transitionOut:')[1] ?? '', 'kind') ?? null,
      status: field(block, 'status'),
      notes: (block.match(/notes:\s*\n?\s*'([\s\S]*?)',\n/) ?? [])[1] ?? field(block, 'notes') ?? null,
    };
  })
  .filter(Boolean);

/* --- consistency checks ------------------------------------------------- */
const problems = [];
for (const line of script.lines) {
  const entry = voice.entries?.[line.id];
  if (!entry) {
    problems.push(`narration "${line.id}" has no generated audio (run: npm run voice)`);
    continue;
  }
  if (entry.text !== line.text) {
    problems.push(
      `narration "${line.id}" text has changed since the audio was generated — re-run: npm run voice -- ${entry.scene}`,
    );
  }
}
for (const scene of scenes) {
  if (!scene.frames) problems.push(`scene "${scene.id}" resolved to zero frames`);
}

/* --- overlaps and total -------------------------------------------------- */
const transitionFrames = {
  none: 0, cut: 0, dissolve: 0, depthPass: 0, focusHandoff: 0, converge: 0, expand: 0,
};
const overlapMatches = [...filmSrc.matchAll(/transitionIn:\s*\{\s*kind:\s*'([a-zA-Z]+)',\s*durationInFrames:\s*(\d+)/g)];
const overlapTotal = overlapMatches.reduce((a, m) => a + Number(m[2]), 0);
void transitionFrames;

const totalFrames = scenes.reduce((a, s) => a + s.frames, 0) - overlapTotal;

const manifest = {
  film: 'Content Fusion — flagship product film',
  generatedAt: new Date().toISOString(),
  fps: FPS,
  voiceLeadInFrames: LEAD_IN,
  voiceLeadOutFrames: LEAD_OUT,
  narrationStatus: voice.status,
  narrationVoice: voice.voice ?? null,
  totalFrames,
  totalSeconds: Number((totalFrames / FPS).toFixed(2)),
  sceneCount: scenes.length,
  scenes,
  problems,
};

mkdirSync(path.join(root, 'docs'), { recursive: true });
writeFileSync(
  path.join(root, 'docs/production-manifest.json'),
  JSON.stringify(manifest, null, 2),
);

console.log(`Content Fusion film — ${scenes.length} scenes, ${manifest.totalSeconds}s at ${FPS}fps\n`);
console.log('  #  scene                 frames    s   mode    status      voice');
console.log('  ─────────────────────────────────────────────────────────────────────');
scenes.forEach((s, i) => {
  console.log(
    `  ${String(i + 1).padStart(2)} ${s.id.padEnd(21)} ${String(s.frames).padStart(5)} ${String(
      s.seconds,
    ).padStart(6)}  ${(s.visualMode ?? '').padEnd(7)} ${(s.status ?? '').padEnd(11)} ${
      s.voiceSeconds ? `${s.voiceSeconds}s` : '—'
    }`,
  );
});
console.log(`\n  overlap from transitions: -${overlapTotal} frames`);
console.log(`  total: ${totalFrames} frames (${manifest.totalSeconds}s)\n`);

if (problems.length) {
  console.log('Problems:');
  for (const p of problems) console.log(`  ✗ ${p}`);
  process.exitCode = 1;
} else {
  console.log('No problems. docs/production-manifest.json written.');
}
