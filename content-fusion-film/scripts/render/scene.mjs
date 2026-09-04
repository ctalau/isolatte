#!/usr/bin/env node
/**
 * Render (or still-sample) one scene, so a single beat can be inspected without
 * rendering the whole film.
 *
 *   npm run render:scene -- intelligent-creation
 *   npm run render:scene -- structure --stills 0,60,120
 *   npm run render:scene -- publishing --4k
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';

const args = process.argv.slice(2);
const sceneId = args.find((a) => !a.startsWith('-'));

if (!sceneId) {
  console.error('Usage: npm run render:scene -- <scene-id> [--stills 0,60,120] [--4k]');
  console.error('Scene ids: see docs/production-manifest.json');
  process.exit(1);
}

const composition = `Scene-${sceneId}`;
const stillsArg = args.find((a) => a.startsWith('--stills'));
const scale = args.includes('--4k') ? ['--scale=2'] : [];

mkdirSync(`out/${sceneId}`, { recursive: true });

if (stillsArg) {
  const frames = (stillsArg.includes('=')
    ? stillsArg.split('=')[1]
    : args[args.indexOf(stillsArg) + 1]
  )
    .split(',')
    .map((n) => n.trim());

  for (const frame of frames) {
    const out = `out/${sceneId}/frame-${String(frame).padStart(5, '0')}.png`;
    console.log(`still ${composition} @ ${frame} → ${out}`);
    const r = spawnSync(
      'npx',
      ['remotion', 'still', composition, out, `--frame=${frame}`, ...scale],
      { stdio: 'inherit', env: process.env },
    );
    if (r.status !== 0) process.exit(r.status ?? 1);
  }
  process.exit(0);
}

const out = `out/${sceneId}/${sceneId}.mp4`;
const r = spawnSync(
  'npx',
  ['remotion', 'render', composition, out, '--crf=16', ...scale],
  { stdio: 'inherit', env: process.env },
);
process.exit(r.status ?? 1);
