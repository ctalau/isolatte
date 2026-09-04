#!/usr/bin/env node
/**
 * Delivery master render.
 *
 * Preview encoding and master encoding are deliberately separate:
 *   · preview — H.264, small, fast, for review
 *   · master  — ProRes 4444 if the renderer supports it, otherwise the highest
 *               practical H.264. A master is an intermediate, not a deliverable
 *               for the web, so it is not CRF-tuned for size.
 *
 *   npm run render:master              4K ProRes (or H.264 fallback)
 *   npm run render:master -- --1080    1080 master
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';

const args = process.argv.slice(2);
const is1080 = args.includes('--1080');
const composition = is1080 ? 'ContentFusion1080' : 'ContentFusionMaster';

mkdirSync('out', { recursive: true });

const proresOut = `out/content-fusion-master${is1080 ? '-1080' : '-4k'}.mov`;
const h264Out = `out/content-fusion-master${is1080 ? '-1080' : '-4k'}.mp4`;

const run = (extra, output) =>
  spawnSync(
    'npx',
    ['remotion', 'render', composition, output, '--log=info', ...extra],
    { stdio: 'inherit', env: process.env },
  );

console.log(`Rendering ${composition} → ProRes 4444 …`);
const prores = run(['--codec=prores', '--prores-profile=4444'], proresOut);

if (prores.status !== 0) {
  console.log('\nProRes unavailable in this environment — falling back to high-quality H.264.');
  const h264 = run(['--codec=h264', '--crf=12', '--pixel-format=yuv420p'], h264Out);
  process.exit(h264.status ?? 1);
}
process.exit(0);
