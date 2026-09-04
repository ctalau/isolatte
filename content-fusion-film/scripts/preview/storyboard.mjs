#!/usr/bin/env node
/**
 * Fast storyboard preview: one bundle, one browser instance, a short burst
 * of frames per scene. This exists because a full video render pays
 * R3F/WebGL shader-compile cost on every 3D frame (~400-5000ms each) — a
 * full-length render is a 15+ minute build even at reduced resolution.
 * That cost is paid once per scene on first touch, not per frame, so
 * capturing a sparse run of frames (stride 5 → 6fps, real-time paced) gives
 * an actual sense of motion for a few extra seconds per scene instead of
 * one extra static still.
 */
import { bundle } from '@remotion/bundler';
import { openBrowser, renderStill, selectComposition } from '@remotion/renderer';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const outDir = path.join(root, 'out/storyboard');
mkdirSync(outDir, { recursive: true });

const BURST_START = 25;
const BURST_STRIDE = 5; // 30fps / 5 = 6fps playback, real-time paced
const BURST_COUNT = 12; // spans 60 frames = 2s of scene time

const burst = (start = BURST_START) =>
  Array.from({ length: BURST_COUNT }, (_, i) => start + i * BURST_STRIDE);

const scenes = [
  { id: 'Scene-fragmentation', label: 'Fragmentation', frames: burst() },
  { id: 'Scene-fusion', label: 'Fusion', frames: burst() },
  { id: 'Scene-intelligent-creation', label: 'Intelligent creation', frames: burst(40) },
  { id: 'Scene-structure', label: 'Structure', frames: burst() },
  { id: 'Scene-reuse', label: 'Reuse', frames: burst() },
  { id: 'Scene-human-control', label: 'Human control', frames: burst() },
  { id: 'Scene-adaptation', label: 'Adaptation', frames: burst() },
  { id: 'Scene-localization', label: 'Localization', frames: burst() },
  { id: 'Scene-publishing', label: 'Publishing', frames: burst(40) },
  { id: 'Scene-hero-system', label: 'Hero system', frames: burst(40) },
  { id: 'Scene-end-frame', label: 'End frame', frames: burst() },
];

const t0 = Date.now();
console.log('Bundling…');
const serveUrl = await bundle({
  entryPoint: path.join(root, 'src/index.ts'),
  onProgress: () => {},
});
console.log(`Bundled in ${Date.now() - t0}ms`);

const browser = await openBrowser('chrome');
console.log(`Browser ready at ${Date.now() - t0}ms`);

const manifest = [];

for (const scene of scenes) {
  const composition = await selectComposition({
    serveUrl,
    id: scene.id,
    puppeteerInstance: browser,
  });

  for (const frame of scene.frames) {
    const tFrame = Date.now();
    const fileName = `${scene.id}-${frame}.jpeg`;
    const output = path.join(outDir, fileName);
    await renderStill({
      composition,
      serveUrl,
      output,
      frame,
      scale: 0.5,
      imageFormat: 'jpeg',
      jpegQuality: 80,
      puppeteerInstance: browser,
    });
    const ms = Date.now() - tFrame;
    console.log(`  ${scene.id} frame ${frame} → ${ms}ms`);
    manifest.push({ scene: scene.id, label: scene.label, frame, file: fileName, ms });
  }
}

await browser.close({ silent: true });

writeFileSync(path.join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2));
console.log(`\nDone in ${Date.now() - t0}ms total. ${manifest.length} stills → ${outDir}`);
