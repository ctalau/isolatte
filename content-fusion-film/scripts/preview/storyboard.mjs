#!/usr/bin/env node
/**
 * Fast storyboard preview: one bundle, one browser instance, a handful of
 * stills per scene. This exists because a full video render pays R3F/WebGL
 * shader-compile cost on every 3D frame (~400-5000ms each) — a full-length
 * render is a 15+ minute build even at reduced resolution. A storyboard
 * needs only a few dozen frames total, so it turns the same pipeline into a
 * ~1 minute preview.
 */
import { bundle } from '@remotion/bundler';
import { openBrowser, renderStill, selectComposition } from '@remotion/renderer';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const outDir = path.join(root, 'out/storyboard');
mkdirSync(outDir, { recursive: true });

const scenes = [
  { id: 'Scene-fragmentation', label: 'Fragmentation', frames: [30, 130] },
  { id: 'Scene-fusion', label: 'Fusion', frames: [30, 130] },
  { id: 'Scene-intelligent-creation', label: 'Intelligent creation', frames: [40, 200] },
  { id: 'Scene-structure', label: 'Structure', frames: [30, 150] },
  { id: 'Scene-reuse', label: 'Reuse', frames: [30, 160] },
  { id: 'Scene-human-control', label: 'Human control', frames: [30, 150] },
  { id: 'Scene-adaptation', label: 'Adaptation', frames: [30, 150] },
  { id: 'Scene-localization', label: 'Localization', frames: [30, 130] },
  { id: 'Scene-publishing', label: 'Publishing', frames: [40, 180] },
  { id: 'Scene-hero-system', label: 'Hero system', frames: [40, 180] },
  { id: 'Scene-end-frame', label: 'End frame', frames: [30, 100] },
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
