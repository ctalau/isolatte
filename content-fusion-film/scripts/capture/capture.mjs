#!/usr/bin/env node
/**
 * Playwright product capture.
 *
 *   CONTENT_FUSION_BASE_URL=https://… npm run capture
 *   CONTENT_FUSION_BASE_URL=… CONTENT_FUSION_STORAGE_STATE=auth.json npm run capture
 *
 * Writes full-page PNGs (and per-layer crops where a definition lists them) to
 * public/content-fusion/screens/. Refuses to run without a base URL — the film
 * must never ship a fabricated "screenshot".
 */
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { baseUrl, captures } from './captures.mjs';

const root = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const outDir = path.join(root, 'public/content-fusion/screens');

if (!baseUrl) {
  console.log('No CONTENT_FUSION_BASE_URL set — nothing was captured.\n');
  console.log('The film currently uses a reconstructed UI (see src/assets/manifest.ts).');
  console.log('These captures are defined and ready to run against a real instance:\n');
  for (const c of captures) {
    console.log(`  ${c.id.padEnd(24)} ${c.viewport.width}×${c.viewport.height}  ${c.url}`);
    console.log(`  ${''.padEnd(24)} ${c.description}`);
    if (c.layers) console.log(`  ${''.padEnd(24)} layers: ${c.layers.join(', ')}`);
    console.log('');
  }
  process.exit(0);
}

const loadPlaywright = async () => {
  try {
    return await import('playwright');
  } catch {
    console.error('playwright is not installed.\n\n  npm install -D playwright\n');
    process.exit(1);
  }
};

const main = async () => {
  const { chromium } = await loadPlaywright();
  await mkdir(outDir, { recursive: true });

  const browser = await chromium.launch();
  const context = await browser.newContext({
    // Capture at 2× so the UI survives a 4K push-in.
    deviceScaleFactor: 2,
    ...(process.env.CONTENT_FUSION_STORAGE_STATE
      ? { storageState: process.env.CONTENT_FUSION_STORAGE_STATE }
      : {}),
  });

  const results = [];
  for (const capture of captures) {
    const page = await context.newPage();
    await page.setViewportSize(capture.viewport);
    const url = new URL(capture.url, baseUrl).toString();
    process.stdout.write(`  ${capture.id.padEnd(24)}`);

    try {
      await page.goto(url, { waitUntil: 'networkidle', timeout: 45000 });
      if (capture.waitFor) await page.waitForSelector(capture.waitFor, { timeout: 20000 });
      // Let any entrance animation settle so the still is not mid-transition.
      await page.waitForTimeout(600);

      const file = path.join(outDir, `${capture.id}.png`);
      await page.screenshot({ path: file });
      results.push({ id: capture.id, status: 'captured', file: path.relative(root, file) });

      for (const layer of capture.layers ?? []) {
        const el = page.locator(`[data-capture-layer="${layer}"]`);
        if ((await el.count()) === 0) continue;
        const layerFile = path.join(outDir, `${capture.id}--${layer}.png`);
        await el.first().screenshot({ path: layerFile });
        results.push({
          id: `${capture.id}--${layer}`,
          status: 'captured',
          file: path.relative(root, layerFile),
        });
      }
      console.log('ok');
    } catch (err) {
      console.log(`failed — ${err instanceof Error ? err.message : String(err)}`);
      results.push({ id: capture.id, status: 'failed' });
    } finally {
      await page.close();
    }
  }

  await browser.close();
  await writeFile(
    path.join(outDir, 'capture-manifest.json'),
    JSON.stringify({ baseUrl, capturedAt: new Date().toISOString(), results }, null, 2),
  );
  console.log(`\nWrote ${results.filter((r) => r.status === 'captured').length} files to ${path.relative(root, outDir)}`);
};

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
