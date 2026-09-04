#!/usr/bin/env node
/**
 * Kokoro narration generator.
 *
 *   script text  →  Kokoro  →  per-scene WAV  →  normalise  →  manifest
 *
 * One file per scene (not one long file) so a single line can be re-voiced
 * without regenerating the film, and so scene durations can be derived from
 * measured audio length.
 *
 * Usage:
 *   npm run voice                 generate every scene
 *   npm run voice -- fusion reuse generate only those scenes
 *   KOKORO_VOICE=am_michael npm run voice
 *
 * If kokoro-js is not installed the script explains how to install it and
 * exits non-zero without touching existing audio.
 */
import { mkdir, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { voiceConfig } from './config.mjs';
import { sceneNarration } from './narration.mjs';
import { encodeWav, normalizeAndPad } from './wav.mjs';

const root = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const only = process.argv.slice(2).filter((a) => !a.startsWith('-'));

const loadKokoro = async () => {
  try {
    return await import('kokoro-js');
  } catch {
    console.error(
      [
        '',
        'kokoro-js is not installed.',
        '',
        '  npm install kokoro-js',
        '',
        'It downloads an ONNX model on first run (~90MB for the q8 build) and',
        'runs entirely locally — no API key, no network at render time.',
        '',
      ].join('\n'),
    );
    process.exit(1);
  }
};

const main = async () => {
  const { KokoroTTS } = await loadKokoro();
  const outDir = path.join(root, voiceConfig.outputDir);
  await mkdir(outDir, { recursive: true });

  console.log(`Loading Kokoro (${voiceConfig.modelId}, dtype=${voiceConfig.dtype})…`);
  const tts = await KokoroTTS.from_pretrained(voiceConfig.modelId, {
    dtype: voiceConfig.dtype,
  });

  const targets = only.length
    ? sceneNarration.filter((s) => only.includes(s.scene) || only.includes(s.narrationId))
    : sceneNarration;

  if (targets.length === 0) {
    console.error(`No scenes matched: ${only.join(', ')}`);
    process.exit(1);
  }

  const entries = {};
  for (const item of targets) {
    const file = `audio/voice/${item.scene}.wav`;
    process.stdout.write(`  ${item.scene.padEnd(22)}`);

    const audio = await tts.generate(item.text, {
      voice: voiceConfig.voiceId,
      speed: voiceConfig.speed,
    });

    const sampleRate = audio.sampling_rate ?? voiceConfig.sampleRate;
    const padded = normalizeAndPad(
      audio.audio,
      voiceConfig.normalizePeak,
      item.tailSilence ?? 0.4,
      sampleRate,
    );
    await writeFile(path.join(root, 'public', file), encodeWav(padded, sampleRate));

    const durationInSeconds = padded.length / sampleRate;
    entries[item.narrationId] = {
      scene: item.scene,
      narrationId: item.narrationId,
      file,
      text: item.text,
      durationInSeconds: Number(durationInSeconds.toFixed(3)),
      voice: voiceConfig.voiceId,
      generatedAt: new Date().toISOString(),
    };
    console.log(`${durationInSeconds.toFixed(2)}s`);
  }

  // Merge with anything generated in a previous partial run.
  const manifestPath = path.join(root, voiceConfig.manifestFile);
  let merged = entries;
  if (existsSync(manifestPath) && only.length) {
    const previous = JSON.parse(await (await import('node:fs/promises')).readFile(manifestPath, 'utf8'));
    merged = { ...previous.entries, ...entries };
  }

  await writeFile(
    manifestPath,
    JSON.stringify({ status: 'generated', voice: voiceConfig.voiceId, entries: merged }, null, 2),
  );
  await writeFile(path.join(root, voiceConfig.tsManifest), renderTsManifest(merged));

  const total = Object.values(merged).reduce((a, e) => a + e.durationInSeconds, 0);
  console.log(`\nWrote ${Object.keys(merged).length} clips, ${total.toFixed(1)}s of narration.`);
  console.log('Scene durations in the film now derive from these lengths.');
};

const renderTsManifest = (entries) => `/**
 * GENERATED FILE — do not edit. Produced by \`npm run voice\`.
 * See scripts/voice/generate.mjs.
 */
export type VoiceEntry = {
  scene: string;
  narrationId: string;
  file: string;
  text: string;
  durationInSeconds: number;
  voice: string;
  generatedAt: string;
};

export type VoiceManifest = {
  status: 'generated' | 'missing';
  voice: string | null;
  entries: Record<string, VoiceEntry>;
};

export const voiceManifest: VoiceManifest = ${JSON.stringify(
  {
    status: 'generated',
    voice: voiceConfig.voiceId,
    entries,
  },
  null,
  2,
)};
`;

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
