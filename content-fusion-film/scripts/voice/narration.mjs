/**
 * The narration script, read from the same JSON the film imports.
 * There is deliberately no second copy of the marketing copy in this repo.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const script = JSON.parse(
  readFileSync(path.join(root, 'src/film/narration.json'), 'utf8'),
);

export const sceneNarration = script.lines.map((l) => ({
  scene: l.scene,
  narrationId: l.id,
  text: l.text,
  tailSilence: l.tailSilence,
}));
