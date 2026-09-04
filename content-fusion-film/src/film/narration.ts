/**
 * Narration script.
 *
 * Copy lives in data, never in JSX, so it can be revised, translated or
 * re-voiced without touching a scene component. Scene durations are derived
 * from the *generated audio length* of these lines (see scripts/voice), so
 * editing a line changes the cut — the picture follows the voice, not the
 * other way round.
 *
 * STATUS: first-pass marketing copy written for the film. Claims are kept at
 * the level of "structured content + AI + human review", which is what the
 * brief describes. Replace with approved copy before delivery.
 *
 * The copy itself lives in narration.json so the Node-side voice generator and
 * the React film read exactly the same strings — there is no second copy to
 * drift out of sync.
 */

import script from './narration.json';

export type NarrationLine = {
  id: string;
  scene: string;
  text: string;
  /** Silence appended after the line by the voice generator, in seconds. */
  tailSilence?: number;
};

/** Keyed by narration id, in film order. */
export const narration: Record<string, NarrationLine> = Object.fromEntries(
  script.lines.map((l) => [l.id, l as NarrationLine]),
);

export const narrationOrder: NarrationLine[] = script.lines as NarrationLine[];

export const headlines = {
  fragmentation: ['Your knowledge', 'is already there.'],
  fusion: ['Turn knowledge', 'into structure.'],
  intelligentCreation: ['AI that understands', 'your content model.'],
  structure: ['Structure is', 'the intelligence.'],
  reuse: ['One source.'],
  humanControl: ['Without losing', 'control.'],
  adaptation: ['Every audience.'],
  localization: ['Every language.'],
  publishing: ['Every channel.'],
  heroSystem: ['The intelligent', 'content layer.'],
  endFrame: ['Content Fusion'],
} as const;
