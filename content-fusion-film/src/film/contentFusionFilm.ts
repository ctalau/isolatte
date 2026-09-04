import type { FilmDefinition, FilmScene } from './types';
import { headlines, narration } from './narration';
import { voiceManifest } from './voiceManifest';
import { FPS, seconds } from '../motion/timing';

/**
 * THE FILM.
 *
 * This file is the single source of truth for what the film is: which scenes
 * exist, how long they run, what they say, how they enter and leave. Scene
 * components read their timing from here; nothing hardcodes a duration.
 *
 * Cutdowns (30s / 15s / social) are produced by filtering and re-timing this
 * list — see src/film/cutdowns.ts — not by building a second film.
 */

/** Silence held before narration starts and after it ends, in frames. */
export const voiceLeadInFrames = 14;
export const voiceLeadOutFrames = 20;

/**
 * Resolve a scene's duration.
 *
 * With generated narration, duration = lead-in + measured voice + lead-out,
 * floored by the scene's own visual minimum (some scenes need more time for the
 * move than the line takes to say). Without narration, the fallback is used.
 */
const resolveDuration = (scene: Omit<FilmScene, 'durationInFrames'>): number => {
  const entry = scene.narrationId ? voiceManifest.entries[scene.narrationId] : undefined;
  if (!entry) return scene.fallbackDurationInFrames;
  const voiceFrames = Math.round(entry.durationInSeconds * FPS);
  return Math.max(
    scene.fallbackDurationInFrames,
    voiceLeadInFrames + voiceFrames + voiceLeadOutFrames,
  );
};

type SceneSpec = Omit<FilmScene, 'durationInFrames'>;

const specs: SceneSpec[] = [
  {
    id: 'fragmentation',
    title: 'Fragmentation',
    fallbackDurationInFrames: seconds(5.4),
    narrationId: 'fragmentation',
    headline: [...headlines.fragmentation],
    // Hybrid: real content fragments are DOM (so their type stays crisp and
    // selectable-quality at 4K) placed in the CSS 3D scene graph.
    visualMode: 'hybrid',
    background: 'spatialFog',
    cameraType: 'drift through field',
    sfx: ['ambience.room', 'riser.low'],
    status: 'first-pass',
    transitionOut: { kind: 'converge', durationInFrames: 18, sfx: 'whoosh.soft' },
    notes: 'Content shards at varied depth. Must not read as a particle demo.',
  },
  {
    id: 'fusion',
    title: 'Fusion',
    fallbackDurationInFrames: seconds(5.2),
    narrationId: 'fusion',
    headline: [...headlines.fusion],
    visualMode: 'hybrid',
    background: 'spatialFog',
    cameraType: 'push to convergence',
    sfx: ['merge.content', 'impact.low'],
    status: 'first-pass',
    transitionIn: { kind: 'converge', durationInFrames: 18 },
    transitionOut: { kind: 'expand', durationInFrames: 20, sfx: 'transition.pass' },
    notes: 'First product reveal. The window assembles out of the fragments.',
  },
  {
    id: 'intelligent-creation',
    title: 'Intelligent creation',
    fallbackDurationInFrames: 258,
    narrationId: 'intelligentCreation',
    headline: [...headlines.intelligentCreation],
    visualMode: 'dom',
    background: 'productStage',
    productState: 'editor.aiSuggestion',
    cameraType: 'truck + push, focus handoff',
    sfx: ['ui.click', 'ui.confirm', 'merge.content'],
    status: 'polished',
    transitionIn: { kind: 'expand', durationInFrames: 20 },
    transitionOut: { kind: 'focusHandoff', durationInFrames: 16 },
    notes: 'HERO REFERENCE SCENE — establishes the film’s visual language.',
  },
  {
    id: 'structure',
    title: 'Structure',
    fallbackDurationInFrames: seconds(6.4),
    narrationId: 'structure',
    headline: [...headlines.structure],
    visualMode: 'dom',
    background: 'productStage',
    productState: 'editor.exploded',
    cameraType: 'pull back + orbit few degrees',
    sfx: ['data.move', 'ui.confirm'],
    status: 'first-pass',
    transitionIn: { kind: 'focusHandoff', durationInFrames: 16 },
    transitionOut: { kind: 'depthPass', durationInFrames: 18, sfx: 'whoosh.soft' },
    notes: 'The document separates into its content model, then re-locks.',
  },
  {
    id: 'reuse',
    title: 'Reuse',
    fallbackDurationInFrames: seconds(6.2),
    narrationId: 'reuse',
    headline: [...headlines.reuse],
    visualMode: 'dom',
    background: 'midnight',
    cameraType: 'follow detaching component',
    sfx: ['data.move', 'ui.confirm'],
    status: 'first-pass',
    transitionIn: { kind: 'depthPass', durationInFrames: 18 },
    transitionOut: { kind: 'dissolve', durationInFrames: 14 },
    notes: 'One component, many instances. Change propagates as a pulse.',
  },
  {
    id: 'human-control',
    title: 'Human control',
    fallbackDurationInFrames: seconds(6.4),
    narrationId: 'humanControl',
    headline: [...headlines.humanControl],
    visualMode: 'dom',
    background: 'productStage',
    productState: 'editor.review',
    cameraType: 'slow push, locked',
    sfx: ['ui.click', 'ui.confirm'],
    status: 'first-pass',
    transitionIn: { kind: 'dissolve', durationInFrames: 14 },
    transitionOut: { kind: 'focusHandoff', durationInFrames: 16 },
    notes: 'Quiet and trustworthy. Warm accent is reserved for this scene.',
  },
  {
    id: 'adaptation',
    title: 'Adaptation',
    fallbackDurationInFrames: seconds(6.2),
    narrationId: 'adaptation',
    headline: [...headlines.adaptation],
    visualMode: 'dom',
    background: 'midnight',
    cameraType: 'lateral truck through variants',
    sfx: ['data.move'],
    status: 'first-pass',
    transitionIn: { kind: 'focusHandoff', durationInFrames: 16 },
    transitionOut: { kind: 'dissolve', durationInFrames: 14 },
    notes: 'Audience fan. Same source, different shape.',
  },
  {
    id: 'localization',
    title: 'Localization',
    fallbackDurationInFrames: seconds(5.2),
    narrationId: 'localization',
    headline: [...headlines.localization],
    visualMode: 'dom',
    background: 'midnight',
    cameraType: 'small orbit, fan and recombine',
    sfx: ['data.move', 'ui.confirm'],
    status: 'first-pass',
    transitionIn: { kind: 'dissolve', durationInFrames: 14 },
    transitionOut: { kind: 'expand', durationInFrames: 20, sfx: 'transition.pass' },
    notes: 'No globes, no flags. Language codes only.',
  },
  {
    id: 'publishing',
    title: 'Publishing',
    fallbackDurationInFrames: seconds(7.4),
    narrationId: 'publishing',
    headline: [...headlines.publishing],
    visualMode: 'three',
    background: 'spatialFog',
    cameraType: 'large pull-back',
    sfx: ['data.move', 'riser.low'],
    status: 'first-pass',
    transitionIn: { kind: 'expand', durationInFrames: 20 },
    transitionOut: { kind: 'dissolve', durationInFrames: 18 },
    notes: 'Curved routing, not a neural-network graphic.',
  },
  {
    id: 'hero-system',
    title: 'Hero system',
    fallbackDurationInFrames: seconds(7.4),
    narrationId: 'heroSystem',
    headline: [...headlines.heroSystem],
    visualMode: 'three',
    background: 'spatialFog',
    cameraType: 'slow crane + orbit',
    sfx: ['impact.low', 'ambience.room'],
    status: 'first-pass',
    transitionIn: { kind: 'dissolve', durationInFrames: 18 },
    transitionOut: { kind: 'dissolve', durationInFrames: 20 },
    notes: 'Strongest 3D composition in the film.',
  },
  {
    id: 'end-frame',
    title: 'End frame',
    fallbackDurationInFrames: seconds(4.4),
    narrationId: 'endFrame',
    headline: [...headlines.endFrame],
    visualMode: 'dom',
    background: 'midnight',
    cameraType: 'locked',
    sfx: ['impact.low'],
    status: 'first-pass',
    transitionIn: { kind: 'dissolve', durationInFrames: 20 },
    notes: 'Mark, one line, one call to action. Nothing else.',
  },
];

export const scenes: FilmScene[] = specs.map((s) => ({
  ...s,
  durationInFrames: resolveDuration(s),
  subhead: s.narrationId ? narration[s.narrationId]?.text : undefined,
}));

/**
 * Scenes overlap by their incoming transition length, so a transition is a real
 * hand-off between two live scenes rather than a fade through black.
 */
export const sceneStarts: number[] = (() => {
  const starts: number[] = [];
  let cursor = 0;
  scenes.forEach((scene, i) => {
    if (i > 0) cursor -= scene.transitionIn?.durationInFrames ?? 0;
    starts.push(cursor);
    cursor += scene.durationInFrames;
  });
  return starts;
})();

export const totalDurationInFrames =
  (sceneStarts[sceneStarts.length - 1] ?? 0) +
  (scenes[scenes.length - 1]?.durationInFrames ?? 0);

export const contentFusionFilm: FilmDefinition = {
  id: 'content-fusion-master',
  fps: FPS,
  scenes,
  totalDurationInFrames,
};

export const sceneById = (id: string): FilmScene | undefined =>
  scenes.find((s) => s.id === id);

export const sceneStartById = (id: string): number => {
  const i = scenes.findIndex((s) => s.id === id);
  return i < 0 ? 0 : (sceneStarts[i] ?? 0);
};
