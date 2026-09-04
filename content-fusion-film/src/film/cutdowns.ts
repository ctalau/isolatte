import type { FilmScene } from './types';
import { scenes } from './contentFusionFilm';

/**
 * Cutdowns.
 *
 * A cutdown is a *selection and re-timing* of the master film, never a second
 * film. Because every scene reads its own duration from the film definition and
 * derives its beats from that number, dropping scenes and shortening the rest
 * produces a coherent cut without touching a single scene component.
 *
 * Scene components are authored against a reference length and put spare frames
 * into their settle, so mild shortening reads as a tighter edit rather than as
 * a sped-up one. Cutting a scene below ~60% of its reference length will start
 * to clip its beats — that is the point at which the scene needs its own
 * short-form variant rather than a trim.
 */

export type CutdownSpec = {
  id: string;
  label: string;
  /** Scene ids, in order. */
  sceneIds: string[];
  /** Per-scene duration override, in frames. Omitted scenes keep master timing. */
  durations?: Record<string, number>;
  /** Cutdowns generally run without narration; music and type carry them. */
  narration: boolean;
};

export const cutdowns: CutdownSpec[] = [
  {
    id: 'cut-30',
    label: '30-second cutdown',
    sceneIds: ['fragmentation', 'fusion', 'intelligent-creation', 'publishing', 'end-frame'],
    durations: {
      fragmentation: 150,
      fusion: 150,
      'intelligent-creation': 280,
      publishing: 250,
      'end-frame': 130,
    },
    narration: false,
  },
  {
    id: 'cut-15',
    label: '15-second ad',
    sceneIds: ['fusion', 'intelligent-creation', 'end-frame'],
    durations: {
      fusion: 120,
      'intelligent-creation': 240,
      'end-frame': 110,
    },
    narration: false,
  },
  {
    id: 'feature-ai',
    label: 'Feature launch — AI creation',
    sceneIds: ['intelligent-creation', 'structure', 'human-control', 'end-frame'],
    narration: true,
  },
  {
    id: 'feature-reuse',
    label: 'Feature launch — reuse and localization',
    sceneIds: ['reuse', 'localization', 'publishing', 'end-frame'],
    narration: true,
  },
];

/** Resolves a cutdown into a scene list with its overridden durations. */
export const resolveCutdown = (spec: CutdownSpec): FilmScene[] =>
  spec.sceneIds
    .map((id) => scenes.find((s) => s.id === id))
    .filter((s): s is FilmScene => Boolean(s))
    .map((scene) => ({
      ...scene,
      durationInFrames: spec.durations?.[scene.id] ?? scene.durationInFrames,
    }));

export const cutdownStarts = (list: FilmScene[]): number[] => {
  const starts: number[] = [];
  let cursor = 0;
  list.forEach((scene, i) => {
    if (i > 0) cursor -= scene.transitionIn?.durationInFrames ?? 0;
    starts.push(cursor);
    cursor += scene.durationInFrames;
  });
  return starts;
};

export const cutdownDuration = (list: FilmScene[]): number => {
  const starts = cutdownStarts(list);
  return (starts[starts.length - 1] ?? 0) + (list[list.length - 1]?.durationInFrames ?? 0);
};
