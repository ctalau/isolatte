import { interpolate } from 'remotion';
import { cinematicEase, type Easing } from './easing';

export type Vec3 = readonly [number, number, number];

/** Frame-window ramp with clamping and a named curve. The film's workhorse. */
export const ramp = (
  frame: number,
  from: number,
  to: number,
  easing: Easing = cinematicEase,
): number =>
  interpolate(frame, [from, to], [0, 1], {
    easing,
    extrapolateLeft: 'clamp',
    extrapolateRight: 'clamp',
  });

/** Ramp mapped onto an output range. */
export const rampTo = (
  frame: number,
  window: readonly [number, number],
  output: readonly [number, number],
  easing: Easing = cinematicEase,
): number => output[0] + (output[1] - output[0]) * ramp(frame, window[0], window[1], easing);

/**
 * In/out envelope: rises over `inFrames`, holds, falls over `outFrames`.
 * Used for anything that appears and later leaves (labels, guides, overlays).
 */
export const envelope = (
  frame: number,
  start: number,
  end: number,
  inFrames = 12,
  outFrames = 12,
  easing: Easing = cinematicEase,
): number => {
  const rise = ramp(frame, start, start + inFrames, easing);
  const fall = 1 - ramp(frame, end - outFrames, end, easing);
  return Math.min(rise, fall);
};

/** Stagger helper: nth element's window, offset by `step` frames. */
export const staggered = (index: number, start: number, step: number, duration: number) =>
  [start + index * step, start + index * step + duration] as const;

export const mix = (a: number, b: number, t: number) => a + (b - a) * t;

export const mixVec3 = (a: Vec3, b: Vec3, t: number): Vec3 => [
  mix(a[0], b[0], t),
  mix(a[1], b[1], t),
  mix(a[2], b[2], t),
];

export const clamp = (v: number, lo: number, hi: number) => (v < lo ? lo : v > hi ? hi : v);

/**
 * Deterministic value noise in [-1, 1]. Seeded and frame-driven, so it renders
 * identically every time — used for the film's "almost imperceptible" drift.
 */
export const driftNoise = (seed: number, t: number): number => {
  const a = Math.sin(seed * 12.9898 + t * 0.734) * 43758.5453;
  const b = Math.sin(seed * 78.233 + t * 0.271) * 12345.6789;
  return ((a - Math.floor(a)) + (b - Math.floor(b))) - 1;
};

/** Seeded PRNG (mulberry32). Never use Math.random() in a Remotion render. */
export const seededRandom = (seed: number) => {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};

/** Stable per-index pseudo-random in [0,1). */
export const hashed = (seed: number, index: number) => {
  let t = (seed * 374761393 + index * 668265263) >>> 0;
  t = (t ^ (t >>> 13)) >>> 0;
  t = Math.imul(t, 1274126177) >>> 0;
  return ((t ^ (t >>> 16)) >>> 0) / 4294967296;
};
