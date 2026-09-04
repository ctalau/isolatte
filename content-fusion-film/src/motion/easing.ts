/**
 * Named easing library.
 *
 * Every curve in the film comes from this file. Scene code references curves by
 * name so the whole picture shares one motion character, and so a curve can be
 * re-tuned globally in one edit.
 *
 * All functions map [0,1] -> [0,1] (some overshoot slightly above 1 on purpose)
 * and are pure, so they are safe for Remotion's deterministic rendering.
 */

export type Easing = (t: number) => number;

const clamp01 = (t: number) => (t < 0 ? 0 : t > 1 ? 1 : t);

/**
 * Closed-form cubic-bezier solver (P0=0,0 P3=1,1). Newton-Raphson on x, then
 * evaluate y. Deterministic and fast enough to call per-frame.
 */
export const cubicBezier = (x1: number, y1: number, x2: number, y2: number): Easing => {
  const cx = 3 * x1;
  const bx = 3 * (x2 - x1) - cx;
  const ax = 1 - cx - bx;
  const cy = 3 * y1;
  const by = 3 * (y2 - y1) - cy;
  const ay = 1 - cy - by;

  const sampleX = (t: number) => ((ax * t + bx) * t + cx) * t;
  const sampleDx = (t: number) => (3 * ax * t + 2 * bx) * t + cx;
  const sampleY = (t: number) => ((ay * t + by) * t + cy) * t;

  return (input: number) => {
    const x = clamp01(input);
    let t = x;
    for (let i = 0; i < 6; i++) {
      const dx = sampleDx(t);
      if (Math.abs(dx) < 1e-6) break;
      const err = sampleX(t) - x;
      if (Math.abs(err) < 1e-6) break;
      t -= err / dx;
    }
    return sampleY(t);
  };
};

/** Primary curve of the film: quiet start, decisive middle, very long settle. */
export const cinematicEase = cubicBezier(0.22, 0.61, 0.16, 1);

/** For objects arriving at rest — almost no acceleration phase. */
export const softLanding = cubicBezier(0.16, 0.84, 0.24, 1);

/** Information that must register quickly (labels, values, UI state). */
export const fastReveal = cubicBezier(0.3, 0.9, 0.35, 1);

/** Type and editorial reveals: gentle in, gentle out, never snappy. */
export const editorialEase = cubicBezier(0.36, 0.06, 0.12, 1);

/** Camera moving toward a subject — builds speed, then decelerates hard. */
export const cameraPush = cubicBezier(0.5, 0.02, 0.18, 1);

/** Camera retreating — leaves immediately, arrives softly. */
export const cameraPull = cubicBezier(0.24, 0.5, 0.1, 1);

/** Two objects becoming one: slight anticipation, then a firm commit. */
export const objectMerge = cubicBezier(0.62, -0.02, 0.2, 1);

/** Symmetric curve for cross-states (opacity swaps, focus transfer). */
export const smoothInOut = cubicBezier(0.5, 0, 0.5, 1);

/** Linear — used only where a constant rate is physically correct. */
export const linear: Easing = (t) => clamp01(t);

/**
 * Restrained overshoot. `amount` is the fraction of overshoot at the peak;
 * keep it under ~0.06 or the film starts to feel like a toy.
 */
export const gentleOvershoot = (amount = 0.04): Easing => {
  const base = cubicBezier(0.2, 0.8, 0.2, 1);
  return (t) => {
    const e = base(clamp01(t));
    // A single decaying lobe added on top of the base curve.
    const lobe = Math.sin(clamp01(t) * Math.PI) * (1 - clamp01(t)) * amount * 3;
    return e + lobe;
  };
};

/** Exponential settle — good for camera focal-length changes. */
export const expoOut: Easing = (t) => {
  const x = clamp01(t);
  return x === 1 ? 1 : 1 - Math.pow(2, -9 * x);
};

export const easings = {
  cinematicEase,
  softLanding,
  fastReveal,
  editorialEase,
  cameraPush,
  cameraPull,
  objectMerge,
  smoothInOut,
  expoOut,
  linear,
} as const;

export type EasingName = keyof typeof easings;
export const easingByName = (name: EasingName): Easing => easings[name];
