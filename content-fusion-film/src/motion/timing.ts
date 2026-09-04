/** Frame/second helpers. The film is authored at a fixed 30fps. */
export const FPS = 30;

export const seconds = (s: number) => Math.round(s * FPS);
export const frames = (f: number) => f / FPS;

/**
 * A frame window with helpers, so scenes describe *moments* rather than doing
 * arithmetic inline. `at(0.5)` is the midpoint of the window.
 */
export type Window = {
  readonly start: number;
  readonly end: number;
  readonly duration: number;
  at: (t: number) => number;
};

export const windowOf = (start: number, duration: number): Window => ({
  start,
  end: start + duration,
  duration,
  at: (t: number) => start + duration * t,
});

/** Local frame inside a scene, clamped to the scene's own length. */
export const localFrame = (frame: number, sceneStart: number) => frame - sceneStart;
