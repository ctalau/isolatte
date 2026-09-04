/**
 * Cinematic camera system.
 *
 * A shot is a set of keyframes over a frame range. `evaluateShot` turns the
 * current frame into a concrete camera state. That single state is consumed by
 * two renderers:
 *
 *   - <CameraRig>      — drives a real THREE.PerspectiveCamera (true-3D scenes)
 *   - projectToCss()   — drives a CSS 3D scene graph (2.5D product scenes)
 *
 * Because both consume the same state, the film can cut between a WebGL shot
 * and a DOM shot without the camera language changing underneath the viewer.
 */

import { cinematicEase, type Easing } from '../motion/easing';
import { mix, mixVec3, type Vec3 } from '../motion/interpolation';

export type CameraState = {
  position: Vec3;
  target: Vec3;
  /** Vertical field of view, degrees. Lower = longer lens = more compression. */
  fov: number;
  /** Camera roll in degrees. Used very sparingly (< 1.5°). */
  roll: number;
  /**
   * World-space Z that is in perfect focus. Layers defocus with distance from
   * it. This is a rack-focus approximation, not a real lens simulation.
   */
  focusZ: number;
  /** 0 = everything sharp, 1 = full defocus falloff. */
  aperture: number;
};

export type CameraKeyframe = {
  /** Normalised position in the shot, 0..1. */
  at: number;
  position?: Vec3;
  target?: Vec3;
  fov?: number;
  roll?: number;
  focusZ?: number;
  aperture?: number;
  /** Curve used to reach *this* keyframe from the previous one. */
  easing?: Easing;
};

export type ShotDefinition = {
  id: string;
  durationInFrames: number;
  /** Convenience two-point form. Expanded into keyframes. */
  from?: Partial<CameraState>;
  to?: Partial<CameraState>;
  easing?: Easing;
  /** Full form. Overrides from/to when present. */
  keyframes?: CameraKeyframe[];
  /**
   * Adds a very small continuous drift so the camera is never perfectly still.
   * Real cameras breathe; perfectly locked frames read as CGI.
   */
  handheld?: { amount: number; seed: number } | false;
};

export const DEFAULT_CAMERA: CameraState = {
  position: [0, 0, 8],
  target: [0, 0, 0],
  fov: 32,
  roll: 0,
  focusZ: 0,
  aperture: 0,
};

const fillState = (partial: Partial<CameraState> | undefined, base: CameraState): CameraState => ({
  position: partial?.position ?? base.position,
  target: partial?.target ?? base.target,
  fov: partial?.fov ?? base.fov,
  roll: partial?.roll ?? base.roll,
  focusZ: partial?.focusZ ?? base.focusZ,
  aperture: partial?.aperture ?? base.aperture,
});

const lerpState = (a: CameraState, b: CameraState, t: number): CameraState => ({
  position: mixVec3(a.position, b.position, t),
  target: mixVec3(a.target, b.target, t),
  fov: mix(a.fov, b.fov, t),
  roll: mix(a.roll, b.roll, t),
  focusZ: mix(a.focusZ, b.focusZ, t),
  aperture: mix(a.aperture, b.aperture, t),
});

/**
 * Sub-degree breathing. Deterministic (pure function of frame + seed) so it is
 * safe under Remotion's parallel frame rendering.
 */
const handheldOffset = (frame: number, seed: number, amount: number): { pos: Vec3; roll: number } => {
  const t = frame / 30;
  const x = Math.sin(t * 0.61 + seed * 1.7) * 0.5 + Math.sin(t * 1.13 + seed * 3.1) * 0.22;
  const y = Math.sin(t * 0.47 + seed * 2.3) * 0.5 + Math.sin(t * 0.97 + seed * 5.9) * 0.18;
  const r = Math.sin(t * 0.33 + seed * 4.4) * 0.5;
  return { pos: [x * amount, y * amount, 0], roll: r * amount * 3 };
};

export const defineShot = (shot: ShotDefinition): ShotDefinition => shot;

export const evaluateShot = (
  shot: ShotDefinition,
  frame: number,
  base: CameraState = DEFAULT_CAMERA,
): CameraState => {
  const progress = shot.durationInFrames > 0 ? frame / shot.durationInFrames : 0;
  const clamped = progress < 0 ? 0 : progress > 1 ? 1 : progress;

  const keys: CameraKeyframe[] =
    shot.keyframes && shot.keyframes.length > 0
      ? [...shot.keyframes].sort((a, b) => a.at - b.at)
      : [
          { at: 0, ...(shot.from ?? {}) },
          { at: 1, ...(shot.to ?? shot.from ?? {}), easing: shot.easing ?? cinematicEase },
        ];

  // Resolve each keyframe against the previous one so partial keys inherit.
  const states: CameraState[] = [];
  let running = fillState(keys[0], base);
  for (const k of keys) {
    running = fillState(k, running);
    states.push(running);
  }

  let result: CameraState;
  if (clamped <= keys[0]!.at) {
    result = states[0]!;
  } else if (clamped >= keys[keys.length - 1]!.at) {
    result = states[states.length - 1]!;
  } else {
    let i = 0;
    while (i < keys.length - 1 && clamped > keys[i + 1]!.at) i++;
    const k0 = keys[i]!;
    const k1 = keys[i + 1]!;
    const span = Math.max(1e-6, k1.at - k0.at);
    const local = (clamped - k0.at) / span;
    const ease = k1.easing ?? shot.easing ?? cinematicEase;
    result = lerpState(states[i]!, states[i + 1]!, ease(local));
  }

  if (shot.handheld) {
    const h = handheldOffset(frame, shot.handheld.seed, shot.handheld.amount);
    result = {
      ...result,
      position: [
        result.position[0] + h.pos[0],
        result.position[1] + h.pos[1],
        result.position[2] + h.pos[2],
      ],
      roll: result.roll + h.roll,
    };
  }

  return result;
};

/** Shorthand used by scene files: cameraShot({from, to, ...}). */
export const cameraShot = (
  opts: Omit<ShotDefinition, 'id'> & { id?: string },
): ShotDefinition => ({ id: opts.id ?? 'shot', ...opts });

// ---------------------------------------------------------------------------
// CSS 3D projection
// ---------------------------------------------------------------------------

/**
 * Design-space pixels per world unit.
 *
 * Calibrated so the nominal shot (camera at z = 8, fov 32°) renders world-space
 * geometry at exactly 1:1 in the 1920×1080 design space:
 *   perspective = (1080/2) / tan(16°) = 1883px, and 8 * 235 ≈ 1883.
 * Pushing the camera closer than z = 8 therefore magnifies, pulling back
 * shrinks — which makes shot authoring predictable.
 */
export const WORLD_UNIT = 235;

export type CssProjection = {
  /** CSS `perspective` for the scene container, in design px. */
  perspective: number;
  /** Transform applied to the world wrapper (i.e. the inverse camera). */
  worldTransform: string;
  /** Kept so layers can compute their own defocus/parallax. */
  state: CameraState;
};

const toDeg = (rad: number) => (rad * 180) / Math.PI;

/**
 * Converts a camera state into CSS 3D parameters.
 *
 * World space is right-handed, Y-up, camera looking down -Z (three.js
 * convention). CSS 3D is Y-down, so X-rotations and Z-rotations invert sign
 * while Y-rotations do not. The composed transform is the inverse camera:
 * move the world instead of the viewer.
 */
export const projectToCss = (
  state: CameraState,
  designHeight: number,
): CssProjection => {
  const fovRad = (state.fov * Math.PI) / 180;
  const perspective = designHeight / 2 / Math.tan(fovRad / 2);

  const [px, py, pz] = state.position;
  const [tx, ty, tz] = state.target;
  const dx = tx - px;
  const dy = ty - py;
  const dz = tz - pz;
  const len = Math.hypot(dx, dy, dz) || 1;
  const yaw = Math.atan2(dx / len, -dz / len);
  const pitch = Math.asin(Math.max(-1, Math.min(1, dy / len)));

  const worldTransform = [
    `translateZ(${perspective.toFixed(3)}px)`,
    `rotateZ(${state.roll.toFixed(4)}deg)`,
    `rotateX(${toDeg(pitch).toFixed(4)}deg)`,
    `rotateY(${(-toDeg(yaw)).toFixed(4)}deg)`,
    `translate3d(${(-px * WORLD_UNIT).toFixed(3)}px, ${(py * WORLD_UNIT).toFixed(3)}px, ${(
      -pz * WORLD_UNIT
    ).toFixed(3)}px)`,
  ].join(' ');

  return { perspective, worldTransform, state };
};

/**
 * Projects a world point into design-space pixels for the same camera the CSS
 * scene graph is using. SVG overlays (connection lines, routing) need this so
 * they stay glued to the 3D-positioned elements they connect.
 */
export const projectPoint = (
  state: CameraState,
  point: Vec3,
  designWidth: number,
  designHeight: number,
): [number, number] => {
  const perspective = designHeight / 2 / Math.tan((state.fov * Math.PI) / 360);
  const distance = Math.max(0.001, (state.position[2] - point[2]) * WORLD_UNIT);
  const scale = perspective / distance;
  return [
    designWidth / 2 + (point[0] - state.position[0]) * WORLD_UNIT * scale,
    designHeight / 2 - (point[1] - state.position[1]) * WORLD_UNIT * scale,
  ];
};

/**
 * Rack-focus approximation: blur in design px for a layer at world depth `z`.
 * Capped so the product never becomes unreadable (see UI LEGIBILITY rules).
 */
export const defocusBlur = (state: CameraState, z: number, maxBlur = 9): number => {
  if (state.aperture <= 0) return 0;
  const d = Math.abs(z - state.focusZ);
  // Smooth, slightly super-linear falloff with a dead zone near the focal plane.
  const normalized = Math.max(0, d - 0.06);
  return Math.min(maxBlur, normalized * 3.4 * state.aperture);
};
