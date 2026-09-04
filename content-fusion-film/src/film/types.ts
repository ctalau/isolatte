import type { BackgroundName } from '../components/effects/Backgrounds';
import type { ShotDefinition } from '../three/camera';

export type VisualMode = 'dom' | 'three' | 'hybrid';

export type TransitionKind =
  | 'none'
  | 'cut'
  | 'dissolve'
  | 'depthPass'
  | 'focusHandoff'
  | 'converge'
  | 'expand';

export type TransitionSpec = {
  kind: TransitionKind;
  durationInFrames: number;
  /** Optional SFX cue id, resolved through src/audio/manifest.ts. */
  sfx?: string;
};

export type SceneEvent = {
  frame: number;
  action: string;
  target: string;
  value?: number | string;
};

/**
 * A shot: camera + timed events for one scene. The DSL is intentionally thin —
 * it exists so scene timing can be edited as data (by a person or by a future
 * coding agent) without touching component code.
 */
export type ShotSpec = {
  id: string;
  duration: number;
  camera?: Omit<ShotDefinition, 'id' | 'durationInFrames'> & { durationInFrames?: number };
  events?: SceneEvent[];
};

export type FilmScene = {
  id: string;
  title: string;
  /** Resolved at build time from narration duration + handles. */
  durationInFrames: number;
  /** Fallback duration used when no narration audio exists yet. */
  fallbackDurationInFrames: number;
  narrationId?: string;
  headline?: string[];
  subhead?: string;
  visualMode: VisualMode;
  background: BackgroundName;
  productState?: string;
  transitionIn?: TransitionSpec;
  transitionOut?: TransitionSpec;
  /** Production-manifest fields. */
  cameraType: string;
  sfx: string[];
  status: 'placeholder' | 'first-pass' | 'polished';
  notes?: string;
};

export type FilmDefinition = {
  id: string;
  fps: number;
  scenes: FilmScene[];
  totalDurationInFrames: number;
};

export const defineShot = (spec: ShotSpec): ShotSpec => spec;
