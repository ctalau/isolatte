import React from 'react';
import { useCurrentFrame } from 'remotion';
import type { FilmScene, TransitionSpec } from '../../film/types';
import { cinematicEase, cameraPull, cameraPush } from '../../motion/easing';
import { ramp } from '../../motion/interpolation';

type Layer = {
  opacity: number;
  scale: number;
  blur: number;
  z: number;
};

const neutral: Layer = { opacity: 1, scale: 1, blur: 0, z: 0 };

/**
 * Semantic scene transitions.
 *
 * Each transition is a *continuation* of the idea rather than a cut: scenes
 * overlap on the timeline (see sceneStarts in contentFusionFilm.ts) and this
 * shell shapes how the outgoing and incoming scenes exchange the frame.
 *
 *   converge     — the frame collapses inward; the next scene forms from it
 *   expand       — the frame opens outward, as if the camera entered the object
 *   depthPass    — the scene passes the camera, with directional blur
 *   focusHandoff — focus, not position, carries the change
 *   dissolve     — the quietest option; used between related product beats
 */
const enterLayer = (spec: TransitionSpec | undefined, t: number): Layer => {
  if (!spec || spec.kind === 'none' || spec.kind === 'cut') return neutral;
  const e = cinematicEase(t);
  switch (spec.kind) {
    case 'converge':
      return { opacity: e, scale: 1.1 - 0.1 * e, blur: (1 - e) * 8, z: 0 };
    case 'expand':
      return { opacity: e, scale: 0.9 + 0.1 * cameraPush(t), blur: (1 - e) * 10, z: 0 };
    case 'depthPass':
      return { opacity: Math.min(1, e * 1.6), scale: 1.06 - 0.06 * e, blur: (1 - e) * 12, z: 0 };
    case 'focusHandoff':
      return { opacity: Math.min(1, e * 1.8), scale: 1.015 - 0.015 * e, blur: (1 - e) * 9, z: 0 };
    default:
      return { opacity: e, scale: 1, blur: 0, z: 0 };
  }
};

const exitLayer = (spec: TransitionSpec | undefined, t: number): Layer => {
  if (!spec || spec.kind === 'none' || spec.kind === 'cut') return neutral;
  const e = cinematicEase(t);
  switch (spec.kind) {
    case 'converge':
      return { opacity: 1 - e, scale: 1 - 0.16 * e, blur: e * 9, z: 0 };
    case 'expand':
      return { opacity: 1 - e, scale: 1 + 0.14 * cameraPull(t), blur: e * 11, z: 0 };
    case 'depthPass':
      return { opacity: 1 - Math.min(1, e * 1.3), scale: 1 + 0.3 * cameraPush(t), blur: e * 18, z: 0 };
    case 'focusHandoff':
      return { opacity: 1 - Math.min(1, e * 1.4), scale: 1.0 + 0.02 * e, blur: e * 10, z: 0 };
    default:
      return { opacity: 1 - e, scale: 1, blur: 0, z: 0 };
  }
};

export const SceneShell: React.FC<{
  scene: Pick<FilmScene, 'durationInFrames' | 'transitionIn' | 'transitionOut'>;
  children: React.ReactNode;
}> = ({ scene, children }) => {
  const f = useCurrentFrame();
  const inSpec = scene.transitionIn;
  const outSpec = scene.transitionOut;

  const inT = inSpec ? ramp(f, 0, Math.max(1, inSpec.durationInFrames)) : 1;
  const outT = outSpec
    ? ramp(f, scene.durationInFrames - Math.max(1, outSpec.durationInFrames), scene.durationInFrames)
    : 0;

  const a = enterLayer(inSpec, inT);
  const b = exitLayer(outSpec, outT);

  const opacity = a.opacity * b.opacity;
  const scale = a.scale * b.scale;
  const blur = a.blur + b.blur;

  return (
    <div
      style={{
        position: 'absolute',
        inset: 0,
        opacity,
        transform: `scale(${scale.toFixed(5)})`,
        transformOrigin: 'center center',
        filter: blur > 0.05 ? `blur(${blur.toFixed(2)}px)` : undefined,
        willChange: 'transform, opacity',
      }}
    >
      {children}
    </div>
  );
};
