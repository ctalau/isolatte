import { spring as remotionSpring } from 'remotion';
import { theme } from '../theme/contentFusion';

type Preset = keyof typeof theme.motion.springs;

/**
 * Thin wrapper over Remotion's spring so scenes use the film's named presets
 * instead of scattering damping/stiffness numbers.
 */
export const namedSpring = (opts: {
  frame: number;
  fps: number;
  preset?: Preset;
  delay?: number;
  durationInFrames?: number;
}) => {
  const { frame, fps, preset = 'settle', delay = 0, durationInFrames } = opts;
  return remotionSpring({
    frame,
    fps,
    delay,
    config: theme.motion.springs[preset],
    ...(durationInFrames ? { durationInFrames } : {}),
  });
};
