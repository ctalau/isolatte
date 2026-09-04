import React from 'react';

/**
 * Studio lighting for a world-space object.
 *
 * A product photographer would not shoot a black object on a black ground with
 * no separation. These three elements do that job in compositing:
 *   · `Halo`          — the soft key pool the object sits inside
 *   · `ContactShadow` — the grounding shadow directly beneath it
 *   · `RimLight`      — a thin bright edge that rescues the silhouette
 *
 * They are deliberately CSS/compositing rather than WebGL so they render
 * identically on every machine (see docs/POST_PROCESSING.md).
 */

export const Halo: React.FC<{
  width: number;
  height: number;
  intensity?: number;
  color?: string;
}> = ({ width, height, intensity = 1, color = 'rgba(122,156,224,' }) => (
  <div
    style={{
      position: 'absolute',
      left: -width * 0.42,
      top: -height * 0.5,
      width: width * 1.84,
      height: height * 2,
      pointerEvents: 'none',
      background: `radial-gradient(46% 42% at 50% 42%, ${color}${(0.20 * intensity).toFixed(
        3,
      )}) 0%, ${color}${(0.06 * intensity).toFixed(3)}) 40%, ${color}0) 72%)`,
      filter: 'blur(6px)',
    }}
  />
);

export const ContactShadow: React.FC<{
  width: number;
  height: number;
  /** Distance below the object, in design px. */
  offset?: number;
  intensity?: number;
}> = ({ width, height, offset = 28, intensity = 1 }) => (
  <div
    style={{
      position: 'absolute',
      left: width * 0.05,
      top: height + offset,
      width: width * 0.9,
      height: 130,
      pointerEvents: 'none',
      background: `radial-gradient(50% 50% at 50% 0%, rgba(0,0,0,${(0.62 * intensity).toFixed(
        3,
      )}) 0%, rgba(0,0,0,0) 74%)`,
      filter: 'blur(22px)',
    }}
  />
);

/**
 * A single-sided highlight along the top-left edges, matching a key light that
 * sits above and slightly left of the subject.
 */
export const RimLight: React.FC<{ radius: number; intensity?: number }> = ({
  radius,
  intensity = 1,
}) => (
  <div
    style={{
      position: 'absolute',
      inset: 0,
      borderRadius: radius,
      pointerEvents: 'none',
      background: `linear-gradient(146deg, rgba(255,255,255,${(0.085 * intensity).toFixed(
        3,
      )}) 0%, rgba(255,255,255,0) 26%)`,
      maskImage:
        'linear-gradient(146deg, #000 0%, #000 2px, transparent 2px)',
      WebkitMaskImage:
        'linear-gradient(146deg, #000 0%, #000 2px, transparent 2px)',
    }}
  />
);
