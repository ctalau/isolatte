import React from 'react';
import { theme } from '../../theme/contentFusion';

/**
 * Frosted-acrylic surface. Used for panels that float above the product plane.
 *
 * Deliberately restrained: low-alpha fill, a single hairline stroke, and one
 * top-edge highlight. No heavy glassmorphism, no rainbow refraction.
 */
export const GlassPanel: React.FC<{
  width?: number | string;
  height?: number | string;
  radius?: number;
  tint?: string;
  strokeColor?: string;
  elevation?: keyof typeof theme.shadows;
  /** 0..1 — strength of the top edge highlight. */
  sheen?: number;
  padding?: number;
  children?: React.ReactNode;
  style?: React.CSSProperties;
}> = ({
  width,
  height,
  radius = theme.radii.lg,
  tint = 'rgba(24,29,39,0.72)',
  strokeColor = theme.colors.stroke.soft,
  elevation = 'panel',
  sheen = 1,
  padding,
  children,
  style,
}) => (
  <div
    style={{
      position: 'relative',
      width,
      height,
      borderRadius: radius,
      padding,
      background: `${theme.gradients.glassSurface}, ${tint}`,
      backdropFilter: 'blur(28px) saturate(115%)',
      WebkitBackdropFilter: 'blur(28px) saturate(115%)',
      border: `1px solid ${strokeColor}`,
      boxShadow: theme.shadows[elevation],
      overflow: 'hidden',
      ...style,
    }}
  >
    {sheen > 0 ? (
      <div
        style={{
          position: 'absolute',
          inset: 0,
          borderRadius: radius,
          pointerEvents: 'none',
          background: `linear-gradient(180deg, rgba(255,255,255,${(0.10 * sheen).toFixed(
            3,
          )}) 0%, rgba(255,255,255,0) 42%)`,
          maskImage: 'linear-gradient(180deg, #000 0%, transparent 55%)',
          WebkitMaskImage: 'linear-gradient(180deg, #000 0%, transparent 55%)',
        }}
      />
    ) : null}
    {children}
  </div>
);

/** Solid product surface — an opaque UI panel, not glass. */
export const Surface: React.FC<{
  width?: number | string;
  height?: number | string;
  radius?: number;
  level?: 0 | 1 | 2 | 3;
  elevation?: keyof typeof theme.shadows | 'none';
  children?: React.ReactNode;
  style?: React.CSSProperties;
}> = ({ width, height, radius = theme.radii.md, level = 1, elevation = 'none', children, style }) => {
  const fills = [theme.colors.ink[1], theme.colors.ink[2], theme.colors.ink[3], theme.colors.ink[4]];
  return (
    <div
      style={{
        position: 'relative',
        width,
        height,
        borderRadius: radius,
        background: fills[level],
        border: `1px solid ${theme.colors.stroke.hairline}`,
        boxShadow: elevation === 'none' ? undefined : theme.shadows[elevation],
        ...style,
      }}
    >
      {children}
    </div>
  );
};

/**
 * A subtle illuminated boundary. Used to mark the *one* element the viewer
 * should be looking at. Never applied to more than one element at a time.
 */
export const GlowEdge: React.FC<{
  radius?: number;
  intensity?: number;
  color?: string;
  inset?: number;
}> = ({ radius = theme.radii.md, intensity = 1, color = theme.colors.accent, inset = 0 }) => (
  <>
    <div
      style={{
        position: 'absolute',
        inset,
        borderRadius: radius,
        border: `1px solid ${color}`,
        opacity: 0.55 * intensity,
        pointerEvents: 'none',
      }}
    />
    <div
      style={{
        position: 'absolute',
        inset: inset - 1,
        borderRadius: radius + 1,
        boxShadow: `0 0 ${(22 * intensity).toFixed(1)}px ${(2 * intensity).toFixed(1)}px ${color}`,
        opacity: 0.22 * intensity,
        pointerEvents: 'none',
      }}
    />
  </>
);

/**
 * A single light sweep travelling across a surface. `progress` is 0..1 and is
 * always frame-derived by the caller.
 */
export const LightSweep: React.FC<{
  progress: number;
  radius?: number;
  intensity?: number;
  angle?: number;
}> = ({ progress, radius = theme.radii.md, intensity = 1, angle = 100 }) => {
  if (progress <= 0 || progress >= 1) return null;
  // Fade in and out at the extremes so the sweep never pops.
  const envelope = Math.sin(progress * Math.PI);
  const x = -60 + progress * 220;
  return (
    <div
      style={{
        position: 'absolute',
        inset: 0,
        borderRadius: radius,
        overflow: 'hidden',
        pointerEvents: 'none',
      }}
    >
      <div
        style={{
          position: 'absolute',
          inset: '-40%',
          transform: `translateX(${x}%)`,
          background: `linear-gradient(${angle}deg, rgba(255,255,255,0) 42%, rgba(255,255,255,${(
            0.14 * intensity * envelope
          ).toFixed(4)}) 50%, rgba(255,255,255,0) 58%)`,
        }}
      />
    </div>
  );
};

/**
 * Floating card that can leave the UI and exist as an object in space.
 * The elevation of the shadow tracks `lift` so the card feels physical.
 */
export const FloatingCard: React.FC<{
  width?: number;
  height?: number;
  /** 0 = flush with the UI plane, 1 = fully detached. */
  lift?: number;
  radius?: number;
  accent?: string;
  children?: React.ReactNode;
  style?: React.CSSProperties;
}> = ({ width, height, lift = 0, radius = theme.radii.lg, accent, children, style }) => (
  <div
    style={{
      position: 'relative',
      width,
      height,
      borderRadius: radius,
      background: `${theme.gradients.glassSurface}, rgba(20,25,34,${(0.82 + 0.1 * lift).toFixed(3)})`,
      border: `1px solid ${accent ? accent : theme.colors.stroke.soft}`,
      boxShadow: `0 ${(2 + 10 * lift).toFixed(1)}px ${(8 + 26 * lift).toFixed(
        1,
      )}px rgba(0,0,0,${(0.32 + 0.14 * lift).toFixed(3)}), 0 ${(16 + 74 * lift).toFixed(
        1,
      )}px ${(40 + 150 * lift).toFixed(1)}px rgba(0,0,0,${(0.34 + 0.28 * lift).toFixed(3)})`,
      backdropFilter: 'blur(24px) saturate(112%)',
      WebkitBackdropFilter: 'blur(24px) saturate(112%)',
      overflow: 'hidden',
      ...style,
    }}
  >
    {children}
  </div>
);
