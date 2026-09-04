import React, { createContext, useContext } from 'react';
import { theme } from '../../theme/contentFusion';
import { WORLD_UNIT, useSpatial } from '../spatial/SpatialContext';

const WindowCtx = createContext<{ baseZ: number }>({ baseZ: 0 });

/**
 * The Content Fusion application window.
 *
 * The window is a single world-space object, but its interior is a real 3D
 * space: children wrapped in <WindowLayer> push forward in Z so the sidebar,
 * canvas, toolbars and AI panel can separate on camera without ever leaving the
 * window's frame. This is the core of the film's 2.5D product language.
 */
export const ProductWindow: React.FC<{
  width: number;
  height: number;
  /** World Z of the window itself, so interior layers can compute defocus. */
  baseZ?: number;
  radius?: number;
  chrome?: React.ReactNode;
  children?: React.ReactNode;
  /** 0..1 — dims the whole window without touching individual layers. */
  attenuate?: number;
  style?: React.CSSProperties;
}> = ({ width, height, baseZ = 0, radius = theme.radii.window, chrome, children, attenuate = 0, style }) => (
  <WindowCtx.Provider value={{ baseZ }}>
    <div
      style={{
        position: 'relative',
        width,
        height,
        borderRadius: radius,
        transformStyle: 'preserve-3d',
        // Slight top-to-bottom falloff: the key light comes from above, so the
        // chrome is brighter than the base of the window.
        background: `linear-gradient(176deg, ${theme.colors.ink[5]} 0%, ${theme.colors.ink[3]} 30%, #0F131A 100%)`,
        // Two-part border: a bright inner hairline reads as a bezel edge catching
        // the key light, the outer ring keeps the silhouette from going muddy.
        border: `1px solid rgba(255,255,255,0.14)`,
        boxShadow: `${theme.shadows.window}, inset 0 1px 0 rgba(255,255,255,0.10), inset 0 0 0 1px rgba(255,255,255,0.02)`,
        ...style,
      }}
    >
      {chrome}
      <div style={{ position: 'absolute', inset: 0, transformStyle: 'preserve-3d' }}>{children}</div>
      {attenuate > 0 ? (
        <div
          style={{
            position: 'absolute',
            inset: 0,
            borderRadius: radius,
            background: `rgba(6,7,10,${attenuate.toFixed(3)})`,
            pointerEvents: 'none',
            transform: `translateZ(${(0.6 * WORLD_UNIT).toFixed(2)}px)`,
          }}
        />
      ) : null}
    </div>
  </WindowCtx.Provider>
);

/**
 * An interior depth layer of the product window.
 * `depth` is in world units and is additive to the window's own Z.
 */
export const WindowLayer: React.FC<{
  depth?: number;
  x?: number;
  y?: number;
  opacity?: number;
  scale?: number;
  rotationY?: number;
  blur?: number;
  alwaysSharp?: boolean;
  children?: React.ReactNode;
  style?: React.CSSProperties;
}> = ({
  depth = 0,
  x = 0,
  y = 0,
  opacity = 1,
  scale = 1,
  rotationY = 0,
  blur = 0,
  alwaysSharp = false,
  children,
  style,
}) => {
  const { baseZ } = useContext(WindowCtx);
  const { blurFor } = useSpatial();
  const total = (alwaysSharp ? 0 : blurFor(baseZ + depth)) + blur;

  return (
    <div
      style={{
        position: 'absolute',
        inset: 0,
        transformStyle: 'preserve-3d',
        transform: `translate3d(${x}px, ${y}px, ${(depth * WORLD_UNIT).toFixed(3)}px) rotateY(${rotationY}deg) scale(${scale})`,
        opacity,
        filter: total > 0.02 ? `blur(${total.toFixed(2)}px)` : undefined,
        ...style,
      }}
    >
      {children}
    </div>
  );
};

/**
 * Minimal application chrome. Deliberately *not* a fake macOS browser: no
 * traffic lights, no URL bar, no laptop bezel. It reads as a product surface.
 */
export const BrowserChrome: React.FC<{
  title?: string;
  breadcrumb?: string[];
  height?: number;
}> = ({ title = 'Content Fusion', breadcrumb = [], height = 46 }) => (
  <div
    style={{
      position: 'absolute',
      left: 0,
      right: 0,
      top: 0,
      height,
      display: 'flex',
      alignItems: 'center',
      gap: 14,
      padding: '0 18px',
      borderBottom: `1px solid ${theme.colors.stroke.hairline}`,
      background: 'linear-gradient(180deg, rgba(255,255,255,0.035) 0%, rgba(255,255,255,0) 100%)',
      borderTopLeftRadius: theme.radii.window,
      borderTopRightRadius: theme.radii.window,
      transformStyle: 'preserve-3d',
    }}
  >
    <Mark size={17} />
    <span
      style={{
        fontFamily: theme.typography.display,
        fontSize: 13,
        fontWeight: 560,
        letterSpacing: '-0.005em',
        color: theme.colors.text.primary,
        opacity: 0.92,
      }}
    >
      {title}
    </span>
    {breadcrumb.length > 0 ? (
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginLeft: 6 }}>
        {breadcrumb.map((crumb, i) => (
          <React.Fragment key={crumb}>
            <span style={{ color: theme.colors.ink[7], fontSize: 12 }}>/</span>
            <span
              style={{
                fontFamily: theme.typography.body,
                fontSize: 12,
                letterSpacing: '0.002em',
                color: i === breadcrumb.length - 1 ? theme.colors.ink[11] : theme.colors.ink[9],
              }}
            >
              {crumb}
            </span>
          </React.Fragment>
        ))}
      </div>
    ) : null}
  </div>
);

/**
 * The Content Fusion mark. A geometric monogram: two offset strokes converging
 * into one — "many sources, one structure". Vector, so it stays crisp at 4K.
 */
export const Mark: React.FC<{ size?: number; color?: string; accent?: string }> = ({
  size = 24,
  color = theme.colors.text.primary,
  accent = theme.colors.accent,
}) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" style={{ display: 'block' }}>
    {/* Three fragments of decreasing length, converging on one solid form. */}
    <rect x="2" y="5.4" width="9" height="2.4" rx="1.2" fill={color} opacity="0.5" />
    <rect x="2" y="10.8" width="6.4" height="2.4" rx="1.2" fill={color} opacity="0.72" />
    <rect x="2" y="16.2" width="3.6" height="2.4" rx="1.2" fill={color} opacity="0.5" />
    <path
      d="M13.4 4.2h4.2c2.4 0 4.4 2 4.4 4.4v6.8c0 2.4-2 4.4-4.4 4.4h-4.2z"
      fill={accent}
    />
  </svg>
);
