import React, { createContext, useContext } from 'react';
import { staticFile } from 'remotion';
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
        // The app itself is a light workspace, matching the real product's
        // review/editor screens. A thin dark rim keeps the window legible as a
        // physical object against the film's dark cinematic environments.
        background: theme.colors.ui.canvas,
        border: `1px solid rgba(0,0,0,0.5)`,
        boxShadow: `${theme.shadows.window}, inset 0 1px 0 rgba(255,255,255,0.5), inset 0 0 0 1px rgba(0,0,0,0.06)`,
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
      borderBottom: `1px solid ${theme.colors.ui.border}`,
      background: theme.colors.ui.surface,
      borderTopLeftRadius: theme.radii.window,
      borderTopRightRadius: theme.radii.window,
      transformStyle: 'preserve-3d',
    }}
  >
    <Mark size={20} />
    <span
      style={{
        fontFamily: theme.typography.display,
        fontSize: 13,
        fontWeight: 560,
        letterSpacing: '-0.005em',
        color: theme.colors.ui.textPrimary,
      }}
    >
      {title}
    </span>
    {breadcrumb.length > 0 ? (
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginLeft: 6 }}>
        {breadcrumb.map((crumb, i) => (
          <React.Fragment key={crumb}>
            <span style={{ color: theme.colors.ui.textTertiary, fontSize: 12 }}>›</span>
            <span
              style={{
                fontFamily: theme.typography.body,
                fontSize: 12,
                letterSpacing: '0.002em',
                color:
                  i === breadcrumb.length - 1
                    ? theme.colors.ui.textPrimary
                    : theme.colors.ui.textSecondary,
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
 * The in-app icon: oXygen's own app mark (orange square, white X), matching
 * the real product chrome seen in review/editor screens. Downloaded from
 * oxygenxml.com — a native square raster asset, so no color/accent props.
 */
export const Mark: React.FC<{ size?: number }> = ({ size = 24 }) => (
  <img
    src={staticFile('brand/oxygen-app-icon.png')}
    width={size}
    height={size}
    style={{ display: 'block', borderRadius: size * 0.18 }}
    alt=""
  />
);

/**
 * The Content Fusion product mark, used for the closing brand card. Downloaded
 * from oxygenxml.com/contentfusion.
 */
export const ProductMark: React.FC<{ size?: number }> = ({ size = 24 }) => (
  <img
    src={staticFile('brand/content-fusion-mark.png')}
    width={size}
    height={size}
    style={{ display: 'block', borderRadius: size * 0.18 }}
    alt=""
  />
);
