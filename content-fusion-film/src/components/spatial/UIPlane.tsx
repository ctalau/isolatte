import React, { useMemo } from 'react';
import { WORLD_UNIT, useSpatial } from './SpatialContext';

export type UIPlaneProps = {
  /** World-space position. z follows the theme's depth language. */
  x?: number;
  y?: number;
  z?: number;
  rotationX?: number;
  rotationY?: number;
  rotationZ?: number;
  scale?: number;
  opacity?: number;
  /** Extra blur on top of the camera's defocus, in design px. */
  blur?: number;
  /** Disable camera defocus for this layer (e.g. UI that must stay crisp). */
  alwaysSharp?: boolean;
  brightness?: number;
  shadow?: string;
  width?: number | string;
  height?: number | string;
  /** Layers are centred on their world position by default. */
  origin?: 'center' | 'top-left';
  children?: React.ReactNode;
  style?: React.CSSProperties;
  className?: string;
};

/**
 * A single depth layer in the 2.5D scene graph.
 *
 * Placement is in world units; the parent <SpatialUI> supplies the camera, so a
 * plane automatically gains parallax, perspective foreshortening, defocus and
 * depth cueing without the scene author computing any of it.
 */
export const UIPlane: React.FC<UIPlaneProps> = ({
  x = 0,
  y = 0,
  z = 0,
  rotationX = 0,
  rotationY = 0,
  rotationZ = 0,
  scale = 1,
  opacity = 1,
  blur = 0,
  alwaysSharp = false,
  brightness,
  shadow,
  width,
  height,
  origin = 'center',
  children,
  style,
  className,
}) => {
  const { blurFor, luminanceFor } = useSpatial();

  const totalBlur = (alwaysSharp ? 0 : blurFor(z)) + blur;
  const luminance = brightness ?? luminanceFor(z);

  const transform = useMemo(
    () =>
      [
        // World -> CSS: Y is inverted, so rotateX / rotateZ flip sign.
        `translate3d(${(x * WORLD_UNIT).toFixed(3)}px, ${(-y * WORLD_UNIT).toFixed(3)}px, ${(
          z * WORLD_UNIT
        ).toFixed(3)}px)`,
        `rotateZ(${(-rotationZ).toFixed(4)}deg)`,
        `rotateY(${rotationY.toFixed(4)}deg)`,
        `rotateX(${(-rotationX).toFixed(4)}deg)`,
        `scale(${scale.toFixed(5)})`,
      ].join(' '),
    [x, y, z, rotationX, rotationY, rotationZ, scale],
  );

  const filters: string[] = [];
  if (totalBlur > 0.02) filters.push(`blur(${totalBlur.toFixed(2)}px)`);
  if (Math.abs(luminance - 1) > 0.002) filters.push(`brightness(${luminance.toFixed(4)})`);

  return (
    <div
      className={className}
      style={{
        position: 'absolute',
        left: 0,
        top: 0,
        width,
        height,
        transformStyle: 'preserve-3d',
        transformOrigin: 'center center',
        transform,
        marginLeft: origin === 'center' && typeof width === 'number' ? -width / 2 : 0,
        marginTop: origin === 'center' && typeof height === 'number' ? -height / 2 : 0,
        opacity,
        filter: filters.length ? filters.join(' ') : undefined,
        boxShadow: shadow,
        willChange: 'transform',
        ...style,
      }}
    >
      {children}
    </div>
  );
};

/**
 * Groups planes so they can be moved together while keeping their own depths.
 * Purely a transform container — it does not consume the camera itself.
 */
export const DepthGroup: React.FC<{
  x?: number;
  y?: number;
  z?: number;
  rotationX?: number;
  rotationY?: number;
  rotationZ?: number;
  scale?: number;
  opacity?: number;
  children?: React.ReactNode;
}> = ({ x = 0, y = 0, z = 0, rotationX = 0, rotationY = 0, rotationZ = 0, scale = 1, opacity = 1, children }) => (
  <div
    style={{
      position: 'absolute',
      left: 0,
      top: 0,
      transformStyle: 'preserve-3d',
      opacity,
      transform: [
        `translate3d(${x * WORLD_UNIT}px, ${-y * WORLD_UNIT}px, ${z * WORLD_UNIT}px)`,
        `rotateZ(${-rotationZ}deg)`,
        `rotateY(${rotationY}deg)`,
        `rotateX(${-rotationX}deg)`,
        `scale(${scale})`,
      ].join(' '),
    }}
  >
    {children}
  </div>
);
