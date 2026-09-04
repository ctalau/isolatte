import React, { createContext, useContext, useMemo } from 'react';
import {
  DEFAULT_CAMERA,
  WORLD_UNIT,
  defocusBlur,
  projectToCss,
  type CameraState,
} from '../../three/camera';

export const DESIGN_WIDTH = 1920;
export const DESIGN_HEIGHT = 1080;

type SpatialContextValue = {
  camera: CameraState;
  perspective: number;
  /** Blur (design px) a layer at world depth z should receive. */
  blurFor: (z: number) => number;
  /** Brightness multiplier for a layer at depth z (depth cueing). */
  luminanceFor: (z: number) => number;
};

const SpatialCtx = createContext<SpatialContextValue | null>(null);

export const useSpatial = (): SpatialContextValue => {
  const ctx = useContext(SpatialCtx);
  if (!ctx) {
    // Scenes may render UI components outside a <SpatialUI> (flat mode).
    return {
      camera: DEFAULT_CAMERA,
      perspective: DESIGN_HEIGHT,
      blurFor: () => 0,
      luminanceFor: () => 1,
    };
  }
  return ctx;
};

/**
 * Root of the 2.5D scene graph.
 *
 * Establishes the CSS perspective and applies the inverse-camera transform to
 * its children. Everything inside is authored in world units; a `<UIPlane>`
 * converts world coordinates into CSS 3D placement.
 */
export const SpatialUI: React.FC<{
  camera: CameraState;
  children: React.ReactNode;
  /** Depth cueing strength — how much far layers lose brightness. */
  depthCue?: number;
  style?: React.CSSProperties;
}> = ({ camera, children, depthCue = 0.1, style }) => {
  const projection = useMemo(() => projectToCss(camera, DESIGN_HEIGHT), [camera]);

  const value = useMemo<SpatialContextValue>(
    () => ({
      camera,
      perspective: projection.perspective,
      blurFor: (z: number) => defocusBlur(camera, z),
      luminanceFor: (z: number) => {
        // Layers further from the camera than the product window darken very
        // slightly; layers in front brighten very slightly. Keep it subtle.
        const delta = z - camera.focusZ;
        return 1 + delta * depthCue;
      },
    }),
    [camera, projection.perspective, depthCue],
  );

  return (
    <SpatialCtx.Provider value={value}>
      <div
        style={{
          position: 'absolute',
          inset: 0,
          perspective: `${projection.perspective}px`,
          perspectiveOrigin: '50% 50%',
          transformStyle: 'preserve-3d',
          ...style,
        }}
      >
        <div
          style={{
            position: 'absolute',
            left: '50%',
            top: '50%',
            width: 0,
            height: 0,
            transformStyle: 'preserve-3d',
            transform: projection.worldTransform,
          }}
        >
          {children}
        </div>
      </div>
    </SpatialCtx.Provider>
  );
};

export { WORLD_UNIT };
