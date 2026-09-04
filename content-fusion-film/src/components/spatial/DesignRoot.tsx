import React from 'react';
import { useVideoConfig } from 'remotion';
import { DESIGN_HEIGHT, DESIGN_WIDTH } from './SpatialContext';

/**
 * Everything in the film is authored in a fixed 1920×1080 design space and
 * scaled to the composition's real resolution.
 *
 * This is what makes a 4K master identical in layout to the 1080 preview, and
 * it means type sizes, spacing and world units only ever need one set of
 * numbers. Vertical formats do *not* use this — they recompose (see
 * docs/FORMATS.md).
 */
export const DesignRoot: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { width, height } = useVideoConfig();
  const scale = Math.min(width / DESIGN_WIDTH, height / DESIGN_HEIGHT);

  return (
    <div
      style={{
        position: 'absolute',
        left: '50%',
        top: '50%',
        width: DESIGN_WIDTH,
        height: DESIGN_HEIGHT,
        marginLeft: -DESIGN_WIDTH / 2,
        marginTop: -DESIGN_HEIGHT / 2,
        transform: `scale(${scale})`,
        transformOrigin: 'center center',
        overflow: 'hidden',
      }}
    >
      {children}
    </div>
  );
};
