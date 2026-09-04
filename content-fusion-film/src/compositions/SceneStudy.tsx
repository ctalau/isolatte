import React from 'react';
import { AbsoluteFill } from 'remotion';
import { componentForScene } from '../film/registry';
import { sceneById } from '../film/contentFusionFilm';
import { DesignRoot } from '../components/spatial/DesignRoot';
import { Grade } from '../components/effects/Grade';
import { DebugOverlay } from '../components/debug/DebugOverlay';
import { theme } from '../theme/contentFusion';

/**
 * Single-scene preview.
 *
 * Every scene gets its own composition (`Scene_<id>`) so scene 5 can be
 * inspected without rendering the other 70 seconds. Same design root, same
 * grade, so what is seen here is what lands in the master.
 */
export const SceneStudy: React.FC<{ sceneId: string; debug: boolean }> = ({ sceneId, debug }) => {
  const scene = sceneById(sceneId);
  const Component = componentForScene(sceneId);
  return (
    <AbsoluteFill style={{ background: theme.colors.ink[0] }}>
      <DesignRoot>
        <Component durationInFrames={scene?.durationInFrames ?? 150} />
      </DesignRoot>
      <Grade vignette={0.7} />
      {debug ? <DebugOverlay /> : null}
    </AbsoluteFill>
  );
};
