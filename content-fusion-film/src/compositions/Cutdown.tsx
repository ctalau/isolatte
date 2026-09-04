import React from 'react';
import { AbsoluteFill, Sequence } from 'remotion';
import { cutdowns, cutdownStarts, resolveCutdown } from '../film/cutdowns';
import { componentForScene } from '../film/registry';
import { SceneShell } from '../components/transitions/SceneShell';
import { DesignRoot } from '../components/spatial/DesignRoot';
import { Grade } from '../components/effects/Grade';
import { theme } from '../theme/contentFusion';

/**
 * Renders any cutdown from its spec. One component serves every short-form
 * version, which is the whole point of keeping the film config-driven.
 */
export const Cutdown: React.FC<{ cutdownId: string }> = ({ cutdownId }) => {
  const spec = cutdowns.find((c) => c.id === cutdownId) ?? cutdowns[0]!;
  const list = resolveCutdown(spec);
  const starts = cutdownStarts(list);

  return (
    <AbsoluteFill style={{ background: theme.colors.ink[0] }}>
      {list.map((scene, i) => {
        const Component = componentForScene(scene.id);
        return (
          <Sequence
            key={scene.id}
            from={starts[i] ?? 0}
            durationInFrames={scene.durationInFrames}
            name={scene.title}
            layout="none"
          >
            <SceneShell scene={scene}>
              <DesignRoot>
                <Component durationInFrames={scene.durationInFrames} />
              </DesignRoot>
            </SceneShell>
          </Sequence>
        );
      })}
      <Grade vignette={0.7} />
    </AbsoluteFill>
  );
};
