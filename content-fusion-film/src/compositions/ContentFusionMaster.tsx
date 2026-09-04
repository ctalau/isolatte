import React from 'react';
import { AbsoluteFill, Sequence } from 'remotion';
import { scenes, sceneStarts } from '../film/contentFusionFilm';
import { componentForScene } from '../film/registry';
import { SceneShell } from '../components/transitions/SceneShell';
import { DesignRoot } from '../components/spatial/DesignRoot';
import { Grade } from '../components/effects/Grade';
import { Subtitles } from '../components/typography/Subtitles';
import { FilmAudio } from '../components/audio/FilmAudio';
import { DebugOverlay } from '../components/debug/DebugOverlay';
import { theme } from '../theme/contentFusion';

export type MasterProps = {
  subtitles: boolean;
  debug: boolean;
  voice: boolean;
  music: boolean;
  sfx: boolean;
  grain: number;
  vignette: number;
};

export const defaultMasterProps: MasterProps = {
  subtitles: false,
  debug: false,
  voice: true,
  music: false,
  sfx: false,
  grain: 1,
  vignette: 0.7,
};

/**
 * The film.
 *
 * Scenes are placed at overlapping offsets (see sceneStarts) so a transition is
 * a hand-off between two live scenes. The grade, subtitles and debug HUD sit
 * above every scene so they are never affected by a scene's own transform.
 */
export const ContentFusionMaster: React.FC<MasterProps> = ({
  subtitles,
  debug,
  voice,
  music,
  sfx,
  grain,
  vignette,
}) => (
  <AbsoluteFill style={{ background: theme.colors.ink[0] }}>
    {scenes.map((scene, i) => {
      const Component = componentForScene(scene.id);
      return (
        <Sequence
          key={scene.id}
          from={sceneStarts[i] ?? 0}
          durationInFrames={scene.durationInFrames}
          name={`${String(i + 1).padStart(2, '0')} ${scene.title}`}
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

    <Grade grain={grain} vignette={vignette} />
    <Subtitles enabled={subtitles} />
    {debug ? <DebugOverlay /> : null}
    <FilmAudio enableVoice={voice} enableMusic={music} enableSfx={sfx} />
  </AbsoluteFill>
);
