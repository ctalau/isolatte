import React from 'react';
import { Composition, Still } from 'remotion';
import './fonts';
import {
  ContentFusionMaster,
  defaultMasterProps,
  type MasterProps,
} from './compositions/ContentFusionMaster';
import { SceneStudy } from './compositions/SceneStudy';
import { Cutdown } from './compositions/Cutdown';
import { cutdowns, cutdownDuration, resolveCutdown } from './film/cutdowns';
import { scenes, totalDurationInFrames } from './film/contentFusionFilm';
import { FPS } from './motion/timing';

/**
 * Composition registry.
 *
 *   ContentFusionMaster   3840×2160 delivery master
 *   ContentFusion1080     1920×1080 web master
 *   Scene_<id>            one per scene, for isolated preview and QA stills
 *
 * Vertical formats are intentionally absent: they must be recomposed rather
 * than letterboxed. See docs/FORMATS.md.
 */
export const RemotionRoot: React.FC = () => (
  <>
    <Composition
      id="ContentFusionMaster"
      component={ContentFusionMaster}
      durationInFrames={totalDurationInFrames}
      fps={FPS}
      width={3840}
      height={2160}
      defaultProps={defaultMasterProps}
    />

    <Composition
      id="ContentFusion1080"
      component={ContentFusionMaster}
      durationInFrames={totalDurationInFrames}
      fps={FPS}
      width={1920}
      height={1080}
      defaultProps={defaultMasterProps}
    />

    <Composition
      id="ContentFusion1080Subtitled"
      component={ContentFusionMaster}
      durationInFrames={totalDurationInFrames}
      fps={FPS}
      width={1920}
      height={1080}
      defaultProps={{ ...defaultMasterProps, subtitles: true } satisfies MasterProps}
    />

    <Composition
      id="ContentFusionDebug"
      component={ContentFusionMaster}
      durationInFrames={totalDurationInFrames}
      fps={FPS}
      width={1920}
      height={1080}
      defaultProps={{ ...defaultMasterProps, debug: true, subtitles: true } satisfies MasterProps}
    />

    {cutdowns.map((cut) => (
      <Composition
        key={cut.id}
        id={`Cut-${cut.id}`}
        component={Cutdown}
        durationInFrames={cutdownDuration(resolveCutdown(cut))}
        fps={FPS}
        width={1920}
        height={1080}
        defaultProps={{ cutdownId: cut.id }}
      />
    ))}

    {scenes.map((scene) => (
      <Composition
        key={scene.id}
        id={`Scene-${scene.id}`}
        component={SceneStudy}
        durationInFrames={scene.durationInFrames}
        fps={FPS}
        width={1920}
        height={1080}
        defaultProps={{ sceneId: scene.id, debug: false }}
      />
    ))}

    <Still
      id="StyleFrame"
      component={SceneStudy}
      width={3840}
      height={2160}
      defaultProps={{ sceneId: 'intelligent-creation', debug: false }}
    />
  </>
);
