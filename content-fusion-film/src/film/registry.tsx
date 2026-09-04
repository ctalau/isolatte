import React from 'react';
import { theme } from '../theme/contentFusion';
import { Fragmentation } from '../scenes/Fragmentation';
import { Fusion } from '../scenes/Fusion';
import { IntelligentCreation } from '../scenes/IntelligentCreation';
import { Structure } from '../scenes/Structure';
import { Reuse } from '../scenes/Reuse';
import { HumanControl } from '../scenes/HumanControl';
import { Adaptation } from '../scenes/Adaptation';
import { Localization } from '../scenes/Localization';
import { Publishing } from '../scenes/Publishing';
import { HeroSystem } from '../scenes/HeroSystem';
import { EndFrame } from '../scenes/EndFrame';

export type SceneComponent = React.FC<{ durationInFrames: number }>;

/** Rendered for any scene id that has no implementation yet. */
const NotImplemented: SceneComponent = () => (
  <div
    style={{
      position: 'absolute',
      inset: 0,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: theme.colors.ink[0],
      color: theme.colors.ink[8],
      fontFamily: theme.typography.mono,
      fontSize: 18,
      letterSpacing: '0.1em',
    }}
  >
    SCENE NOT IMPLEMENTED
  </div>
);

export const sceneComponents: Record<string, SceneComponent> = {
  fragmentation: Fragmentation,
  fusion: Fusion,
  'intelligent-creation': IntelligentCreation,
  structure: Structure,
  reuse: Reuse,
  'human-control': HumanControl,
  adaptation: Adaptation,
  localization: Localization,
  publishing: Publishing,
  'hero-system': HeroSystem,
  'end-frame': EndFrame,
};

export const componentForScene = (id: string): SceneComponent =>
  sceneComponents[id] ?? NotImplemented;
