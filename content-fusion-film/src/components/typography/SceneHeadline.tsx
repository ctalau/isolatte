import React from 'react';
import { Headline } from './Type';

/**
 * Scene headline block.
 *
 * Placement and the optional scrim live here rather than in each scene, so the
 * film's type always sits in the same safe area and never fights the product
 * behind it. `scrim` is only for scenes where the composition genuinely fills
 * the frame — a scrim over empty space is a smudge.
 */
export const SceneHeadline: React.FC<{
  lines: string[];
  progress: number;
  opacity?: number;
  scale?: 'display' | 'headline' | 'title';
  position?: 'bottom-left' | 'center-left';
  scrim?: 'none' | 'bottom' | 'left';
}> = ({
  lines,
  progress,
  opacity = 1,
  scale = 'display',
  position = 'bottom-left',
  scrim = 'none',
}) => (
  <>
    {scrim === 'bottom' ? (
      <div
        style={{
          position: 'absolute',
          left: 0,
          right: 0,
          bottom: 0,
          height: 420,
          pointerEvents: 'none',
          opacity: opacity * Math.min(1, progress * 2),
          background:
            'linear-gradient(180deg, rgba(6,7,10,0) 0%, rgba(6,7,10,0.62) 52%, rgba(6,7,10,0.9) 100%)',
        }}
      />
    ) : null}
    {scrim === 'left' ? (
      <div
        style={{
          position: 'absolute',
          left: 0,
          top: 0,
          bottom: 0,
          width: 1100,
          pointerEvents: 'none',
          opacity: opacity * Math.min(1, progress * 2),
          background:
            'linear-gradient(90deg, rgba(6,7,10,0.9) 0%, rgba(6,7,10,0.74) 45%, rgba(6,7,10,0) 100%)',
        }}
      />
    ) : null}
    <div
      style={
        position === 'bottom-left'
          ? { position: 'absolute', left: 148, bottom: 118, opacity }
          : { position: 'absolute', left: 148, top: '50%', transform: 'translateY(-50%)', opacity }
      }
    >
      <Headline lines={lines} progress={progress} scale={scale} />
    </div>
  </>
);
