import React from 'react';
import { useCurrentFrame } from 'remotion';
import { theme } from '../../theme/contentFusion';
import { driftNoise } from '../../motion/interpolation';

export type BackgroundName = 'midnight' | 'cloud' | 'gradientField' | 'spatialFog' | 'productStage';

/**
 * Ambient environments.
 *
 * All of them move, but only just: the drift amplitudes below are chosen so a
 * viewer never sees the movement, only feels that the frame is alive.
 */
export const Background: React.FC<{ name: BackgroundName; intensity?: number }> = ({
  name,
  intensity = 1,
}) => {
  const frame = useCurrentFrame();
  const t = frame / 30;

  // Two slow, incommensurate drifts so the field never visibly loops.
  const dx = driftNoise(11, t * 0.09) * 2.4 * intensity;
  const dy = driftNoise(29, t * 0.07) * 1.8 * intensity;

  if (name === 'cloud') {
    return (
      <div style={{ position: 'absolute', inset: 0, background: theme.gradients.cloudField }}>
        <div
          style={{
            position: 'absolute',
            inset: '-12%',
            background:
              'radial-gradient(48% 40% at 30% 22%, rgba(91,140,255,0.10) 0%, rgba(91,140,255,0) 68%)',
            transform: `translate3d(${dx}%, ${dy}%, 0)`,
          }}
        />
      </div>
    );
  }

  if (name === 'productStage') {
    return (
      <div style={{ position: 'absolute', inset: 0, background: theme.colors.ink[0] }}>
        {/* Key light: a soft overhead pool the product sits inside. */}
        <div
          style={{
            position: 'absolute',
            inset: '-20%',
            background:
              'radial-gradient(46% 44% at 50% 18%, rgba(150,180,255,0.10) 0%, rgba(120,150,220,0.028) 42%, rgba(0,0,0,0) 72%)',
            transform: `translate3d(${dx * 0.4}%, ${dy * 0.4}%, 0)`,
          }}
        />
        {/* Cool rim from below-left keeps the silhouette from dying into black. */}
        <div
          style={{
            position: 'absolute',
            inset: '-20%',
            background:
              'radial-gradient(40% 34% at 14% 88%, rgba(91,140,255,0.075) 0%, rgba(91,140,255,0) 66%)',
            transform: `translate3d(${-dx * 0.5}%, ${-dy * 0.5}%, 0)`,
          }}
        />
      </div>
    );
  }

  if (name === 'spatialFog') {
    return (
      <div style={{ position: 'absolute', inset: 0, background: theme.colors.ink[0] }}>
        <div
          style={{
            position: 'absolute',
            inset: '-25%',
            background:
              'radial-gradient(60% 52% at 62% 34%, rgba(70,96,150,0.16) 0%, rgba(30,42,66,0.05) 45%, rgba(0,0,0,0) 74%)',
            filter: 'blur(20px)',
            transform: `translate3d(${dx * 1.6}%, ${dy * 1.6}%, 0)`,
          }}
        />
        <div
          style={{
            position: 'absolute',
            inset: '-25%',
            background:
              'radial-gradient(44% 40% at 24% 74%, rgba(91,140,255,0.10) 0%, rgba(91,140,255,0) 70%)',
            filter: 'blur(28px)',
            transform: `translate3d(${-dx * 1.2}%, ${dy * 0.9}%, 0)`,
          }}
        />
      </div>
    );
  }

  if (name === 'gradientField') {
    return (
      <div style={{ position: 'absolute', inset: 0, background: theme.gradients.midnightField }}>
        <div
          style={{
            position: 'absolute',
            inset: '-18%',
            background: theme.gradients.stage,
            transform: `translate3d(${dx}%, ${dy}%, 0)`,
          }}
        />
      </div>
    );
  }

  return (
    <div style={{ position: 'absolute', inset: 0, background: theme.gradients.midnightField }}>
      <div
        style={{
          position: 'absolute',
          inset: '-15%',
          background:
            'radial-gradient(52% 42% at 50% 14%, rgba(96,124,190,0.10) 0%, rgba(96,124,190,0) 70%)',
          transform: `translate3d(${dx * 0.8}%, ${dy * 0.8}%, 0)`,
        }}
      />
    </div>
  );
};
