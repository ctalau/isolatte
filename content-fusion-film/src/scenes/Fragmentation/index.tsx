import React, { useMemo } from 'react';
import { useCurrentFrame } from 'remotion';
import { Background } from '../../components/effects/Backgrounds';
import { ParticleField } from '../../components/effects/Graphics';
import { SpatialUI, DESIGN_HEIGHT, DESIGN_WIDTH } from '../../components/spatial/SpatialContext';
import { UIPlane } from '../../components/spatial/UIPlane';
import { ContentShard, buildShardField } from '../../components/spatial/ContentShard';
import { Headline } from '../../components/typography/Type';
import { cameraShot, evaluateShot } from '../../three/camera';
import { cinematicEase, softLanding } from '../../motion/easing';
import { ramp } from '../../motion/interpolation';
import { headlines } from '../../film/narration';

/**
 * SCENE 01 — FRAGMENTATION
 *
 * A slow lateral drift through real content fragments held at three depth
 * bands. The near band crosses the lens out of focus, which is what gives the
 * shot its sense of volume; the far band supplies parallax.
 *
 * As the line resolves, the drift decelerates and every fragment rotates toward
 * a common facing — the field stops being scattered before anything moves.
 */
export const Fragmentation: React.FC<{ durationInFrames: number }> = ({ durationInFrames }) => {
  const f = useCurrentFrame();
  const shards = useMemo(() => buildShardField(21), []);

  const shot = useMemo(
    () =>
      cameraShot({
        id: 'fragmentation',
        durationInFrames,
        keyframes: [
          {
            at: 0,
            position: [-1.5, 0.34, 5.0],
            target: [-0.62, 0.1, -0.4],
            fov: 39,
            focusZ: -0.4,
            aperture: 0.62,
          },
          {
            at: 0.62,
            position: [0.5, -0.05, 4.6],
            target: [0.16, -0.02, -0.4],
            fov: 37,
            focusZ: -0.4,
            aperture: 0.6,
            easing: cinematicEase,
          },
          {
            // Deceleration: the field settles before the next scene pulls it in.
            at: 1,
            position: [0.95, -0.14, 4.5],
            target: [0.36, -0.05, -0.4],
            fov: 36.2,
            focusZ: -0.4,
            aperture: 0.5,
            easing: softLanding,
          },
        ],
        handheld: { amount: 0.02, seed: 9 },
      }),
    [durationInFrames],
  );

  const camera = evaluateShot(shot, f);

  // Fragments arrive in a staggered wash rather than all at once.
  const fieldIn = ramp(f, 0, 34, cinematicEase);
  // Late in the scene every shard rotates toward a shared facing.
  const align = ramp(f, durationInFrames - 62, durationInFrames - 6, softLanding);

  const headlineProgress = ramp(f, 40, 108, cinematicEase);
  const headlineOut = 1 - ramp(f, durationInFrames - 34, durationInFrames - 6, cinematicEase);

  return (
    <div style={{ position: 'absolute', inset: 0 }}>
      <Background name="spatialFog" />
      <ParticleField
        width={DESIGN_WIDTH}
        height={DESIGN_HEIGHT}
        frame={f}
        seed={3}
        count={26}
        opacity={0.5 * fieldIn}
      />

      <SpatialUI camera={camera} depthCue={0.16}>
        {shards.map((shard, i) => {
          const appear = ramp(f, i * 1.6, 24 + i * 1.6, cinematicEase);
          // Each shard drifts on its own slow cycle; amplitude falls to zero as
          // the field aligns, so the deceleration is felt, not just seen.
          const drift = (1 - align) * 0.06;
          const dx = Math.sin(f * 0.0072 + i * 1.7) * drift;
          const dy = Math.cos(f * 0.0059 + i * 2.3) * drift * 0.7;
          return (
            <UIPlane
              key={shard.id}
              x={shard.x + dx}
              y={shard.y + dy}
              z={shard.z}
              rotationY={shard.rotationY * (1 - align)}
              rotationX={shard.rotationX * (1 - align)}
              scale={shard.scale * (0.94 + 0.06 * appear)}
              opacity={appear * fieldIn}
            >
              <ContentShard shard={shard} dim={0.06} />
            </UIPlane>
          );
        })}
      </SpatialUI>

      {/* Local scrim: the type must own its area even as fragments drift past. */}
      <div
        style={{
          position: 'absolute',
          left: 0,
          top: 0,
          bottom: 0,
          width: 1160,
          pointerEvents: 'none',
          opacity: headlineOut * headlineProgress,
          background:
            'linear-gradient(90deg, rgba(7,10,16,0.9) 0%, rgba(7,10,16,0.78) 46%, rgba(7,10,16,0) 100%)',
        }}
      />
      <div
        style={{
          position: 'absolute',
          left: 148,
          top: '50%',
          transform: 'translateY(-50%)',
          opacity: headlineOut,
        }}
      >
        <Headline lines={[...headlines.fragmentation]} progress={headlineProgress} scale="display" />
      </div>

      {/* Depth haze in front of the far band — atmosphere, not fog. */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          pointerEvents: 'none',
          background:
            'radial-gradient(78% 62% at 50% 50%, rgba(10,14,22,0) 38%, rgba(8,11,18,0.5) 100%)',
        }}
      />
    </div>
  );
};
