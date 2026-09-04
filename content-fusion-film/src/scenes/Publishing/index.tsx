import React, { useMemo } from 'react';
import { useCurrentFrame } from 'remotion';
import { Background } from '../../components/effects/Backgrounds';
import { Headline } from '../../components/typography/Type';
import { ThreeStage } from '../../three/ThreeStage';
import { RoutingRibbon, SpatialCard } from '../../three/SpatialCard';
import { cameraShot, evaluateShot } from '../../three/camera';
import { cameraPull, cinematicEase, softLanding } from '../../motion/easing';
import { ramp } from '../../motion/interpolation';
import { channels } from '../../assets/productContent';
import { headlines } from '../../film/narration';
import { theme } from '../../theme/contentFusion';

/**
 * SCENE 09 — PUBLISHING  (true 3D)
 *
 * The camera pulls back far enough that the product stops being an interface
 * and becomes the centre of a system. Content leaves along curved routes to six
 * destinations. This is one of only three scenes rendered in WebGL, because the
 * shot needs real perspective across a wide depth range — something CSS 3D
 * cannot hold together at this scale.
 */

/**
 * Destination tiles, placed explicitly rather than on a ring.
 *
 * A ring puts two tiles directly behind the product where the camera cannot see
 * them. Two columns flanking the source keep all six legible at once, and the
 * inward-facing rotation makes the arrangement read as a system rather than a
 * grid of thumbnails.
 */
const TILE_LAYOUT: Array<{ position: [number, number, number]; rotationY: number }> = [
  { position: [-3.62, 1.5, -0.95], rotationY: 0.3 },
  { position: [-3.95, -0.05, -0.2], rotationY: 0.34 },
  { position: [-3.42, -1.6, -1.05], rotationY: 0.28 },
  { position: [3.62, 1.5, -0.95], rotationY: -0.3 },
  { position: [3.95, -0.05, -0.2], rotationY: -0.34 },
  { position: [3.42, -1.6, -1.05], rotationY: -0.28 },
];

const destinations = channels.map((ch, i) => ({
  ...ch,
  ...TILE_LAYOUT[i % TILE_LAYOUT.length]!,
}));

export const Publishing: React.FC<{ durationInFrames: number }> = ({ durationInFrames }) => {
  const f = useCurrentFrame();

  const shot = useMemo(
    () =>
      cameraShot({
        id: 'publishing',
        durationInFrames,
        keyframes: [
          { at: 0, position: [0, 0.05, 3.9], target: [0, 0, 0], fov: 33, focusZ: 0, aperture: 0 },
          {
            at: 0.58,
            position: [0.2, 0.5, 7.3],
            target: [0.05, 0.02, -0.5],
            fov: 40,
            easing: cameraPull,
          },
          {
            at: 1,
            position: [0.55, 0.72, 8.1],
            target: [0.06, 0.0, -0.6],
            fov: 41,
            easing: softLanding,
          },
        ],
        handheld: { amount: 0.02, seed: 27 },
      }),
    [durationInFrames],
  );

  const camera = evaluateShot(shot, f);

  const productIn = ramp(f, 0, 26, cinematicEase);
  const tilesIn = destinations.map((_, i) => ramp(f, 62 + i * 8, 104 + i * 8, softLanding));
  const routes = destinations.map((_, i) => ramp(f, 84 + i * 9, 150 + i * 9, cinematicEase));

  const headlineProgress = ramp(f, 150, 208, cinematicEase);
  const headlineOut = 1 - ramp(f, durationInFrames - 30, durationInFrames - 6, cinematicEase);

  return (
    <div style={{ position: 'absolute', inset: 0 }}>
      <Background name="spatialFog" />

      <ThreeStage camera={camera}>
        {/* The product, as an object in the system. */}
        <SpatialCard
          spec={{
            key: 'publishing-product',
            width: 720,
            height: 452,
            title: 'Configure single sign-on',
            subtitle: 'Content Fusion · structured source',
            accent: theme.colors.accent,
            rules: 5,
          }}
          size={[3.36, 2.11]}
          position={[0, 0, 0]}
          opacity={productIn}
        />

        {destinations.map((d, i) => (
          <React.Fragment key={d.id}>
            <RoutingRibbon
              from={[d.position[0] > 0 ? 1.6 : -1.6, d.position[1] > 0 ? 0.6 : -0.6, 0.04]}
              // Land on the tile's inner edge, not its centre, so the route
              // never crosses the card's own content.
              to={[d.position[0] + (d.position[0] > 0 ? -0.72 : 0.72), d.position[1], d.position[2] + 0.05]}
              progress={routes[i] ?? 0}
              color={theme.colors.accent}
              radius={0.016}
              bow={0.5}
              opacity={0.62 * (routes[i] ?? 0)}
            />
            <SpatialCard
              spec={{
                key: `channel-${d.id}`,
                width: 396,
                height: 248,
                title: d.label,
                accent: theme.colors.accent,
                rules: 3,
                kind: 'channel',
              }}
              size={[1.58, 0.99]}
              position={d.position}
              rotation={[0, d.rotationY, 0]}
              opacity={tilesIn[i] ?? 0}
              scale={0.94 + 0.06 * (tilesIn[i] ?? 0)}
            />
          </React.Fragment>
        ))}
      </ThreeStage>

      <div style={{ position: 'absolute', left: 148, bottom: 118, opacity: headlineOut }}>
        <Headline lines={[...headlines.publishing]} progress={headlineProgress} scale="display" />
      </div>
    </div>
  );
};
