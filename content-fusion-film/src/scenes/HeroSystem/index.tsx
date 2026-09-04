import React, { useMemo } from 'react';
import { useCurrentFrame } from 'remotion';
import { Background } from '../../components/effects/Backgrounds';
import { Headline } from '../../components/typography/Type';
import { ThreeStage } from '../../three/ThreeStage';
import { RoutingRibbon, SpatialCard } from '../../three/SpatialCard';
import { cameraShot, evaluateShot } from '../../three/camera';
import { cinematicEase, softLanding } from '../../motion/easing';
import { ramp } from '../../motion/interpolation';
import { channels } from '../../assets/productContent';
import { headlines } from '../../film/narration';
import { theme } from '../../theme/contentFusion';

/**
 * SCENE 10 — HERO SYSTEM  (true 3D)
 *
 * The whole picture, in one composition:
 *   · structured source behind the product (where the content actually lives)
 *   · the product at the centre, with AI operating inside it
 *   · destinations extending outward
 *
 * The camera cranes up and orbits by about twelve degrees. That is the largest
 * camera move in the film, and it is slow on purpose — the shot has to feel
 * like an architectural reveal, not a fly-through.
 */

/**
 * Structured source sits *behind and above* the product. Directly behind it
 * would be hidden by the product card at every camera angle in this crane.
 */
const SOURCE_STACK: Array<[number, number, number]> = [
  [-1.95, 2.62, -3.3],
  [0.05, 2.95, -3.8],
  [2.05, 2.62, -3.3],
];

/**
 * Destinations flank the product in two columns, lifted so the lower-left of
 * the frame stays clear for the headline.
 */
const DESTINATIONS: Array<{ position: [number, number, number]; rotationY: number }> = [
  { position: [-3.86, 1.92, 0.3], rotationY: 0.34 },
  { position: [-4.08, 0.48, 0.95], rotationY: 0.38 },
  { position: [-3.62, -0.98, 0.3], rotationY: 0.32 },
  { position: [3.86, 1.92, 0.3], rotationY: -0.34 },
  { position: [4.08, 0.48, 0.95], rotationY: -0.38 },
  { position: [3.62, -0.98, 0.3], rotationY: -0.32 },
];

export const HeroSystem: React.FC<{ durationInFrames: number }> = ({ durationInFrames }) => {
  const f = useCurrentFrame();

  const shot = useMemo(
    () =>
      cameraShot({
        id: 'hero-system',
        durationInFrames,
        keyframes: [
          {
            at: 0,
            position: [-2.4, -1.35, 8.2],
            target: [0, -0.1, -0.8],
            fov: 40,
            focusZ: 0,
            aperture: 0,
          },
          {
            at: 0.55,
            position: [-0.6, 0.35, 8.9],
            target: [0, 0.02, -0.9],
            fov: 39,
            easing: cinematicEase,
          },
          {
            // The crane tops out high and slightly right; the whole system is
            // legible for the last two seconds and the frame then settles.
            at: 1,
            position: [1.35, 1.55, 9.4],
            target: [0.05, 0.08, -1.0],
            fov: 38,
            easing: softLanding,
          },
        ],
        handheld: { amount: 0.018, seed: 33 },
      }),
    [durationInFrames],
  );

  const camera = evaluateShot(shot, f);

  const productIn = ramp(f, 0, 24, cinematicEase);
  const sourceIn = SOURCE_STACK.map((_, i) => ramp(f, 26 + i * 9, 66 + i * 9, softLanding));
  const destIn = DESTINATIONS.map((_, i) => ramp(f, 58 + i * 7, 100 + i * 7, softLanding));
  const routes = DESTINATIONS.map((_, i) => ramp(f, 80 + i * 8, 148 + i * 8, cinematicEase));
  const feeds = SOURCE_STACK.map((_, i) => ramp(f, 52 + i * 8, 116 + i * 8, cinematicEase));

  const headlineProgress = ramp(f, 150, 214, cinematicEase);
  const headlineOut = 1 - ramp(f, durationInFrames - 30, durationInFrames - 6, cinematicEase);

  return (
    <div style={{ position: 'absolute', inset: 0 }}>
      <Background name="spatialFog" />

      <ThreeStage camera={camera}>
        {/* --- Structured source, behind the product ---------------------- */}
        {SOURCE_STACK.map((pos, i) => (
          <React.Fragment key={`src-${i}`}>
            <SpatialCard
              spec={{
                key: `hero-source-${i}`,
                width: 320,
                height: 200,
                title: ['Topics', 'Components', 'Taxonomy'][i]!,
                accent: [
                  theme.colors.structure.block,
                  theme.colors.structure.reusable,
                  theme.colors.structure.taxonomy,
                ][i]!,
                rules: 3,
              }}
              size={[1.28, 0.8]}
              position={pos}
              rotation={[0, i === 0 ? 0.2 : i === 2 ? -0.2 : 0, 0]}
              opacity={(sourceIn[i] ?? 0) * 0.92}
            />
            {/* Source feeds the product: routes point inward. */}
            <RoutingRibbon
              from={pos}
              to={[pos[0] * 0.3, 1.0, -0.06]}
              progress={feeds[i] ?? 0}
              color={theme.colors.structure.reusable}
              radius={0.012}
              bow={0.3}
              opacity={0.4 * (feeds[i] ?? 0)}
            />
          </React.Fragment>
        ))}

        {/* --- The product, at the centre of the system -------------------- */}
        <SpatialCard
          spec={{
            key: 'hero-product',
            width: 760,
            height: 476,
            title: 'Content Fusion',
            subtitle: 'Structured content · AI · human review',
            accent: theme.colors.accent,
            rules: 5,
          }}
          size={[3.42, 2.14]}
          position={[0, 0, 0]}
          opacity={productIn}
        />

        {/* AI operating inside the product: a small panel in front of it. */}
        <SpatialCard
          spec={{
            key: 'hero-ai',
            width: 300,
            height: 150,
            title: 'Suggested continuation',
            accent: theme.colors.accent,
            rules: 2,
          }}
          size={[1.2, 0.6]}
          position={[0.98, -0.62, 0.55]}
          rotation={[0, -0.1, 0]}
          opacity={ramp(f, 34, 74, softLanding) * 0.97}
        />

        {/* --- Destinations ------------------------------------------------ */}
        {DESTINATIONS.map((d, i) => (
          <React.Fragment key={`dest-${i}`}>
            <RoutingRibbon
              from={[d.position[0] > 0 ? 1.64 : -1.64, d.position[1] * 0.42, 0.05]}
              to={[
                d.position[0] + (d.position[0] > 0 ? -0.68 : 0.68),
                d.position[1],
                d.position[2] + 0.05,
              ]}
              progress={routes[i] ?? 0}
              color={theme.colors.accent}
              radius={0.014}
              bow={0.5}
              opacity={0.55 * (routes[i] ?? 0)}
            />
            <SpatialCard
              spec={{
                key: `hero-dest-${i}`,
                width: 372,
                height: 232,
                title: channels[i]?.label ?? 'Channel',
                accent: theme.colors.accent,
                rules: 3,
              }}
              size={[1.49, 0.93]}
              position={d.position}
              rotation={[0, d.rotationY, 0]}
              opacity={destIn[i] ?? 0}
              scale={0.94 + 0.06 * (destIn[i] ?? 0)}
            />
          </React.Fragment>
        ))}
      </ThreeStage>

      <div style={{ position: 'absolute', left: 148, bottom: 112, opacity: headlineOut }}>
        <Headline lines={[...headlines.heroSystem]} progress={headlineProgress} scale="headline" />
      </div>
    </div>
  );
};
