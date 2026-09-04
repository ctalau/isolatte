import React, { useMemo } from 'react';
import { useCurrentFrame } from 'remotion';
import { theme } from '../../theme/contentFusion';
import { Background } from '../../components/effects/Backgrounds';
import { SpatialUI } from '../../components/spatial/SpatialContext';
import { UIPlane } from '../../components/spatial/UIPlane';
import { GlowEdge } from '../../components/spatial/Surfaces';
import { Headline } from '../../components/typography/Type';
import { audienceProfiles } from '../../assets/productContent';
import { cameraShot, evaluateShot } from '../../three/camera';
import { cinematicEase, softLanding } from '../../motion/easing';
import { ramp } from '../../motion/interpolation';
import { headlines } from '../../film/narration';

const c = theme.colors;
const t = theme.typography;

const CARD_W = 340;
const CARD_H = 258;

/**
 * SCENE 07 — ADAPTATION
 *
 * The same structured source, rendered for four audiences. The cards are
 * arranged as a shallow fan through depth and the camera trucks laterally past
 * them, so each variant becomes the subject in turn without a single cut.
 *
 * The differences between the variants are real editorial differences —
 * register, depth, what gets led with — not colour swaps.
 */

const variants = [
  {
    ...audienceProfiles[0]!,
    heading: 'SAML metadata endpoint',
    body: 'POST the IdP metadata document to /auth/saml/metadata. Group claims are mapped to workspace roles at first sign-in.',
    mono: true,
  },
  {
    ...audienceProfiles[1]!,
    heading: 'Sign in with your company account',
    body: 'Once your administrator connects your identity provider, you sign in the same way you sign in to everything else.',
    mono: false,
  },
  {
    ...audienceProfiles[2]!,
    heading: 'Member cannot complete sign-in',
    body: 'Symptom: the provider page loads but the workspace does not. Cause: group mapping is missing. Resolution: map the group to a role.',
    mono: false,
  },
  {
    ...audienceProfiles[3]!,
    heading: 'Set up single sign-on',
    body: 'In this lesson you will connect a provider, map one group, and verify the result. Checkpoint: a test member signs in successfully.',
    mono: false,
  },
];

/** Fan positions: shallow arc through depth, centred on the source. */
const layout = variants.map((_, i) => {
  const n = variants.length;
  const spread = (i - (n - 1) / 2) / ((n - 1) / 2); // -1 .. 1
  return {
    x: spread * 2.55,
    y: -Math.abs(spread) * 0.1,
    z: 0.32 - Math.abs(spread) * 0.6,
    rotationY: -spread * 9,
  };
});

export const Adaptation: React.FC<{ durationInFrames: number }> = ({ durationInFrames }) => {
  const f = useCurrentFrame();

  const shot = useMemo(
    () =>
      cameraShot({
        id: 'adaptation',
        durationInFrames,
        keyframes: [
          { at: 0, position: [-2.4, 0.1, 6.2], target: [-1.9, 0.02, 0], fov: 33, focusZ: -0.1, aperture: 0.85 },
          {
            at: 0.55,
            position: [0.35, 0.02, 6.5],
            target: [0.2, 0.0, 0],
            fov: 33,
            focusZ: 0.05,
            aperture: 0.8,
            easing: cinematicEase,
          },
          {
            at: 1,
            position: [1.9, -0.04, 7.1],
            target: [1.35, 0.0, 0],
            fov: 32.5,
            focusZ: -0.05,
            aperture: 0.7,
            easing: softLanding,
          },
        ],
        handheld: { amount: 0.014, seed: 18 },
      }),
    [durationInFrames],
  );

  const camera = evaluateShot(shot, f);

  const sourceIn = ramp(f, 4, 34, cinematicEase);
  const fan = ramp(f, 24, 96, cinematicEase);
  const headlineProgress = ramp(f, 92, 146, cinematicEase);
  const headlineOut = 1 - ramp(f, durationInFrames - 28, durationInFrames - 6, cinematicEase);

  return (
    <div style={{ position: 'absolute', inset: 0 }}>
      <Background name="midnight" />

      <SpatialUI camera={camera} depthCue={0.15}>
        {/* Source, behind the fan: everything downstream comes from here. */}
        <UIPlane x={0} y={0.62} z={-1.5} opacity={sourceIn * (1 - fan * 0.42)} width={420}>
          <div
            style={{
              width: 420,
              padding: '18px 22px',
              borderRadius: theme.radii.md,
              background: 'rgba(15,19,26,0.9)',
              border: `1px solid ${c.stroke.soft}`,
              boxShadow: theme.shadows.card,
            }}
          >
            <div
              style={{
                fontFamily: t.mono,
                fontSize: 10,
                letterSpacing: '0.14em',
                textTransform: 'uppercase',
                color: c.ink[8],
                marginBottom: 10,
              }}
            >
              Structured source
            </div>
            <div
              style={{
                fontFamily: t.display,
                fontSize: 19,
                fontWeight: 555,
                letterSpacing: '-0.014em',
                color: c.ink[11],
              }}
            >
              Configure single sign-on
            </div>
          </div>
        </UIPlane>

        {variants.map((v, i) => {
          const pos = layout[i]!;
          const appear = ramp(f, 20 + i * 9, 58 + i * 9, cinematicEase);
          // The camera passes each card; the one nearest the lens axis lifts.
          const focusProximity = Math.max(0, 1 - Math.abs(camera.target[0] - pos.x) / 1.5);
          return (
            <UIPlane
              key={v.id}
              x={pos.x * fan}
              y={pos.y * fan}
              z={pos.z * fan}
              rotationY={pos.rotationY * fan}
              scale={0.94 + 0.06 * appear + focusProximity * 0.045}
              opacity={appear}
              width={CARD_W}
              height={CARD_H}
            >
              <div style={{ position: 'relative' }}>
                <div
                  style={{
                    width: CARD_W,
                    height: CARD_H,
                    padding: '20px 22px',
                    borderRadius: theme.radii.lg,
                    background: `linear-gradient(158deg, rgba(255,255,255,0.055) 0%, rgba(255,255,255,0.012) 100%), rgba(18,22,30,0.95)`,
                    border: `1px solid ${c.stroke.hairline}`,
                    boxShadow: theme.shadows.card,
                    display: 'flex',
                    flexDirection: 'column',
                  }}
                >
                  <div
                    style={{
                      fontFamily: t.mono,
                      fontSize: 10,
                      letterSpacing: '0.14em',
                      textTransform: 'uppercase',
                      color: c.accent,
                      marginBottom: 16,
                    }}
                  >
                    {v.label}
                  </div>
                  <div
                    style={{
                      fontFamily: v.mono ? t.mono : t.display,
                      fontSize: v.mono ? 15 : 17,
                      fontWeight: v.mono ? 500 : 555,
                      letterSpacing: v.mono ? '-0.002em' : '-0.014em',
                      lineHeight: 1.28,
                      color: c.text.primary,
                      marginBottom: 14,
                    }}
                  >
                    {v.heading}
                  </div>
                  <div
                    style={{
                      fontFamily: t.body,
                      fontSize: 13,
                      lineHeight: 1.6,
                      color: c.ink[10],
                      flex: 1,
                    }}
                  >
                    {v.body}
                  </div>
                  <div
                    style={{
                      fontFamily: t.body,
                      fontSize: 11.5,
                      color: c.ink[8],
                      paddingTop: 14,
                      borderTop: `1px solid ${c.stroke.hairline}`,
                    }}
                  >
                    {v.detail}
                  </div>
                </div>
                {focusProximity > 0.7 ? (
                  <GlowEdge radius={theme.radii.lg} intensity={(focusProximity - 0.7) * 1.4} />
                ) : null}
              </div>
            </UIPlane>
          );
        })}
      </SpatialUI>

      <div style={{ position: 'absolute', left: 148, bottom: 116, opacity: headlineOut }}>
        <Headline lines={[...headlines.adaptation]} progress={headlineProgress} scale="display" />
      </div>
    </div>
  );
};
