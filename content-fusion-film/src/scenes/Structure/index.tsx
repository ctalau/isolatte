import React, { useMemo } from 'react';
import { useCurrentFrame } from 'remotion';
import { theme } from '../../theme/contentFusion';
import { Background } from '../../components/effects/Backgrounds';
import { SpatialUI } from '../../components/spatial/SpatialContext';
import { UIPlane } from '../../components/spatial/UIPlane';
import { ContactShadow, Halo } from '../../components/spatial/Stage';
import { Headline } from '../../components/typography/Type';
import { cameraShot, evaluateShot } from '../../three/camera';
import { cinematicEase, softLanding, objectMerge } from '../../motion/easing';
import { envelope, mix, ramp } from '../../motion/interpolation';
import { headlines } from '../../film/narration';

const c = theme.colors;
const t = theme.typography;

/**
 * SCENE 04 — STRUCTURE
 *
 * The topic separates into the layers of its content model, each labelled, then
 * locks back together. This is the film's clearest "product truth" statement:
 * the intelligence in later scenes exists because this model exists.
 *
 * The layers below are a schematic of the document shown in scenes 02–03 — the
 * same title, the same reusable note — so the viewer reads it as the *same*
 * object seen from the side, not as a new diagram.
 */

type StratumSpec = {
  id: string;
  label: string;
  color: string;
  /** Explode depth, in world units. */
  depth: number;
  height: number;
  content: React.ReactNode;
};

const PLATE_W = 660;

const plateStyle = (color: string): React.CSSProperties => ({
  position: 'relative',
  width: PLATE_W,
  borderRadius: theme.radii.md,
  background: `linear-gradient(158deg, rgba(255,255,255,0.055) 0%, rgba(255,255,255,0.014) 100%), rgba(25,31,41,0.95)`,
  border: `1px solid ${color}55`,
  boxShadow: theme.shadows.card,
  padding: '16px 22px',
  display: 'flex',
  flexDirection: 'column',
  justifyContent: 'center',
});

const rule = (w: number, opacity = 0.16) => (
  <div
    style={{
      height: 5,
      width: `${w}%`,
      borderRadius: 3,
      background: `rgba(199,206,218,${opacity})`,
    }}
  />
);

export const Structure: React.FC<{ durationInFrames: number }> = ({ durationInFrames }) => {
  const f = useCurrentFrame();

  const strata = useMemo<StratumSpec[]>(
    () => [
      {
        id: 'title',
        label: 'Title',
        color: c.structure.title,
        depth: 0.55,
        height: 74,
        content: (
          <span
            style={{
              fontFamily: t.display,
              fontSize: 27,
              fontWeight: 570,
              letterSpacing: '-0.02em',
              color: c.text.primary,
            }}
          >
            Configure single sign-on
          </span>
        ),
      },
      {
        id: 'metadata',
        label: 'Metadata',
        color: c.structure.metadata,
        depth: 0.28,
        height: 62,
        content: (
          <div style={{ display: 'flex', gap: 8 }}>
            {['Task', 'Administrator', 'Platform', '4.2'].map((v) => (
              <span
                key={v}
                style={{
                  fontFamily: t.mono,
                  fontSize: 11,
                  letterSpacing: '0.06em',
                  color: c.ink[10],
                  padding: '5px 10px',
                  borderRadius: 5,
                  background: 'rgba(255,255,255,0.05)',
                  border: `1px solid ${c.stroke.hairline}`,
                }}
              >
                {v}
              </span>
            ))}
          </div>
        ),
      },
      {
        id: 'block',
        label: 'Content block',
        color: c.structure.block,
        depth: 0,
        height: 116,
        content: (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
            {rule(94, 0.2)}
            {rule(78, 0.16)}
            {rule(86, 0.16)}
            {rule(44, 0.12)}
          </div>
        ),
      },
      {
        id: 'reusable',
        label: 'Reusable component',
        color: c.structure.reusable,
        depth: -0.28,
        height: 84,
        content: (
          <div>
            <div
              style={{
                fontFamily: t.mono,
                fontSize: 9.5,
                letterSpacing: '0.13em',
                textTransform: 'uppercase',
                color: c.structure.reusable,
                marginBottom: 8,
              }}
            >
              Admin permission note
            </div>
            {rule(72, 0.16)}
          </div>
        ),
      },
      {
        id: 'taxonomy',
        label: 'Taxonomy relationship',
        color: c.structure.taxonomy,
        depth: -0.55,
        height: 70,
        content: (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {['Authentication', 'Security', 'Administration'].map((v, i) => (
              <React.Fragment key={v}>
                {i > 0 ? (
                  <span style={{ width: 22, height: 1, background: `${c.structure.taxonomy}66` }} />
                ) : null}
                <span
                  style={{
                    fontFamily: t.body,
                    fontSize: 12,
                    color: c.ink[10],
                    padding: '5px 11px',
                    borderRadius: theme.radii.pill,
                    border: `1px solid ${c.structure.taxonomy}44`,
                  }}
                >
                  {v}
                </span>
              </React.Fragment>
            ))}
          </div>
        ),
      },
    ],
    [],
  );

  const shot = useMemo(
    () =>
      cameraShot({
        id: 'structure',
        durationInFrames,
        keyframes: [
          // The stack sits right of centre for the whole shot so the headline
          // owns the left third without a scrim.
          { at: 0, position: [-0.52, 0.0, 8.4], target: [-0.5, 0, 0], fov: 30, focusZ: 0.05, aperture: 0.24 },
          {
            // Pull back and orbit a few degrees so the separation reads as depth.
            at: 0.5,
            position: [-1.06, 0.26, 8.0],
            target: [-1.12, 0.02, 0],
            fov: 31,
            focusZ: 0.02,
            aperture: 0.28,
            easing: cinematicEase,
          },
          {
            at: 1,
            position: [-0.62, 0.04, 8.5],
            target: [-0.6, 0.0, 0],
            fov: 30,
            focusZ: 0.05,
            aperture: 0.22,
            easing: softLanding,
          },
        ],
        handheld: { amount: 0.014, seed: 6 },
      }),
    [durationInFrames],
  );

  const camera = evaluateShot(shot, f);

  const explode = ramp(f, 22, 84, cinematicEase);
  const relock = ramp(f, durationInFrames - 66, durationInFrames - 12, objectMerge);
  const separation = explode * (1 - relock);

  const headlineProgress = ramp(f, 96, 156, cinematicEase);
  const headlineOut = 1 - ramp(f, durationInFrames - 40, durationInFrames - 10, cinematicEase);

  // Stacked layout: plates share one column and fan apart vertically as well as
  // in depth, so the model is legible without the camera having to fly.
  const gap = 14;
  const totalH = strata.reduce((a, s) => a + s.height + gap, -gap);

  return (
    <div style={{ position: 'absolute', inset: 0 }}>
      <Background name="productStage" />

      <SpatialUI camera={camera} depthCue={0.16}>
        <UIPlane z={-0.7} width={PLATE_W} height={totalH} alwaysSharp>
          <Halo width={PLATE_W} height={totalH} intensity={0.8} />
        </UIPlane>
        <UIPlane z={-0.4} width={PLATE_W} height={totalH} alwaysSharp opacity={1 - separation * 0.5}>
          <ContactShadow width={PLATE_W} height={totalH} intensity={0.7} />
        </UIPlane>

        {strata.map((s, i) => {
          const stackY = (totalH / 2 - (strata.slice(0, i).reduce((a, x) => a + x.height + gap, 0) + s.height / 2)) / 235;
          // Exploding adds vertical spread on top of the stack offset, so the
          // plates never collide when they come toward the camera.
          // Depth alone does not separate a stack of near-identical plates —
          // the vertical fan is what makes each stratum individually readable.
          // Sign matches stackY (index 0 is the top plate, i.e. positive Y), so
          // the fan adds to the stack instead of cancelling it out.
          const spreadY = ((strata.length - 1) / 2 - i) * 0.30 * separation;
          const appear = ramp(f, 2 + i * 3, 22 + i * 3, cinematicEase);

          return (
            <React.Fragment key={s.id}>
              <UIPlane
                x={0}
                y={stackY + spreadY}
                z={mix(0, s.depth, separation)}
                rotationX={separation * 1.6}
                width={PLATE_W}
                height={s.height}
                opacity={appear}
              >
                <div style={{ ...plateStyle(s.color), height: s.height }}>{s.content}</div>
              </UIPlane>

              {/* Guide + label, revealed only while the model is exploded. */}
              <UIPlane
                x={PLATE_W / 2 / 235 + 0.26}
                y={stackY + spreadY}
                z={mix(0, s.depth, separation)}
                opacity={envelope(f, 40 + i * 5, durationInFrames - 40, 16, 18)}
                origin="top-left"
                alwaysSharp
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, transform: 'translateY(-7px)' }}>
                  <div style={{ width: 62, height: 1, background: s.color, opacity: 0.55 }} />
                  <span
                    style={{
                      fontFamily: t.mono,
                      fontSize: 13,
                      fontWeight: 500,
                      letterSpacing: '0.13em',
                      textTransform: 'uppercase',
                      color: s.color,
                      // Small tracked-out mono needs help against a dark stage.
                      textShadow: '0 1px 6px rgba(0,0,0,0.7)',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {s.label}
                  </span>
                </div>
              </UIPlane>
            </React.Fragment>
          );
        })}
      </SpatialUI>

      <div style={{ position: 'absolute', left: 148, bottom: 132, opacity: headlineOut }}>
        <Headline lines={[...headlines.structure]} progress={headlineProgress} scale="headline" />
      </div>
    </div>
  );
};
