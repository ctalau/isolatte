import React, { useMemo } from 'react';
import { useCurrentFrame } from 'remotion';
import { theme } from '../../theme/contentFusion';
import { Background } from '../../components/effects/Backgrounds';
import { SpatialUI, DESIGN_HEIGHT, DESIGN_WIDTH } from '../../components/spatial/SpatialContext';
import { UIPlane } from '../../components/spatial/UIPlane';
import { GlowEdge } from '../../components/spatial/Surfaces';
import { ConnectionLine } from '../../components/effects/Graphics';
import { IconComponent } from '../../components/ui/Icons';
import { Headline } from '../../components/typography/Type';
import { cameraShot, evaluateShot, projectPoint } from '../../three/camera';
import { cinematicEase, softLanding, objectMerge } from '../../motion/easing';
import { envelope, mix, ramp } from '../../motion/interpolation';
import { headlines } from '../../film/narration';

const c = theme.colors;
const t = theme.typography;

/**
 * SCENE 05 — REUSE
 *
 * One component leaves its source topic and takes up residence inside three
 * other topics. Not copy/paste: the instances stay *linked*, which the second
 * half of the scene proves by editing the master and letting the change travel
 * back out along the same paths.
 */

const DOC_W = 268;
const DOC_H = 178;
const COMPONENT_W = 300;

/** Destination topics, in world units, at three different depths. */
const destinations = [
  { id: 'api', label: 'Manage API tokens', x: 2.05, y: 0.86, z: 0.22 },
  { id: 'rotate', label: 'Rotate credentials', x: 2.35, y: -0.12, z: -0.3 },
  { id: 'admin', label: 'Administration', x: 1.95, y: -1.08, z: 0.02 },
];

const MASTER = { x: -1.72, y: 0.0, z: 0.12 };

const DocCard: React.FC<{
  label: string;
  hasComponent: number;
  pulse: number;
}> = ({ label, hasComponent, pulse }) => (
  <div
    style={{
      width: DOC_W,
      height: DOC_H,
      borderRadius: theme.radii.md,
      background: `linear-gradient(158deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.012) 100%), rgba(17,21,29,0.94)`,
      border: `1px solid ${c.stroke.hairline}`,
      boxShadow: theme.shadows.card,
      padding: 16,
      position: 'relative',
      overflow: 'hidden',
    }}
  >
    <div
      style={{
        fontFamily: t.display,
        fontSize: 13.5,
        fontWeight: 555,
        letterSpacing: '-0.008em',
        color: c.ink[11],
        marginBottom: 12,
      }}
    >
      {label}
    </div>
    {[0.92, 0.7].map((w, i) => (
      <div
        key={i}
        style={{
          height: 5,
          width: `${w * 100}%`,
          borderRadius: 3,
          background: 'rgba(199,206,218,0.14)',
          marginBottom: 9,
        }}
      />
    ))}

    {/* The linked instance of the reusable component. */}
    <div
      style={{
        marginTop: 6,
        opacity: hasComponent,
        transform: `translateY(${((1 - hasComponent) * 8).toFixed(2)}px)`,
        padding: '9px 11px',
        borderRadius: theme.radii.sm,
        background: `rgba(127,209,192,${(0.05 + pulse * 0.1).toFixed(3)})`,
        border: `1px solid rgba(127,209,192,${(0.2 + pulse * 0.45).toFixed(3)})`,
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        boxShadow: pulse > 0 ? `0 0 ${(18 * pulse).toFixed(0)}px rgba(127,209,192,0.3)` : undefined,
      }}
    >
      <IconComponent size={12} color={c.structure.reusable} />
      <span style={{ fontFamily: t.body, fontSize: 11.5, color: c.ink[10] }}>
        Admin permission note
      </span>
    </div>
  </div>
);

export const Reuse: React.FC<{ durationInFrames: number }> = ({ durationInFrames }) => {
  const f = useCurrentFrame();

  const shot = useMemo(
    () =>
      cameraShot({
        id: 'reuse',
        durationInFrames,
        keyframes: [
          { at: 0, position: [-0.9, 0.05, 6.6], target: [-0.7, 0.0, 0], fov: 34, focusZ: 0.12, aperture: 0.6 },
          {
            // Follow the component out of its source topic.
            at: 0.42,
            position: [0.35, 0.02, 7.5],
            target: [0.3, 0.0, 0],
            fov: 33,
            focusZ: 0.05,
            aperture: 0.5,
            easing: cinematicEase,
          },
          {
            at: 1,
            position: [0.62, -0.02, 8.0],
            target: [0.42, 0.0, 0],
            fov: 32,
            focusZ: 0.0,
            aperture: 0.35,
            easing: softLanding,
          },
        ],
        handheld: { amount: 0.014, seed: 12 },
      }),
    [durationInFrames],
  );

  const camera = evaluateShot(shot, f);

  /* Phase 1: the component detaches and multiplies into the destinations. */
  const detach = ramp(f, 30, 74, cinematicEase);
  const travels = destinations.map((_, i) => ramp(f, 70 + i * 12, 132 + i * 12, objectMerge));
  const landed = destinations.map((_, i) => ramp(f, 118 + i * 12, 146 + i * 12, softLanding));

  /* Phase 2: the master changes, and the change propagates to every instance. */
  const editAt = durationInFrames - 96;
  const masterPulse = envelope(f, editAt, editAt + 40, 8, 26, cinematicEase);
  const instancePulses = destinations.map((_, i) =>
    envelope(f, editAt + 22 + i * 7, editAt + 62 + i * 7, 9, 26, cinematicEase),
  );
  const propagation = destinations.map((_, i) => ramp(f, editAt + 12 + i * 6, editAt + 44 + i * 6, cinematicEase));

  const linkOpacity = envelope(f, 88, durationInFrames - 8, 26, 22);
  const headlineProgress = ramp(f, 150, 208, cinematicEase);
  const headlineOut = 1 - ramp(f, durationInFrames - 34, durationInFrames - 8, cinematicEase);

  // Links are SVG in the flat design plane, but their endpoints are projected
  // through the same camera the 3D scene graph uses, so they stay attached to
  // the cards as the camera moves.
  const project = (x: number, y: number, z: number): [number, number] =>
    projectPoint(camera, [x, y, z], DESIGN_WIDTH, DESIGN_HEIGHT);

  return (
    <div style={{ position: 'absolute', inset: 0 }}>
      <Background name="midnight" />

      <svg
        width={DESIGN_WIDTH}
        height={DESIGN_HEIGHT}
        style={{ position: 'absolute', inset: 0, pointerEvents: 'none' }}
      >
        {destinations.map((d, i) => (
          <ConnectionLine
            key={d.id}
            from={project(MASTER.x + DOC_W / 2 / 235, MASTER.y, MASTER.z)}
            to={project(d.x - DOC_W / 2 / 235, d.y, d.z)}
            progress={travels[i] ?? 0}
            bow={i === 1 ? 0.05 : i === 0 ? -0.16 : 0.16}
            color="rgba(127,209,192,0.4)"
            width={1.2}
            opacity={linkOpacity}
          />
        ))}
        {/* Change propagation: a travelling segment along the same paths. */}
        {destinations.map((d, i) => {
          const p = propagation[i] ?? 0;
          if (p <= 0 || p >= 1) return null;
          return (
            <ConnectionLine
              key={`pulse-${d.id}`}
              from={project(MASTER.x + DOC_W / 2 / 235, MASTER.y, MASTER.z)}
              to={project(d.x - DOC_W / 2 / 235, d.y, d.z)}
              progress={p}
              bow={i === 1 ? 0.05 : i === 0 ? -0.16 : 0.16}
              color={c.structure.reusable}
              width={2.2}
              opacity={Math.sin(p * Math.PI) * 0.85}
            />
          );
        })}
      </svg>

      <SpatialUI camera={camera} depthCue={0.14}>
        {/* --- Source topic ------------------------------------------------- */}
        <UIPlane x={MASTER.x} y={MASTER.y} z={MASTER.z} width={DOC_W} height={DOC_H}>
          <div style={{ position: 'relative' }}>
            <DocCard label="Configure single sign-on" hasComponent={1 - detach * 0.75} pulse={masterPulse} />
            {masterPulse > 0.02 ? (
              <GlowEdge radius={theme.radii.md} intensity={masterPulse * 0.8} color={c.structure.reusable} />
            ) : null}
          </div>
        </UIPlane>

        <UIPlane x={MASTER.x} y={MASTER.y - 0.62} z={MASTER.z} opacity={0.85} origin="top-left">
          <span
            style={{
              fontFamily: t.mono,
              fontSize: 10.5,
              letterSpacing: '0.14em',
              textTransform: 'uppercase',
              color: c.ink[8],
              whiteSpace: 'nowrap',
              transform: 'translateX(-118px)',
              display: 'inline-block',
            }}
          >
            Source of truth
          </span>
        </UIPlane>

        {/* --- The component itself, in transit ----------------------------- */}
        {destinations.map((d, i) => {
          const travel = travels[i] ?? 0;
          if (travel <= 0.001 || travel >= 0.999) return null;
          return (
            <UIPlane
              key={`fly-${d.id}`}
              x={mix(MASTER.x + 0.2, d.x - 0.1, travel)}
              y={mix(MASTER.y - 0.18, d.y - 0.2, travel)}
              z={mix(MASTER.z + 0.5, d.z + 0.02, travel)}
              scale={mix(1, 0.72, travel)}
              opacity={Math.sin(Math.min(1, travel * 1.1) * Math.PI) * 1.1}
              width={COMPONENT_W}
            >
              <div
                style={{
                  width: COMPONENT_W,
                  padding: '11px 14px',
                  borderRadius: theme.radii.sm,
                  background: 'rgba(20,29,32,0.94)',
                  border: `1px solid rgba(127,209,192,0.42)`,
                  boxShadow: theme.shadows.panel,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 9,
                }}
              >
                <IconComponent size={13} color={c.structure.reusable} />
                <span style={{ fontFamily: t.body, fontSize: 12.5, color: c.ink[11] }}>
                  Admin permission note
                </span>
              </div>
            </UIPlane>
          );
        })}

        {/* --- Destination topics ------------------------------------------- */}
        {destinations.map((d, i) => (
          <UIPlane key={d.id} x={d.x} y={d.y} z={d.z} width={DOC_W} height={DOC_H} opacity={ramp(f, 14 + i * 6, 44 + i * 6, cinematicEase)}>
            <DocCard label={d.label} hasComponent={landed[i] ?? 0} pulse={instancePulses[i] ?? 0} />
          </UIPlane>
        ))}
      </SpatialUI>

      <div style={{ position: 'absolute', left: 148, bottom: 128, opacity: headlineOut }}>
        <Headline lines={[...headlines.reuse]} progress={headlineProgress} scale="display" />
      </div>
    </div>
  );
};
