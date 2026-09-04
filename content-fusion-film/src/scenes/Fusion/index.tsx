import React, { useMemo } from 'react';
import { useCurrentFrame } from 'remotion';
import { theme } from '../../theme/contentFusion';
import { Background } from '../../components/effects/Backgrounds';
import { SpatialUI } from '../../components/spatial/SpatialContext';
import { UIPlane } from '../../components/spatial/UIPlane';
import { ContentShard, buildShardField } from '../../components/spatial/ContentShard';
import { ContactShadow, Halo, RimLight } from '../../components/spatial/Stage';
import { LightSweep } from '../../components/spatial/Surfaces';
import { BrowserChrome, ProductWindow, WindowLayer } from '../../components/ui/ProductWindow';
import { DocumentCanvas, MetadataPanel, Sidebar } from '../../components/ui/EditorUI';
import { Headline } from '../../components/typography/Type';
import { editorDocument } from '../../assets/productContent';
import { cameraShot, evaluateShot } from '../../three/camera';
import { cameraPush, cinematicEase, objectMerge, softLanding } from '../../motion/easing';
import { hashed, mix, ramp } from '../../motion/interpolation';
import { headlines } from '../../film/narration';

export const FUSION_WINDOW_W = 1340;
export const FUSION_WINDOW_H = 790;

/**
 * SCENE 02 — FUSION
 *
 * Convergence, not a vortex. Every fragment travels along its own eased path to
 * a docking point on the window plane, arriving at a slightly different time.
 * The window does not fade in over the top of them — it becomes visible exactly
 * as they land, so the composition reads as assembly.
 */
export const Fusion: React.FC<{ durationInFrames: number }> = ({ durationInFrames }) => {
  const f = useCurrentFrame();
  const shards = useMemo(() => buildShardField(21), []);

  const shot = useMemo(
    () =>
      cameraShot({
        id: 'fusion',
        durationInFrames,
        keyframes: [
          {
            at: 0,
            position: [1.1, -0.16, 4.42],
            target: [0.36, -0.05, -0.4],
            fov: 36.2,
            focusZ: -0.45,
            aperture: 1.2,
          },
          {
            // Pull back to reveal the assembled object at a readable size.
            at: 0.55,
            position: [0.3, -0.04, 7.4],
            target: [0.08, -0.01, 0],
            fov: 32,
            focusZ: 0.02,
            aperture: 0.7,
            easing: cameraPush,
          },
          {
            at: 1,
            position: [0.04, 0.0, 9.1],
            target: [0.0, 0.0, 0],
            fov: 30,
            focusZ: 0.03,
            aperture: 0.35,
            easing: softLanding,
          },
        ],
        handheld: { amount: 0.012, seed: 4 },
      }),
    [durationInFrames],
  );

  const camera = evaluateShot(shot, f);

  const windowIn = ramp(f, 62, 112, softLanding);
  const headlineProgress = ramp(f, 10, 74, cinematicEase);
  const headlineOut = 1 - ramp(f, 88, 118, cinematicEase);
  const sweep = ramp(f, 96, 146, cinematicEase);

  return (
    <div style={{ position: 'absolute', inset: 0 }}>
      <Background name="spatialFog" />

      <SpatialUI camera={camera} depthCue={0.14}>
        {/* --- Fragments travelling to their docking points ----------------- */}
        {shards.map((shard, i) => {
          // Staggered convergence: order is seeded so it is stable, and spread
          // across ~40 frames so arrivals are felt as a sequence.
          const delay = 18 + hashed(31, i) * 38;
          const t = objectMerge(ramp(f, delay, delay + 46, cinematicEase));

          // Docking points sit on the window plane, spread across its area, so
          // fragments visibly become parts of the interface.
          const dockX = ((hashed(41, i) - 0.5) * FUSION_WINDOW_W * 0.78) / 235;
          const dockY = ((hashed(43, i) - 0.5) * FUSION_WINDOW_H * 0.72) / 235;

          const x = mix(shard.x, dockX, t);
          const y = mix(shard.y, dockY, t);
          const z = mix(shard.z, 0.02, t);
          const scale = mix(shard.scale, 0.22, t);
          // Fragments dissolve into the surface just before they arrive.
          const opacity = (1 - ramp(f, delay + 30, delay + 46, cinematicEase)) * (1 - windowIn * 0.35);

          return (
            <UIPlane
              key={shard.id}
              x={x}
              y={y}
              z={z}
              rotationY={shard.rotationY * (1 - t)}
              rotationX={shard.rotationX * (1 - t)}
              scale={scale}
              opacity={opacity}
            >
              <ContentShard shard={shard} dim={0.06} />
            </UIPlane>
          );
        })}

        {/* --- The product, assembling ------------------------------------- */}
        <UIPlane z={-0.5} width={FUSION_WINDOW_W} height={FUSION_WINDOW_H} alwaysSharp opacity={windowIn}>
          <Halo width={FUSION_WINDOW_W} height={FUSION_WINDOW_H} intensity={windowIn} />
        </UIPlane>
        <UIPlane z={-0.08} width={FUSION_WINDOW_W} height={FUSION_WINDOW_H} alwaysSharp opacity={windowIn}>
          <ContactShadow width={FUSION_WINDOW_W} height={FUSION_WINDOW_H} intensity={windowIn} />
        </UIPlane>

        <UIPlane
          z={0}
          width={FUSION_WINDOW_W}
          height={FUSION_WINDOW_H}
          alwaysSharp
          opacity={windowIn}
          scale={0.965 + 0.035 * windowIn}
        >
          <ProductWindow
            width={FUSION_WINDOW_W}
            height={FUSION_WINDOW_H}
            baseZ={0}
            chrome={<BrowserChrome breadcrumb={['Authentication', 'Configure single sign-on']} />}
          >
            <WindowLayer depth={0.022} opacity={ramp(f, 78, 116, cinematicEase)}>
              <Sidebar />
            </WindowLayer>
            <WindowLayer depth={0.05} opacity={ramp(f, 84, 124, cinematicEase)}>
              <DocumentCanvas blocks={editorDocument} />
            </WindowLayer>
            <WindowLayer depth={0.022} opacity={ramp(f, 90, 130, cinematicEase)}>
              <MetadataPanel />
            </WindowLayer>
            <WindowLayer depth={0.2}>
              <RimLight radius={theme.radii.window} intensity={windowIn} />
              <LightSweep progress={sweep} radius={theme.radii.window} intensity={1.1} />
            </WindowLayer>
          </ProductWindow>
        </UIPlane>
      </SpatialUI>

      <div
        style={{
          position: 'absolute',
          left: 148,
          top: '50%',
          transform: 'translateY(-50%)',
          opacity: headlineOut,
        }}
      >
        <Headline lines={[...headlines.fusion]} progress={headlineProgress} scale="display" />
      </div>
    </div>
  );
};
