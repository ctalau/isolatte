import React, { useMemo } from 'react';
import { useCurrentFrame } from 'remotion';
import { theme } from '../../theme/contentFusion';
import { Background } from '../../components/effects/Backgrounds';
import { SpatialUI } from '../../components/spatial/SpatialContext';
import { UIPlane } from '../../components/spatial/UIPlane';
import { ContactShadow, Halo, RimLight } from '../../components/spatial/Stage';
import { BrowserChrome, ProductWindow, WindowLayer } from '../../components/ui/ProductWindow';
import { DocumentCanvas, MetadataPanel, Sidebar } from '../../components/ui/EditorUI';
import { ReviewPanel } from '../../components/ui/AIPanel';
import { ClickPulse, Cursor, cursorArc } from '../../components/ui/Cursor';
import { SceneHeadline } from '../../components/typography/SceneHeadline';
import { editorDocument } from '../../assets/productContent';
import { cameraShot, evaluateShot } from '../../three/camera';
import { cinematicEase, fastReveal, softLanding } from '../../motion/easing';
import { envelope, ramp } from '../../motion/interpolation';
import { headlines } from '../../film/narration';

const WINDOW_W = 1340;
const WINDOW_H = 790;
const PANEL = { x: 0.0, y: 0.05, z: 0.5 } as const;

/**
 * SCENE 06 — HUMAN CONTROL
 *
 * The quietest scene in the film, on purpose. One panel, one decision, one
 * cursor. The camera barely moves; the only accent colour is the warm one,
 * which appears nowhere else — so approval reads as a human act rather than a
 * system state.
 */
export const HumanControl: React.FC<{ durationInFrames: number }> = ({ durationInFrames }) => {
  const f = useCurrentFrame();

  const shot = useMemo(
    () =>
      cameraShot({
        id: 'human-control',
        durationInFrames,
        keyframes: [
          { at: 0, position: [0.0, 0.0, 8.1], target: [0, 0, 0.1], fov: 30, focusZ: 0.5, aperture: 1.0 },
          {
            at: 1,
            // A single, almost imperceptible push. Trust is stillness.
            position: [0.06, -0.01, 7.35],
            target: [0.03, 0.0, 0.12],
            fov: 29.2,
            focusZ: 0.5,
            aperture: 1.15,
            easing: softLanding,
          },
        ],
        handheld: { amount: 0.01, seed: 15 },
      }),
    [durationInFrames],
  );

  const camera = evaluateShot(shot, f);

  const panelIn = ramp(f, 12, 44, softLanding);
  const cursorStart = Math.round(durationInFrames * 0.42);
  const clickAt = cursorStart + 34;
  const approve = envelope(f, clickAt - 12, clickAt + 14, 12, 10, fastReveal);
  const approved = ramp(f, clickAt, clickAt + 10, fastReveal);

  const from = [-0.95, -0.42] as const;
  const to = [PANEL.x + 0.75, PANEL.y - 0.44] as const;
  const cursorT = ramp(f, cursorStart, clickAt - 5, cinematicEase);
  const [cx, cy] = cursorArc(from, to, cursorT, 0.1);
  const cursorOpacity =
    ramp(f, cursorStart - 16, cursorStart - 2, cinematicEase) *
    (1 - ramp(f, clickAt + 18, clickAt + 38, cinematicEase));
  const clickPulse = envelope(f, clickAt, clickAt + 26, 1, 24, cinematicEase);

  const headlineProgress = ramp(f, clickAt + 8, clickAt + 62, cinematicEase);
  const headlineOut = 1 - ramp(f, durationInFrames - 26, durationInFrames - 6, cinematicEase);

  // The product recedes behind the decision, then comes back once it is made.
  const attenuate = 0.24 * panelIn * (1 - approved * 0.55);

  return (
    <div style={{ position: 'absolute', inset: 0 }}>
      <Background name="productStage" />

      <SpatialUI camera={camera} depthCue={0.14}>
        <UIPlane z={-0.5} width={WINDOW_W} height={WINDOW_H} alwaysSharp>
          <Halo width={WINDOW_W} height={WINDOW_H} intensity={0.9} />
        </UIPlane>
        <UIPlane z={-0.08} width={WINDOW_W} height={WINDOW_H} alwaysSharp>
          <ContactShadow width={WINDOW_W} height={WINDOW_H} />
        </UIPlane>

        <UIPlane z={0} width={WINDOW_W} height={WINDOW_H} alwaysSharp>
          <ProductWindow
            width={WINDOW_W}
            height={WINDOW_H}
            baseZ={0}
            attenuate={attenuate}
            chrome={<BrowserChrome breadcrumb={['Authentication', 'Configure single sign-on']} />}
          >
            <WindowLayer depth={0.022}>
              <Sidebar />
            </WindowLayer>
            <WindowLayer depth={0.05}>
              <DocumentCanvas blocks={editorDocument} />
            </WindowLayer>
            <WindowLayer depth={0.022}>
              <MetadataPanel highlight={approved} />
            </WindowLayer>
            <WindowLayer depth={0.2}>
              <RimLight radius={theme.radii.window} />
            </WindowLayer>
          </ProductWindow>
        </UIPlane>

        <UIPlane
          x={PANEL.x}
          y={PANEL.y}
          z={PANEL.z}
          opacity={panelIn}
          scale={0.96 + 0.04 * panelIn}
          width={452}
        >
          <div style={{ transform: `translateY(${((1 - panelIn) * 22).toFixed(2)}px)` }}>
            <ReviewPanel
              removed="You need administrator permissions to change authentication settings."
              added="You need administrator permissions on the workspace to change authentication settings."
              approve={approve}
              approved={approved}
            />
          </div>
        </UIPlane>

        <UIPlane x={cx} y={cy} z={0.56} alwaysSharp opacity={cursorOpacity} origin="top-left">
          <Cursor x={0} y={0} />
          {clickPulse > 0 ? (
            <ClickPulse x={2} y={2} progress={1 - clickPulse} color={theme.colors.human} />
          ) : null}
        </UIPlane>
      </SpatialUI>

      {/* The window fills the frame in this scene, so the type needs a scrim. */}
      <SceneHeadline
        lines={[...headlines.humanControl]}
        progress={headlineProgress}
        opacity={headlineOut}
        scale="headline"
        scrim="bottom"
      />
    </div>
  );
};
