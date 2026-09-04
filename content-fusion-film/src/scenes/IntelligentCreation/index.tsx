import React from 'react';
import { useCurrentFrame } from 'remotion';
import { theme } from '../../theme/contentFusion';
import { Background } from '../../components/effects/Backgrounds';
import { SpatialUI } from '../../components/spatial/SpatialContext';
import { UIPlane } from '../../components/spatial/UIPlane';
import { GlowEdge, LightSweep } from '../../components/spatial/Surfaces';
import { ContactShadow, Halo, RimLight } from '../../components/spatial/Stage';
import {
  BrowserChrome,
  ProductWindow,
  WindowLayer,
} from '../../components/ui/ProductWindow';
import {
  DocumentCanvas,
  FloatingToolbar,
  MetadataPanel,
  METADATA_WIDTH,
  Sidebar,
  SIDEBAR_WIDTH,
} from '../../components/ui/EditorUI';
import { AIPanel } from '../../components/ui/AIPanel';
import { ClickPulse, Cursor, cursorArc } from '../../components/ui/Cursor';
import { IconSparkle } from '../../components/ui/Icons';
import { aiSuggestionBlocks, editorDocument } from '../../assets/productContent';
import { cameraShot, evaluateShot } from '../../three/camera';
import { ramp, rampTo, envelope } from '../../motion/interpolation';
import {
  cameraPush,
  cinematicEase,
  fastReveal,
  objectMerge,
  softLanding,
} from '../../motion/easing';

/**
 * SCENE 03 — INTELLIGENT CREATION  (hero reference scene)
 *
 * This is the scene that establishes the film's visual language:
 *   · the product window as a physical object under studio light
 *   · interior layers separating in Z as the camera pushes in
 *   · an AI proposal detaching from the interface, resolving, then *merging*
 *     back into the document with a real reflow
 *   · focus (not cuts) carrying the viewer's attention between layers
 *
 * Everything is a pure function of the frame.
 */

/** Beat sheet reference length. The scene stretches its settle if the film gives it more. */
export const SCENE_03_DURATION = 258;

const WINDOW_W = 1340;
const WINDOW_H = 790;

/* -- Beat sheet (frames) --------------------------------------------------- */
const B = {
  toolbarIn: 10,
  aiActionHover: 26,
  aiActionClick: 40,
  panelIn: 48,
  panelResolveStart: 66,
  panelResolveEnd: 150,
  focusToPanel: 60,
  cursorToApply: 156,
  applyClick: 186,
  merge: 194,
  mergeEnd: 236,
} as const;

/**
 * Layout, in world units. The window is 1340 design px wide = 5.70 units, so it
 * spans x ∈ [-2.85, 2.85]. The AI proposal lives near its right edge and
 * overhangs it, which is what sells "this left the interface".
 */
const PANEL_HOME = { x: 2.3, y: 0.44, z: 0.44 } as const;
/** Where the proposal is absorbed: the document's insertion point. */
const PANEL_MERGE = { x: 0.1, y: -0.6, z: 0.03 } as const;

const heroShot = cameraShot({
  id: 'intelligent-creation',
  durationInFrames: SCENE_03_DURATION,
  keyframes: [
    // Framed wide and slightly off-axis. The lateral offset between camera and
    // target is what produces parallax between the window's interior layers —
    // a head-on camera would make the 2.5D stack read as a flat screenshot.
    { at: 0, position: [-0.2, 0.1, 9.85], target: [-0.05, 0.02, 0], fov: 30, focusZ: 0.03, aperture: 0.3 },
    {
      at: 0.19,
      position: [0.0, 0.05, 9.15],
      target: [0.0, 0.01, 0],
      fov: 29.4,
      focusZ: 0.05,
      aperture: 0.4,
      easing: cinematicEase,
    },
    {
      // Truck right and push toward the proposal; focus transfers to its plane.
      at: 0.52,
      position: [0.24, -0.04, 8.05],
      target: [0.16, 0.0, 0.14],
      fov: 28,
      focusZ: 0.44,
      aperture: 1.15,
      easing: cameraPush,
    },
    {
      at: 0.73,
      position: [0.3, -0.05, 7.9],
      target: [0.2, -0.01, 0.16],
      fov: 27.7,
      focusZ: 0.44,
      aperture: 1.15,
      easing: softLanding,
    },
    {
      // Settle back onto the document as the suggestion merges in.
      at: 1,
      position: [0.02, 0.02, 9.0],
      target: [0.0, 0.01, 0],
      fov: 29.4,
      focusZ: 0.05,
      aperture: 0.42,
      easing: cinematicEase,
    },
  ],
  handheld: { amount: 0.014, seed: 3 },
});

export const IntelligentCreation: React.FC<{ durationInFrames?: number }> = ({
  durationInFrames = SCENE_03_DURATION,
}) => {
  const f = useCurrentFrame();

  // The beat sheet is authored against SCENE_03_DURATION. When the film hands
  // the scene more time (narration is the master clock), the extra frames go
  // into the settle at the end rather than stretching every beat.
  const camera = evaluateShot({ ...heroShot, durationInFrames }, f);

  /* -- AI panel state ----------------------------------------------------- */
  const panelIn = ramp(f, B.panelIn, B.panelIn + 26, softLanding);
  const resolve = ramp(f, B.panelResolveStart, B.panelResolveEnd, cinematicEase);
  const approve = envelope(f, B.applyClick - 12, B.applyClick + 16, 12, 10, fastReveal);
  const mergeT = ramp(f, B.merge, B.mergeEnd, objectMerge);

  // The panel leaves by travelling back and down into the document, shrinking
  // and defocusing — it is absorbed, not dismissed.
  const panelOpacity = panelIn * (1 - ramp(f, B.merge + 14, B.mergeEnd - 6, cinematicEase));
  const panelZ = PANEL_HOME.z + (PANEL_MERGE.z - PANEL_HOME.z) * mergeT;
  const panelX = PANEL_HOME.x + (PANEL_MERGE.x - PANEL_HOME.x) * mergeT;
  const panelY =
    PANEL_HOME.y + (PANEL_MERGE.y - PANEL_HOME.y) * mergeT + (1 - panelIn) * -0.07;
  const panelScale = (0.955 + 0.045 * panelIn) * (1 - mergeT * 0.2);

  /* -- Document reflow ---------------------------------------------------- */
  // Existing blocks stay put; the accepted blocks grow in beneath them while
  // the canvas eases upward to keep the insertion point on screen.
  const accepted = aiSuggestionBlocks.map((_, i) =>
    ramp(f, B.merge + 10 + i * 7, B.merge + 40 + i * 7, softLanding),
  );
  const documentBlocks = [...editorDocument, ...aiSuggestionBlocks];
  const reveals = [
    ...editorDocument.map(() => 1),
    ...accepted,
  ];
  const scrollY = rampTo(f, [B.merge + 8, B.mergeEnd + 18], [0, 268], cinematicEase);
  // The inserted blocks keep an accent rule that fades as the scene settles.
  const insertHighlight = envelope(f, B.merge + 16, durationInFrames - 6, 14, 30, cinematicEase);
  const highlights = [
    ...editorDocument.map(() => 0),
    ...aiSuggestionBlocks.map(() => insertHighlight),
  ];

  /* -- Toolbar + cursor --------------------------------------------------- */
  const toolbarOpacity = ramp(f, B.toolbarIn, B.toolbarIn + 18, cinematicEase);
  const aiActionActive = f >= B.aiActionHover;
  const actionPulse = envelope(f, B.aiActionClick, B.aiActionClick + 24, 1, 22, cinematicEase);

  // Cursor travels, in world space, from the toolbar action to the proposal's
  // Apply button. World space (not window pixels) so it stays glued to the two
  // targets while the camera moves between them.
  const toolbarPoint = [-0.04, -1.42] as const;
  const applyPoint = [PANEL_HOME.x + 0.46, PANEL_HOME.y - 0.66] as const;
  const cursorT = ramp(f, B.cursorToApply, B.applyClick - 6, cinematicEase);
  const [cx, cy] = cursorArc(toolbarPoint, applyPoint, cursorT, 0.11);
  const cursorOpacity =
    ramp(f, B.aiActionClick - 22, B.aiActionClick - 8, cinematicEase) *
    (1 - ramp(f, B.applyClick + 10, B.applyClick + 26, cinematicEase));
  const applyPulse = envelope(f, B.applyClick, B.applyClick + 26, 1, 24, cinematicEase);

  /* -- Attenuate the window while the proposal is the subject -------------- */
  const attenuate = envelope(f, B.panelIn + 6, B.merge + 10, 24, 20, cinematicEase) * 0.13;

  const sweep = ramp(f, B.panelIn, B.panelIn + 46, cinematicEase);

  return (
    <div style={{ position: 'absolute', inset: 0, background: theme.colors.ink[0] }}>
      <Background name="productStage" />

      <SpatialUI camera={camera} depthCue={0.14}>
        {/* --- Studio light behind the product, so it has a silhouette ------ */}
        <UIPlane z={-0.5} width={WINDOW_W} height={WINDOW_H} alwaysSharp>
          <Halo width={WINDOW_W} height={WINDOW_H} intensity={1} />
        </UIPlane>
        <UIPlane z={-0.08} width={WINDOW_W} height={WINDOW_H} alwaysSharp>
          <ContactShadow width={WINDOW_W} height={WINDOW_H} />
        </UIPlane>

        {/* --- Product window ---------------------------------------------- */}
        <UIPlane z={0} width={WINDOW_W} height={WINDOW_H} alwaysSharp>
          <ProductWindow
            width={WINDOW_W}
            height={WINDOW_H}
            baseZ={0}
            attenuate={attenuate}
            chrome={
              <BrowserChrome breadcrumb={['Authentication', 'Configure single sign-on']} />
            }
          >
            <WindowLayer depth={0.022}>
              <Sidebar />
            </WindowLayer>

            <WindowLayer depth={0.05}>
              <DocumentCanvas
                blocks={documentBlocks}
                reveals={reveals}
                highlights={highlights}
                scrollY={scrollY}
              />
            </WindowLayer>

            <WindowLayer depth={0.022}>
              <MetadataPanel />
            </WindowLayer>

            {/* Edge shading: keeps the canvas from meeting the panels flat. */}
            <WindowLayer depth={0.04}>
              <div
                style={{
                  position: 'absolute',
                  left: SIDEBAR_WIDTH,
                  right: METADATA_WIDTH,
                  top: 0,
                  bottom: 0,
                  pointerEvents: 'none',
                  background:
                    'linear-gradient(90deg, rgba(0,0,0,0.30) 0%, rgba(0,0,0,0) 7%, rgba(0,0,0,0) 93%, rgba(0,0,0,0.30) 100%)',
                }}
              />
            </WindowLayer>

            {/* Content fades under the floating toolbar, as it would in the app. */}
            <WindowLayer depth={0.09}>
              <div
                style={{
                  position: 'absolute',
                  left: SIDEBAR_WIDTH,
                  right: METADATA_WIDTH,
                  bottom: 0,
                  height: 150,
                  pointerEvents: 'none',
                  background:
                    'linear-gradient(180deg, rgba(15,19,26,0) 0%, rgba(15,19,26,0.72) 52%, rgba(15,19,26,0.94) 100%)',
                }}
              />
            </WindowLayer>

            {/* Floating toolbar sits clearly above the canvas. */}
            <WindowLayer depth={0.16}>
              <div
                style={{
                  position: 'absolute',
                  left: SIDEBAR_WIDTH,
                  right: METADATA_WIDTH,
                  bottom: 34,
                  display: 'flex',
                  justifyContent: 'center',
                }}
              >
                <div style={{ position: 'relative' }}>
                  <FloatingToolbar
                    opacity={toolbarOpacity}
                    items={[
                      { label: 'Structure' },
                      { label: 'Reuse' },
                      {
                        label: 'Continue with AI',
                        icon: (
                          <IconSparkle
                            size={13}
                            color={aiActionActive ? theme.colors.accent : theme.colors.ink[10]}
                          />
                        ),
                        active: aiActionActive,
                      },
                      { label: 'Publish' },
                    ]}
                  />
                  {actionPulse > 0 ? (
                    <ClickPulse x={214} y={15} progress={1 - actionPulse} color={theme.colors.accent} />
                  ) : null}
                </div>
              </div>
            </WindowLayer>

            {/* Key-light edge, above every interior layer. */}
            <WindowLayer depth={0.2}>
              <RimLight radius={theme.radii.window} />
            </WindowLayer>
          </ProductWindow>
        </UIPlane>

        {/* --- AI proposal, floating in front of the interface -------------- */}
        <UIPlane
          x={panelX}
          y={panelY}
          z={panelZ}
          scale={panelScale}
          opacity={panelOpacity}
          rotationY={-4.2 + mergeT * 4.2}
          rotationX={1.4 - mergeT * 1.4}
          width={428}
        >
          <div style={{ position: 'relative', transform: `translateY(${((1 - panelIn) * 26).toFixed(2)}px)` }}>
            <AIPanel blocks={aiSuggestionBlocks} resolve={resolve} approve={approve} />
            <GlowEdge radius={theme.radii.lg} intensity={0.35 + approve * 0.5} />
            <LightSweep progress={sweep} radius={theme.radii.lg} intensity={0.9} />
          </div>
        </UIPlane>

        {/* --- Cursor lives just in front of everything it touches ---------- */}
        <UIPlane x={cx} y={cy} z={0.5} alwaysSharp opacity={cursorOpacity} origin="top-left">
          <Cursor x={0} y={0} />
          {applyPulse > 0 ? (
            <ClickPulse x={2} y={2} progress={1 - applyPulse} color={theme.colors.human} />
          ) : null}
        </UIPlane>
      </SpatialUI>

    </div>
  );
};
