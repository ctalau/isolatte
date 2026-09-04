# Post-processing

## The decision

The film's whole-frame grade is **CSS/compositing, not WebGL post-processing**.

`@react-three/postprocessing` was evaluated for the effects the brief lists —
subtle bloom, vignette, depth of field, tone mapping. Three things ruled it out
as the default path:

1. **It only covers the WebGL scenes.** Nine of eleven scenes are DOM/CSS 3D. A
   post chain on the `<ThreeCanvas>` would grade two scenes differently from the
   other nine, which is exactly the kind of inconsistency that makes a film look
   assembled rather than authored.
2. **Depth of field is the wrong tool here.** A real DoF pass makes UI text
   unreadable long before it becomes cinematic, and the brief is explicit that
   product clarity wins. The film instead uses a *rack-focus approximation*
   (`defocusBlur` in `src/three/camera.ts`) with a hard cap and a dead zone
   around the focal plane, applied per layer. Focus guides attention; it never
   destroys legibility.
3. **Render stability.** Effect composers introduce framebuffer state that has
   to be identical across parallel frame renders. The compositing path is a pure
   function of the frame by construction.

## What is actually applied

`src/components/effects/Grade.tsx`, over the whole frame, above every scene:

* **Vignette** — a radial darkening, default strength 0.7, reaching about 24% at
  82% radius. Deliberately below the threshold where a viewer would name it.
* **Grain** — a deterministic `feTurbulence` tile at 2.8% opacity in `overlay`
  blend, offset every second frame so it does not strobe at 30fps and does not
  visibly crawl. This is digital product cinema, not a vintage film-grain filter.

Bloom is **not** applied as a pass. Where a highlight needs to bloom, it is
authored into the element (`GlowEdge`, `LightSweep`, the halo in
`src/components/spatial/Stage.tsx`), which keeps it local and controllable.

## Tone mapping in the 3D scenes

The WebGL scenes do use ACES filmic tone mapping at exposure 0.94 — slightly
under 1 so highlights on UI surfaces never clip to white. This is set on the
renderer, not as a post pass, so it costs nothing and cannot destabilise.

## Motion blur

Investigated; implemented as **explicit transition blur** rather than
multi-frame sampling:

* Multi-frame accumulation multiplies 4K render time by the sample count for an
  effect that is invisible at the film's deliberately slow camera speeds.
* `SceneShell` applies directional-ish blur during `depthPass` and `expand`
  transitions, where objects genuinely cross the lens fast.
* `RevealLine` resolves type from blur to sharp during its entrance.
* Stationary UI is always crisp — `alwaysSharp` on a `UIPlane` opts a layer out
  of camera defocus entirely, and the product window uses it.

If a future shot needs true motion blur, the place to add it is a Remotion
frame-sampling wrapper around a single scene, not a global setting.
