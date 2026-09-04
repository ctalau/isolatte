# Formats

## Shipped

| Composition | Size | Notes |
|---|---|---|
| `ContentFusionMaster` | 3840×2160 | Delivery master |
| `ContentFusion1080` | 1920×1080 | Web master |
| `ContentFusion1080Subtitled` | 1920×1080 | Burned-in subtitles |
| `ContentFusionDebug` | 1920×1080 | HUD, safe areas, camera readout |
| `Cut-cut-30` / `Cut-cut-15` | 1920×1080 | Cutdowns |
| `Cut-feature-ai` / `Cut-feature-reuse` | 1920×1080 | Feature launch cuts |
| `Scene-*` | 1920×1080 | One per scene |

16:9 sizes share one layout. Everything is authored in a fixed 1920×1080 design
space (`DesignRoot`) and scaled, so the 4K master is layout-identical to the
1080 preview and type sizes only ever need one set of numbers.

## Vertical (1080×1350, 1080×1920) — deliberately not shipped yet

Scaling the 16:9 layout into a vertical frame is the single most reliable way to
make a premium film look cheap: the product window becomes a letterboxed strip,
the headline safe area collapses, and the camera's lateral moves stop reading.

Vertical must be **recomposed**, and the system is built for that:

* **Camera** — shots are keyframe data (`cameraShot`), so a vertical variant is a
  second set of keyframes with tighter framing and more vertical travel, not a
  new scene.
* **Layout** — `DesignRoot` is the only place the design space is defined. A
  vertical root with its own design size is a small addition.
* **Product** — the window is composed from independent layers
  (`Sidebar`, `DocumentCanvas`, `MetadataPanel`, `FloatingToolbar`). A vertical
  cut can drop the metadata panel and narrow the sidebar rather than shrinking
  the whole window.
* **Type** — `theme.typography.scale` is the single source for sizes and
  tracking; vertical needs larger relative sizes, which is one override object.
* **Story** — the vertical cut should use the `Cut-cut-15` scene selection, not
  all eleven scenes.

The work that remains is genuinely creative (re-framing eleven shots), not
architectural.

## Safe areas

`ContentFusionDebug` draws them:

* **Title safe** — the inner 90%. All headlines sit inside it (left margin 148px
  in design space).
* **Subtitle band** — bottom 7–18%, inset 12% each side. Scene headlines are
  placed above it so burned-in subtitles never collide with the film's own type.

Scene headlines use `SceneHeadline`, which owns placement and the optional
scrim, so the safe area is enforced in one component rather than per scene.
