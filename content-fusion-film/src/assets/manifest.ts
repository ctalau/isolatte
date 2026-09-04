/**
 * Asset manifest.
 *
 * Every product asset the film needs, with an explicit status. Nothing in this
 * repository claims to be a capture of the real Content Fusion application:
 * where the real thing is unavailable, the film uses a *reconstructed* UI built
 * from React components, which is labelled as such below.
 *
 * `npm run manifest` validates this file and prints what still needs replacing.
 */

export type AssetStatus = 'placeholder' | 'reconstructed' | 'captured' | 'delivered';

export type AssetEntry = {
  id: string;
  kind: 'screen' | 'logo' | 'icon' | 'avatar' | 'content' | 'brand' | 'audio' | 'font';
  status: AssetStatus;
  /** Where the asset lives, or where a real one should be placed. */
  path?: string;
  /** Precisely what a real replacement must be. */
  expectedAsset?: string;
  /** Which scenes consume it. */
  usedBy: string[];
  notes?: string;
};

export const assetManifest: AssetEntry[] = [
  {
    id: 'editor-main',
    kind: 'screen',
    status: 'reconstructed',
    expectedAsset:
      'Real Content Fusion editor captured at 2560×1440, logged in, with a topic open, sidebar expanded and the metadata panel visible.',
    usedBy: ['fusion', 'intelligent-creation', 'human-control'],
    notes:
      'Currently built as React components (src/components/ui/EditorUI.tsx). This is Mode 3 "reconstructed UI" — chosen because these scenes animate the interface, which a flat screenshot cannot do. Replace the *content*, not the mechanism, once real product data is available.',
  },
  {
    id: 'editor-ai-panel',
    kind: 'screen',
    status: 'reconstructed',
    expectedAsset:
      'Real AI suggestion panel with the actual copy, affordances and state names used in the product.',
    usedBy: ['intelligent-creation'],
    notes: 'Labels ("Suggested continuation", "Apply", "Draft") are invented for the film and must be confirmed against the product before delivery.',
  },
  {
    id: 'editor-review-panel',
    kind: 'screen',
    status: 'reconstructed',
    expectedAsset: 'Real review/approval panel showing an actual diff.',
    usedBy: ['human-control'],
  },
  {
    id: 'mark',
    kind: 'logo',
    status: 'placeholder',
    path: 'src/components/ui/ProductWindow.tsx (Mark)',
    expectedAsset: 'Official Content Fusion logotype and mark as SVG, plus clear-space rules.',
    usedBy: ['fusion', 'intelligent-creation', 'human-control', 'end-frame'],
    notes: 'PLACEHOLDER MARK — a geometric stand-in, not the real brand mark.',
  },
  {
    id: 'brand-tokens',
    kind: 'brand',
    status: 'placeholder',
    path: 'src/theme/contentFusion.ts',
    expectedAsset: 'Official brand colour, type and spacing tokens.',
    usedBy: ['*'],
    notes:
      'The palette is an art-directed stand-in. Replacing it is a single-file change by design.',
  },
  {
    id: 'sample-content',
    kind: 'content',
    status: 'placeholder',
    path: 'src/assets/productContent.ts',
    expectedAsset: 'Approved sample topic, metadata, taxonomy and localized strings.',
    usedBy: ['*'],
    notes:
      'Written for the film. Structurally representative of technical content; not a customer document.',
  },
  {
    id: 'inter',
    kind: 'font',
    status: 'delivered',
    path: 'node_modules/@fontsource-variable/inter',
    usedBy: ['*'],
    notes: 'Bundled locally so renders never depend on the network.',
  },
  {
    id: 'jetbrains-mono',
    kind: 'font',
    status: 'delivered',
    path: 'node_modules/@fontsource/jetbrains-mono',
    usedBy: ['*'],
  },
  {
    id: 'narration',
    kind: 'audio',
    status: 'delivered',
    path: 'public/audio/voice/',
    usedBy: ['*'],
    notes:
      'Generated locally with Kokoro (npm run voice). The voice ID is a first pass and is expected to change; regenerating re-times the film automatically.',
  },
  {
    id: 'music-bed',
    kind: 'audio',
    status: 'placeholder',
    path: 'public/audio/music/bed.wav',
    expectedAsset:
      'Commissioned score: sophisticated electronic, minimal pulse, restrained, resolving at the end frame. Not library music.',
    usedBy: ['*'],
    notes: 'Not present. Music is disabled by default so renders succeed without it.',
  },
  {
    id: 'sfx-pack',
    kind: 'audio',
    status: 'placeholder',
    path: 'public/audio/sfx/',
    expectedAsset: 'Designed SFX per src/audio/manifest.ts (nine cues).',
    usedBy: ['*'],
    notes: 'Not present. SFX are disabled by default.',
  },
];

export const placeholders = () =>
  assetManifest.filter((a) => a.status === 'placeholder' || a.status === 'reconstructed');
