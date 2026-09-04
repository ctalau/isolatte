/**
 * Capture definitions.
 *
 * These describe the product states the film wants as real screenshots. Until
 * a reachable Content Fusion instance exists, `npm run capture` reports what it
 * would capture and exits without writing anything — it never invents an image.
 *
 * Set CONTENT_FUSION_BASE_URL (and CONTENT_FUSION_STORAGE_STATE for an
 * authenticated session) to enable real capture.
 */
export const baseUrl = process.env.CONTENT_FUSION_BASE_URL ?? null;

/** @typedef {{id: string, url: string, viewport: {width: number, height: number}, waitFor?: string, description: string, layers?: string[]}} CaptureDefinition */

/** @type {CaptureDefinition[]} */
export const captures = [
  {
    id: 'editor-main',
    url: '/editor/topics/configure-single-sign-on',
    viewport: { width: 2560, height: 1440 },
    waitFor: '[data-testid="editor-canvas"]',
    description: 'Editor with a topic open, sidebar expanded, metadata panel visible.',
    // Regions to capture separately for the layered-screenshot representation.
    layers: ['sidebar', 'canvas', 'metadata', 'toolbar'],
  },
  {
    id: 'editor-ai-suggestion',
    url: '/editor/topics/configure-single-sign-on?panel=ai',
    viewport: { width: 2560, height: 1440 },
    waitFor: '[data-testid="ai-panel"]',
    description: 'AI suggestion panel open with a generated proposal visible.',
    layers: ['ai-panel'],
  },
  {
    id: 'editor-review',
    url: '/editor/topics/configure-single-sign-on?panel=review',
    viewport: { width: 2560, height: 1440 },
    waitFor: '[data-testid="review-panel"]',
    description: 'Review panel showing a pending change with approve/dismiss.',
    layers: ['review-panel'],
  },
  {
    id: 'library-components',
    url: '/library/components',
    viewport: { width: 2560, height: 1440 },
    description: 'Reusable component library, showing usage counts.',
  },
  {
    id: 'localization-overview',
    url: '/localization',
    viewport: { width: 2560, height: 1440 },
    description: 'Language status across a publication.',
  },
];
