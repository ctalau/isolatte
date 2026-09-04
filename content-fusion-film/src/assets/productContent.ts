/**
 * Sample content shown inside the reconstructed Content Fusion UI.
 *
 * IMPORTANT — SOURCE OF TRUTH
 * This is *representative* content authored for the film, not a capture of a
 * real customer project. It is structured the way structured technical content
 * generally is (topic → short description → prerequisite → steps → note, with
 * reusable fragments and metadata), so the film can show real editorial
 * behaviour without fabricating a specific customer's data.
 *
 * All copy here is configurable and expected to be replaced with real product
 * content before final delivery. See src/assets/manifest.ts.
 */

export type ContentBlock =
  | { kind: 'title'; text: string }
  | { kind: 'shortdesc'; text: string }
  | { kind: 'section'; label: string }
  | { kind: 'paragraph'; text: string; reusable?: boolean }
  | { kind: 'step'; index: number; text: string; code?: string }
  | { kind: 'note'; text: string; reusable?: boolean }
  | { kind: 'code'; lines: string[] };

export const editorDocument: ContentBlock[] = [
  { kind: 'title', text: 'Configure single sign-on' },
  {
    kind: 'shortdesc',
    text: 'Connect your identity provider so members sign in with your organization credentials.',
  },
  { kind: 'section', label: 'Before you begin' },
  {
    kind: 'note',
    text: 'You need administrator permissions on the workspace to change authentication settings.',
    reusable: true,
  },
  { kind: 'section', label: 'Procedure' },
  { kind: 'step', index: 1, text: 'Open Settings and select Authentication.' },
  { kind: 'step', index: 2, text: 'Choose your identity provider, then paste the metadata URL.' },
  { kind: 'step', index: 3, text: 'Map the provider groups to workspace roles and save.' },
  {
    kind: 'paragraph',
    text: 'Existing members keep their roles. New members are assigned a role the first time they sign in through the provider.',
  },
  { kind: 'section', label: 'Result' },
  {
    kind: 'paragraph',
    text: 'Members are redirected to your identity provider when they open the workspace, and return signed in.',
  },
  {
    kind: 'note',
    text: 'Service accounts and API tokens are not affected by single sign-on.',
    reusable: true,
  },
];

/** Blocks the AI action proposes to add. Shown as a suggestion, never as fact. */
export const aiSuggestionBlocks: ContentBlock[] = [
  { kind: 'section', label: 'Verify the connection' },
  {
    kind: 'paragraph',
    text: 'Sign out, then sign in again from a private window. The provider sign-in page should appear before the workspace loads.',
  },
  {
    kind: 'note',
    text: 'If sign-in fails, confirm the metadata URL is reachable from your network.',
  },
];

export const contentTree = [
  { label: 'Getting started', depth: 0, kind: 'map' as const },
  { label: 'Installation', depth: 1, kind: 'topic' as const },
  { label: 'Authentication', depth: 1, kind: 'map' as const },
  { label: 'Configure single sign-on', depth: 2, kind: 'topic' as const, active: true },
  { label: 'Manage API tokens', depth: 2, kind: 'topic' as const },
  { label: 'Rotate credentials', depth: 2, kind: 'topic' as const },
  { label: 'Administration', depth: 1, kind: 'map' as const },
  { label: 'Reusable components', depth: 0, kind: 'library' as const },
  { label: 'Admin permission note', depth: 1, kind: 'component' as const },
  { label: 'Supported providers', depth: 1, kind: 'component' as const },
];

export const metadataFields = [
  { label: 'Type', value: 'Task' },
  { label: 'Audience', value: 'Administrator' },
  { label: 'Product', value: 'Platform' },
  { label: 'Version', value: '4.2' },
  { label: 'Status', value: 'In review' },
  { label: 'Languages', value: '7' },
];

export const structureLabels = [
  { id: 'title', label: 'Title', color: 'title' as const },
  { id: 'metadata', label: 'Metadata', color: 'metadata' as const },
  { id: 'block', label: 'Content block', color: 'block' as const },
  { id: 'reusable', label: 'Reusable component', color: 'reusable' as const },
  { id: 'taxonomy', label: 'Taxonomy relationship', color: 'taxonomy' as const },
];

export const audienceProfiles = [
  { id: 'technical', label: 'Technical', detail: 'Reference depth, exact parameters' },
  { id: 'customer', label: 'Customer', detail: 'Task-first, plain language' },
  { id: 'support', label: 'Support', detail: 'Symptom, cause, resolution' },
  { id: 'learning', label: 'Learning', detail: 'Guided, with checkpoints' },
];

export const languages = [
  { code: 'EN', label: 'English' },
  { code: 'DE', label: 'Deutsch' },
  { code: 'FR', label: 'Français' },
  { code: 'JA', label: '日本語' },
  { code: 'ES', label: 'Español' },
  { code: 'RO', label: 'Română' },
];

export const channels = [
  { id: 'docs', label: 'Documentation' },
  { id: 'web', label: 'Web' },
  { id: 'support', label: 'Support' },
  { id: 'knowledge', label: 'Knowledge base' },
  { id: 'learning', label: 'Learning' },
  { id: 'ai', label: 'AI experiences' },
];
