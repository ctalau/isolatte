/**
 * Audio architecture.
 *
 * Six independent layers, each with its own gain, so the mix can be balanced
 * without re-cutting anything:
 *
 *   voice      generated narration, one file per scene
 *   music      score bed
 *   ambience   room tone / spatial air
 *   ui         click, confirm — tied to on-screen interaction
 *   transition whoosh / pass — tied to a scene change
 *   impact     low-frequency accents on the film's few hard beats
 *
 * Music and SFX files are PLACEHOLDERS. The film is designed to read without
 * them; see status fields below and docs/AUDIO.md.
 */

export type AudioLayer = 'voice' | 'music' | 'ambience' | 'ui' | 'transition' | 'impact';

export type SfxCue = {
  id: string;
  layer: AudioLayer;
  file: string;
  status: 'placeholder' | 'delivered';
  /** Linear gain applied on top of the layer gain. */
  gain: number;
  description: string;
};

export const mixer: Record<AudioLayer, { gain: number; duckedByVoice: number }> = {
  // duckedByVoice: multiplier applied while narration is playing.
  voice: { gain: 1.0, duckedByVoice: 1 },
  music: { gain: 0.34, duckedByVoice: 0.55 },
  ambience: { gain: 0.22, duckedByVoice: 0.7 },
  ui: { gain: 0.5, duckedByVoice: 0.85 },
  transition: { gain: 0.42, duckedByVoice: 0.8 },
  impact: { gain: 0.6, duckedByVoice: 0.9 },
};

export const sfxCues: Record<string, SfxCue> = {
  'ui.click': {
    id: 'ui.click',
    layer: 'ui',
    file: 'audio/sfx/ui-click.wav',
    status: 'placeholder',
    gain: 0.8,
    description: 'Short, dry, no pitch tail. Must not sound like a game UI.',
  },
  'ui.confirm': {
    id: 'ui.confirm',
    layer: 'ui',
    file: 'audio/sfx/ui-confirm.wav',
    status: 'placeholder',
    gain: 0.7,
    description: 'Soft two-note confirmation, barely above the bed.',
  },
  'whoosh.soft': {
    id: 'whoosh.soft',
    layer: 'transition',
    file: 'audio/sfx/whoosh-soft.wav',
    status: 'placeholder',
    gain: 0.6,
    description: 'Air movement, no pitch sweep. Supports the camera, not the cut.',
  },
  'transition.pass': {
    id: 'transition.pass',
    layer: 'transition',
    file: 'audio/sfx/transition-pass.wav',
    status: 'placeholder',
    gain: 0.65,
    description: 'Object passing the lens. Stereo movement left→right.',
  },
  'merge.content': {
    id: 'merge.content',
    layer: 'ui',
    file: 'audio/sfx/merge-content.wav',
    status: 'placeholder',
    gain: 0.7,
    description: 'Two elements becoming one. Short, granular, no reverb tail.',
  },
  'data.move': {
    id: 'data.move',
    layer: 'transition',
    file: 'audio/sfx/data-move.wav',
    status: 'placeholder',
    gain: 0.5,
    description: 'Fine-grained movement texture for distribution shots.',
  },
  'impact.low': {
    id: 'impact.low',
    layer: 'impact',
    file: 'audio/sfx/impact-low.wav',
    status: 'placeholder',
    gain: 0.75,
    description: 'Sub-heavy, no click. Used at most three times in the film.',
  },
  'riser.low': {
    id: 'riser.low',
    layer: 'transition',
    file: 'audio/sfx/riser-low.wav',
    status: 'placeholder',
    gain: 0.45,
    description: 'Tonal riser, 2s, resolves rather than peaks.',
  },
  'ambience.room': {
    id: 'ambience.room',
    layer: 'ambience',
    file: 'audio/ambience/room-tone.wav',
    status: 'placeholder',
    gain: 1,
    description: 'Neutral air. Gives the black frames a sense of space.',
  },
};

export const musicBed = {
  id: 'music.main',
  file: 'audio/music/bed.wav',
  status: 'placeholder' as const,
  description:
    'Sophisticated electronic, minimal pulse, restrained. Must work under narration and resolve at the end frame. Not licensed stock — to be commissioned.',
};
