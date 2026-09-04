import React from 'react';
import { useCurrentFrame } from 'remotion';
import { theme } from '../../theme/contentFusion';
import { scenes, sceneStarts, voiceLeadInFrames } from '../../film/contentFusionFilm';
import { narration } from '../../film/narration';
import { voiceManifest } from '../../film/voiceManifest';
import { FPS } from '../../motion/timing';
import { envelope } from '../../motion/interpolation';

/**
 * Subtitles are generated from the narration script — never authored twice.
 * Long lines are split at the nearest sentence or clause boundary so a cue is
 * at most two lines, which is the only readable shape at this size.
 */
const splitCue = (text: string): string[] => {
  if (text.length <= 62) return [text];
  const mid = Math.floor(text.length / 2);
  const candidates = [...text.matchAll(/[,.;:] /g)].map((m) => m.index ?? 0);
  const pivot =
    candidates.length > 0
      ? candidates.reduce((best, i) => (Math.abs(i - mid) < Math.abs(best - mid) ? i : best))
      : text.lastIndexOf(' ', mid);
  return [text.slice(0, pivot + 1).trim(), text.slice(pivot + 1).trim()].filter(Boolean);
};

export const Subtitles: React.FC<{ enabled?: boolean }> = ({ enabled = false }) => {
  const frame = useCurrentFrame();
  if (!enabled) return null;

  const index = sceneStarts.findIndex(
    (start, i) => frame >= start && frame < start + (scenes[i]?.durationInFrames ?? 0),
  );
  const scene = index >= 0 ? scenes[index] : undefined;
  if (!scene?.narrationId) return null;

  const line = narration[scene.narrationId];
  if (!line) return null;

  const start = (sceneStarts[index] ?? 0) + voiceLeadInFrames;
  const entry = voiceManifest.entries[scene.narrationId];
  const spoken = entry ? Math.round(entry.durationInSeconds * FPS) : scene.durationInFrames - 34;
  const end = start + spoken;

  const opacity = envelope(frame, start - 4, end + 8, 8, 10);
  if (opacity <= 0.01) return null;

  const lines = splitCue(line.text);

  return (
    <div
      style={{
        position: 'absolute',
        left: '12%',
        right: '12%',
        bottom: '7.5%',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 4,
        opacity,
        pointerEvents: 'none',
      }}
    >
      {lines.map((l) => (
        <span
          key={l}
          style={{
            fontFamily: theme.typography.body,
            fontSize: 26,
            fontWeight: 460,
            letterSpacing: '-0.006em',
            color: '#F3F6FB',
            textShadow: '0 2px 14px rgba(0,0,0,0.85), 0 0 2px rgba(0,0,0,0.7)',
            textAlign: 'center',
          }}
        >
          {l}
        </span>
      ))}
    </div>
  );
};
