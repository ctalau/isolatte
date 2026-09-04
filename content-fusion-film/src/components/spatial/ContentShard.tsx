import React from 'react';
import { theme } from '../../theme/contentFusion';
import { hashed } from '../../motion/interpolation';

const t = theme.typography;
const c = theme.colors;

export type ShardKind = 'sentence' | 'card' | 'metadata' | 'snippet' | 'icon' | 'table';

export type Shard = {
  id: string;
  kind: ShardKind;
  /** World position of the fragment before convergence. */
  x: number;
  y: number;
  z: number;
  rotationY: number;
  rotationX: number;
  scale: number;
  text?: string;
  label?: string;
};

/**
 * A fragment of knowledge, before Content Fusion gives it structure.
 *
 * These are deliberately *legible objects* — a line of a procedure, a metadata
 * pair, a support snippet — not abstract glowing particles. The scene reads as
 * "real content, scattered", which is the actual message.
 */
export const ContentShard: React.FC<{ shard: Shard; dim?: number }> = ({ shard, dim = 0 }) => {
  const alpha = 1 - dim;
  const base: React.CSSProperties = {
    borderRadius: theme.radii.sm,
    border: `1px solid rgba(255,255,255,${(0.1 * alpha).toFixed(3)})`,
    background: `linear-gradient(160deg, rgba(255,255,255,0.06) 0%, rgba(255,255,255,0.016) 100%), rgba(26,32,43,${(
      0.92 * alpha
    ).toFixed(3)})`,
    boxShadow: theme.shadows.card,
    backdropFilter: 'blur(12px)',
    WebkitBackdropFilter: 'blur(12px)',
  };

  if (shard.kind === 'metadata') {
    return (
      <div style={{ ...base, padding: '9px 13px', display: 'flex', gap: 10, alignItems: 'baseline', whiteSpace: 'nowrap' }}>
        <span
          style={{
            fontFamily: t.mono,
            fontSize: 9.5,
            letterSpacing: '0.13em',
            textTransform: 'uppercase',
            color: c.ink[8],
          }}
        >
          {shard.label}
        </span>
        <span style={{ fontFamily: t.body, fontSize: 12.5, color: c.ink[11] }}>{shard.text}</span>
      </div>
    );
  }

  if (shard.kind === 'icon') {
    return (
      <div
        style={{
          ...base,
          width: 44,
          height: 44,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <div
          style={{
            width: 15,
            height: 15,
            borderRadius: 4,
            border: `1.2px solid ${c.ink[9]}`,
          }}
        />
      </div>
    );
  }

  if (shard.kind === 'table') {
    return (
      <div style={{ ...base, padding: 10, width: 190 }}>
        {[0, 1, 2].map((row) => (
          <div key={row} style={{ display: 'flex', gap: 8, marginBottom: row < 2 ? 7 : 0 }}>
            {[0, 1, 2].map((col) => (
              <div
                key={col}
                style={{
                  height: 6,
                  borderRadius: 3,
                  flex: col === 0 ? 1.4 : 1,
                  background: `rgba(199,206,218,${(0.1 + hashed(7, row * 3 + col) * 0.16).toFixed(3)})`,
                }}
              />
            ))}
          </div>
        ))}
      </div>
    );
  }

  if (shard.kind === 'snippet') {
    return (
      <div style={{ ...base, padding: '11px 14px', width: 262 }}>
        <div
          style={{
            fontFamily: t.mono,
            fontSize: 9.5,
            letterSpacing: '0.12em',
            textTransform: 'uppercase',
            color: c.ink[8],
            marginBottom: 6,
          }}
        >
          {shard.label}
        </div>
        <div style={{ fontFamily: t.body, fontSize: 12.5, lineHeight: 1.5, color: c.ink[10] }}>
          {shard.text}
        </div>
      </div>
    );
  }

  if (shard.kind === 'card') {
    return (
      <div style={{ ...base, padding: 13, width: 208 }}>
        <div
          style={{
            fontFamily: t.display,
            fontSize: 13,
            fontWeight: 545,
            letterSpacing: '-0.008em',
            color: c.ink[11],
            marginBottom: 9,
          }}
        >
          {shard.label}
        </div>
        {[0.92, 0.72, 0.48].map((w, i) => (
          <div
            key={i}
            style={{
              height: 5,
              width: `${w * 100}%`,
              borderRadius: 3,
              background: 'rgba(199,206,218,0.15)',
              marginBottom: 7,
            }}
          />
        ))}
      </div>
    );
  }

  // sentence
  return (
    <div style={{ ...base, padding: '10px 15px', width: 300 }}>
      <span style={{ fontFamily: t.body, fontSize: 13, lineHeight: 1.5, color: c.ink[10] }}>
        {shard.text}
      </span>
    </div>
  );
};

/**
 * The fragment field. Positions are seeded, not random, so the composition is
 * identical on every render — and hand-tuned in bands so it reads as arranged
 * rather than sprayed.
 */
export const buildShardField = (seed = 21): Shard[] => {
  const specs: Array<Partial<Shard> & { kind: ShardKind }> = [
    { kind: 'sentence', text: 'You need administrator permissions to change authentication settings.' },
    { kind: 'card', label: 'Release notes 4.2' },
    { kind: 'metadata', label: 'Audience', text: 'Administrator' },
    { kind: 'snippet', label: 'Support ticket', text: 'Customer cannot complete sign-in after enabling the provider.' },
    { kind: 'sentence', text: 'Map the provider groups to workspace roles.' },
    { kind: 'icon' },
    { kind: 'table' },
    { kind: 'metadata', label: 'Product', text: 'Platform' },
    { kind: 'card', label: 'Onboarding guide' },
    { kind: 'sentence', text: 'Service accounts are not affected.' },
    { kind: 'snippet', label: 'Knowledge base', text: 'Rotating credentials does not sign existing members out.' },
    { kind: 'icon' },
    { kind: 'metadata', label: 'Status', text: 'In review' },
    { kind: 'card', label: 'API reference' },
    { kind: 'sentence', text: 'Members return signed in.' },
    { kind: 'table' },
    { kind: 'sentence', text: 'Open Settings and select Authentication.' },
    { kind: 'metadata', label: 'Version', text: '4.2' },
    { kind: 'card', label: 'Admin handbook' },
    { kind: 'snippet', label: 'Release note', text: 'Group mapping now supports nested provider groups.' },
    { kind: 'icon' },
    { kind: 'sentence', text: 'Paste the metadata URL.' },
    { kind: 'metadata', label: 'Language', text: 'de-DE' },
    { kind: 'table' },
    { kind: 'card', label: 'Migration guide' },
    { kind: 'snippet', label: 'FAQ', text: 'Can members still use a password? Not once the provider is enforced.' },
    { kind: 'sentence', text: 'Confirm the metadata URL is reachable.' },
    { kind: 'icon' },
  ];

  /**
   * Three depth bands. The near band crosses the lens out of focus (that is
   * what gives the shot volume), the mid band carries the readable content, and
   * the far band supplies parallax. Spreads are sized to the scene's ~37° lens
   * so the frame fills without fragments drifting off-screen.
   */
  const bands = [
    { z: 0.85, spread: 2.4, yspread: 1.5, scale: 1.0 },
    { z: -0.4, spread: 3.3, yspread: 1.95, scale: 0.82 },
    { z: -1.7, spread: 4.4, yspread: 2.6, scale: 0.62 },
  ];

  return specs.map((spec, i) => {
    const band = bands[i % 3]!;
    const r1 = hashed(seed, i * 3);
    const r2 = hashed(seed, i * 3 + 1);
    const r3 = hashed(seed, i * 3 + 2);
    return {
      id: `shard-${i}`,
      kind: spec.kind,
      label: spec.label,
      text: spec.text,
      x: (r1 - 0.5) * band.spread * 2,
      y: (r2 - 0.5) * band.yspread * 2,
      z: band.z + (r3 - 0.5) * 0.5,
      rotationY: (r1 - 0.5) * 14,
      rotationX: (r2 - 0.5) * 7,
      scale: band.scale * (0.9 + r3 * 0.22),
    };
  });
};
