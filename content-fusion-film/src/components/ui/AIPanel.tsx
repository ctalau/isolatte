import React from 'react';
import { theme } from '../../theme/contentFusion';
import { BlockView } from './EditorUI';
import { IconCheck, IconSparkle } from './Icons';
import type { ContentBlock } from '../../assets/productContent';

const t = theme.typography;
const c = theme.colors;

/**
 * The AI suggestion panel.
 *
 * Framed as a *proposal*: it is visually separated from the document, labelled,
 * and carries explicit accept/dismiss affordances. The film never shows AI
 * output silently becoming published content — the human action is always on
 * screen. See the CREATIVE DIRECTION note on human control.
 */
export const AIPanel: React.FC<{
  title?: string;
  prompt?: string;
  blocks: ContentBlock[];
  /** 0..1 — how much of the suggestion body has resolved. */
  resolve?: number;
  /** 0..1 — approval affordance emphasis. */
  approve?: number;
  width?: number;
  footerNote?: string;
}> = ({
  title = 'Suggested continuation',
  prompt = 'Extend this task with a verification step',
  blocks,
  resolve = 1,
  approve = 0,
  width = 428,
  footerNote = 'Review before applying',
}) => (
  <div
    style={{
      width,
      borderRadius: theme.radii.lg,
      overflow: 'hidden',
      background: `${theme.gradients.glassSurface}, rgba(28,34,46,0.9)`,
      backdropFilter: 'blur(30px) saturate(118%)',
      WebkitBackdropFilter: 'blur(30px) saturate(118%)',
      border: `1px solid rgba(91,140,255,0.22)`,
      boxShadow: theme.shadows.panel,
    }}
  >
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 9,
        padding: '14px 17px 12px',
        borderBottom: `1px solid ${c.stroke.hairline}`,
      }}
    >
      <IconSparkle color={c.accent} size={14} />
      <span
        style={{
          fontFamily: t.display,
          fontSize: 13,
          fontWeight: 560,
          letterSpacing: '-0.004em',
          color: c.ink[12],
        }}
      >
        {title}
      </span>
      <span style={{ flex: 1 }} />
      <span
        style={{
          fontFamily: t.mono,
          fontSize: 9.5,
          letterSpacing: '0.12em',
          textTransform: 'uppercase',
          color: c.accent,
          padding: '3px 7px',
          borderRadius: 4,
          background: 'rgba(91,140,255,0.12)',
        }}
      >
        Draft
      </span>
    </div>

    <div style={{ padding: '13px 17px 0' }}>
      <div
        style={{
          fontFamily: t.body,
          fontSize: 12,
          lineHeight: 1.5,
          color: c.ink[9],
          paddingBottom: 13,
          borderBottom: `1px solid rgba(255,255,255,0.04)`,
        }}
      >
        {prompt}
      </div>
    </div>

    <div style={{ padding: '15px 17px 16px', display: 'flex', flexDirection: 'column', gap: 13 }}>
      {blocks.map((b, i) => {
        // Blocks resolve in sequence so the suggestion reads as *composed*,
        // not pasted. Each block gets a third of the resolve window, staggered.
        const start = i * 0.22;
        const local = Math.max(0, Math.min(1, (resolve - start) / 0.56));
        return <BlockView key={i} block={b} reveal={local} />;
      })}
    </div>

    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 9,
        padding: '12px 17px',
        borderTop: `1px solid ${c.stroke.hairline}`,
        background: 'rgba(0,0,0,0.16)',
      }}
    >
      <span style={{ fontFamily: t.body, fontSize: 11.5, color: c.ink[8] }}>{footerNote}</span>
      <span style={{ flex: 1 }} />
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          height: 28,
          padding: '0 12px',
          borderRadius: theme.radii.sm,
          fontFamily: t.body,
          fontSize: 12,
          color: c.ink[9],
          border: `1px solid ${c.stroke.hairline}`,
        }}
      >
        Dismiss
      </div>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 7,
          height: 28,
          padding: '0 13px',
          borderRadius: theme.radii.sm,
          fontFamily: t.body,
          fontSize: 12,
          fontWeight: 520,
          color: '#0A0D14',
          background: `rgba(${approve > 0 ? '232,180,115' : '91,140,255'}, 1)`,
          boxShadow: approve > 0 ? `0 0 ${(20 * approve).toFixed(0)}px rgba(232,180,115,0.4)` : undefined,
          transform: `scale(${(1 + approve * 0.03).toFixed(4)})`,
        }}
      >
        <IconCheck color="#0A0D14" size={13} strokeWidth={1.9} />
        Apply
      </div>
    </div>
  </div>
);

/**
 * Compact review panel used in the human-control scene: shows the difference
 * between current and proposed text with an explicit approval action.
 */
export const ReviewPanel: React.FC<{
  removed: string;
  added: string;
  approve?: number;
  approved?: number;
  width?: number;
}> = ({ removed, added, approve = 0, approved = 0, width = 452 }) => (
  <div
    style={{
      width,
      borderRadius: theme.radii.lg,
      overflow: 'hidden',
      background: `${theme.gradients.glassSurface}, rgba(28,34,46,0.92)`,
      backdropFilter: 'blur(30px) saturate(118%)',
      WebkitBackdropFilter: 'blur(30px) saturate(118%)',
      border: `1px solid ${approved > 0.5 ? 'rgba(232,180,115,0.32)' : c.stroke.soft}`,
      boxShadow: theme.shadows.panel,
    }}
  >
    <div
      style={{
        padding: '14px 18px 12px',
        borderBottom: `1px solid ${c.stroke.hairline}`,
        display: 'flex',
        alignItems: 'center',
        gap: 9,
      }}
    >
      <span
        style={{
          fontFamily: t.display,
          fontSize: 13,
          fontWeight: 560,
          letterSpacing: '-0.004em',
          color: c.ink[12],
        }}
      >
        Review change
      </span>
      <span style={{ flex: 1 }} />
      <span
        style={{
          fontFamily: t.mono,
          fontSize: 9.5,
          letterSpacing: '0.12em',
          textTransform: 'uppercase',
          color: approved > 0.5 ? c.human : c.ink[9],
        }}
      >
        {approved > 0.5 ? 'Approved' : 'Awaiting approval'}
      </span>
    </div>

    <div style={{ padding: '14px 18px 16px', display: 'flex', flexDirection: 'column', gap: 9 }}>
      <DiffRow sign="−" text={removed} tone="removed" />
      <DiffRow sign="+" text={added} tone="added" />
    </div>

    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 9,
        padding: '12px 18px',
        borderTop: `1px solid ${c.stroke.hairline}`,
        background: 'rgba(0,0,0,0.16)',
      }}
    >
      <span style={{ fontFamily: t.body, fontSize: 11.5, color: c.ink[8] }}>
        Suggested by AI · applied by you
      </span>
      <span style={{ flex: 1 }} />
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 7,
          height: 28,
          padding: '0 14px',
          borderRadius: theme.radii.sm,
          fontFamily: t.body,
          fontSize: 12,
          fontWeight: 520,
          color: '#0A0D14',
          background: c.human,
          transform: `scale(${(1 + approve * 0.035).toFixed(4)})`,
          boxShadow: approve > 0 ? `0 0 ${(22 * approve).toFixed(0)}px rgba(232,180,115,0.45)` : undefined,
        }}
      >
        <IconCheck color="#0A0D14" size={13} strokeWidth={1.9} />
        Approve
      </div>
    </div>
  </div>
);

const DiffRow: React.FC<{ sign: string; text: string; tone: 'added' | 'removed' }> = ({
  sign,
  text,
  tone,
}) => (
  <div
    style={{
      display: 'flex',
      gap: 11,
      padding: '10px 13px',
      borderRadius: theme.radii.sm,
      background: tone === 'added' ? 'rgba(127,209,192,0.07)' : 'rgba(255,255,255,0.026)',
      border: `1px solid ${tone === 'added' ? 'rgba(127,209,192,0.18)' : c.stroke.hairline}`,
    }}
  >
    <span
      style={{
        fontFamily: t.mono,
        fontSize: 12,
        color: tone === 'added' ? c.structure.reusable : c.ink[8],
        lineHeight: 1.5,
      }}
    >
      {sign}
    </span>
    <span
      style={{
        fontFamily: t.body,
        fontSize: 13,
        lineHeight: 1.5,
        color: tone === 'added' ? c.ink[11] : c.ink[8],
        textDecoration: tone === 'removed' ? 'line-through' : undefined,
        textDecorationColor: 'rgba(255,255,255,0.22)',
      }}
    >
      {text}
    </span>
  </div>
);
