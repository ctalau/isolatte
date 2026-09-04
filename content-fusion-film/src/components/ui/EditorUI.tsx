import React from 'react';
import { theme } from '../../theme/contentFusion';
import {
  contentTree,
  metadataFields,
  type ContentBlock,
} from '../../assets/productContent';
import { IconComponent, IconLibrary, IconMap, IconTopic } from './Icons';

const t = theme.typography;
const c = theme.colors;

export const SIDEBAR_WIDTH = 250;
export const METADATA_WIDTH = 268;
/** Height of the application chrome; side panels start below it. */
export const CHROME_HEIGHT = 46;

/* -------------------------------------------------------------------------- */
/* Sidebar                                                                     */
/* -------------------------------------------------------------------------- */

const treeIcon = (kind: string, active: boolean) => {
  const color = active ? c.accent : c.ink[8];
  if (kind === 'map') return <IconMap color={color} />;
  if (kind === 'library') return <IconLibrary color={color} />;
  if (kind === 'component') return <IconComponent color={color} />;
  return <IconTopic color={color} />;
};

export const Sidebar: React.FC<{ highlightComponent?: boolean }> = ({ highlightComponent = false }) => (
  <div
    style={{
      position: 'absolute',
      left: 0,
      top: CHROME_HEIGHT,
      bottom: 0,
      width: SIDEBAR_WIDTH,
      paddingTop: 18,
      background: `linear-gradient(180deg, rgba(255,255,255,0.022) 0%, rgba(255,255,255,0) 60%), ${c.ink[2]}`,
      borderRight: `1px solid ${c.stroke.hairline}`,
      borderBottomLeftRadius: theme.radii.window,
    }}
  >
    <div
      style={{
        padding: '0 18px 12px',
        fontFamily: t.mono,
        fontSize: t.scale.micro.size,
        fontWeight: 500,
        letterSpacing: '0.14em',
        textTransform: 'uppercase',
        color: c.ink[8],
      }}
    >
      Workspace
    </div>
    <div style={{ display: 'flex', flexDirection: 'column', gap: 1, padding: '0 10px' }}>
      {contentTree.map((node) => {
        const isActive = Boolean(node.active);
        const isHi = highlightComponent && node.kind === 'component' && node.label.startsWith('Admin');
        return (
          <div
            key={node.label}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 9,
              height: 27,
              paddingLeft: 8 + node.depth * 14,
              paddingRight: 8,
              borderRadius: theme.radii.sm,
              background: isActive
                ? 'rgba(91,140,255,0.13)'
                : isHi
                  ? 'rgba(127,209,192,0.11)'
                  : 'transparent',
              boxShadow: isActive ? `inset 0 0 0 1px rgba(91,140,255,0.22)` : undefined,
            }}
          >
            {treeIcon(node.kind, isActive)}
            <span
              style={{
                fontFamily: t.body,
                fontSize: 12.5,
                letterSpacing: '-0.002em',
                color: isActive ? c.ink[12] : node.depth === 0 ? c.ink[11] : c.ink[10],
                fontWeight: node.depth === 0 ? 520 : 420,
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}
            >
              {node.label}
            </span>
          </div>
        );
      })}
    </div>

    <div
      style={{
        position: 'absolute',
        left: 18,
        right: 18,
        bottom: 18,
        paddingTop: 12,
        borderTop: `1px solid ${c.stroke.hairline}`,
        display: 'flex',
        alignItems: 'center',
        gap: 8,
      }}
    >
      <span
        style={{
          width: 6,
          height: 6,
          borderRadius: 3,
          background: c.structure.reusable,
          opacity: 0.8,
        }}
      />
      <span style={{ fontFamily: t.body, fontSize: 11.5, color: c.ink[9] }}>
        42 topics · 7 languages
      </span>
    </div>
  </div>
);

/* -------------------------------------------------------------------------- */
/* Document blocks                                                             */
/* -------------------------------------------------------------------------- */

export const BlockView: React.FC<{
  block: ContentBlock;
  /** 0..1 entrance progress, used for reflow and suggestion merges. */
  reveal?: number;
  emphasis?: number;
  muted?: number;
  /** 0..1 — marks a block that was just inserted. Fades out on its own. */
  highlight?: number;
}> = ({ block, reveal = 1, emphasis = 0, muted = 0, highlight = 0 }) => {
  const opacity = reveal * (1 - muted * 0.62);
  const shared: React.CSSProperties = {
    opacity,
    transform: `translateY(${((1 - reveal) * 10).toFixed(2)}px)`,
    filter: reveal < 1 ? `blur(${((1 - reveal) * 3).toFixed(2)}px)` : undefined,
  };

  const inner = renderBlock(block, shared, emphasis);
  if (highlight <= 0.001) return inner;
  // A newly inserted block keeps an accent rule for a moment, so the eye finds
  // where the accepted suggestion landed without any extra UI chrome.
  return (
    <div style={{ position: 'relative' }}>
      <div
        style={{
          position: 'absolute',
          left: -20,
          top: -6,
          bottom: -6,
          width: 2,
          borderRadius: 2,
          background: c.accent,
          opacity: 0.75 * highlight,
        }}
      />
      {inner}
    </div>
  );
};

const renderBlock = (
  block: ContentBlock,
  shared: React.CSSProperties,
  emphasis: number,
): React.ReactElement | null => {
  switch (block.kind) {
    case 'title':
      return (
        <h1
          style={{
            ...shared,
            margin: 0,
            fontFamily: t.display,
            fontSize: 31,
            fontWeight: 570,
            letterSpacing: '-0.021em',
            lineHeight: 1.14,
            color: c.text.primary,
          }}
        >
          {block.text}
        </h1>
      );
    case 'shortdesc':
      return (
        <p
          style={{
            ...shared,
            margin: 0,
            fontFamily: t.body,
            fontSize: 15.5,
            fontWeight: 420,
            lineHeight: 1.55,
            letterSpacing: '-0.003em',
            color: c.ink[10],
            maxWidth: 560,
          }}
        >
          {block.text}
        </p>
      );
    case 'section':
      return (
        <div
          style={{
            ...shared,
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            marginTop: 4,
          }}
        >
          <span
            style={{
              fontFamily: t.display,
              fontSize: 15,
              fontWeight: 570,
              letterSpacing: '-0.008em',
              color: c.ink[11],
            }}
          >
            {block.label}
          </span>
          <span style={{ flex: 1, height: 1, background: c.stroke.hairline }} />
        </div>
      );
    case 'paragraph':
      return (
        <p
          style={{
            ...shared,
            margin: 0,
            fontFamily: t.body,
            fontSize: 14,
            lineHeight: 1.62,
            letterSpacing: '-0.001em',
            color: c.ink[10],
            maxWidth: 560,
          }}
        >
          {block.text}
        </p>
      );
    case 'step':
      return (
        <div style={{ ...shared, display: 'flex', gap: 13, alignItems: 'flex-start' }}>
          <div
            style={{
              width: 21,
              height: 21,
              flex: '0 0 auto',
              borderRadius: 6,
              background: 'rgba(255,255,255,0.045)',
              border: `1px solid ${c.stroke.hairline}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontFamily: t.mono,
              fontSize: 11,
              color: c.ink[10],
              marginTop: 1,
            }}
          >
            {block.index}
          </div>
          <p
            style={{
              margin: 0,
              fontFamily: t.body,
              fontSize: 14,
              lineHeight: 1.6,
              color: c.ink[11],
              maxWidth: 520,
            }}
          >
            {block.text}
          </p>
        </div>
      );
    case 'note':
      return (
        <div
          style={{
            ...shared,
            position: 'relative',
            display: 'flex',
            gap: 12,
            padding: '12px 15px',
            borderRadius: theme.radii.sm,
            background: block.reusable ? 'rgba(127,209,192,0.055)' : 'rgba(255,255,255,0.028)',
            border: `1px solid ${block.reusable ? 'rgba(127,209,192,0.2)' : c.stroke.hairline}`,
            maxWidth: 560,
            boxShadow: emphasis > 0 ? `0 0 0 ${(emphasis * 2).toFixed(1)}px rgba(127,209,192,${(0.22 * emphasis).toFixed(3)})` : undefined,
          }}
        >
          {block.reusable ? (
            <span style={{ marginTop: 1 }}>
              <IconComponent color={c.structure.reusable} size={14} />
            </span>
          ) : null}
          <div>
            {block.reusable ? (
              <div
                style={{
                  fontFamily: t.mono,
                  fontSize: 9.5,
                  letterSpacing: '0.13em',
                  textTransform: 'uppercase',
                  color: c.structure.reusable,
                  marginBottom: 5,
                  opacity: 0.9,
                }}
              >
                Reusable component
              </div>
            ) : null}
            <p
              style={{
                margin: 0,
                fontFamily: t.body,
                fontSize: 13.5,
                lineHeight: 1.55,
                color: c.ink[10],
              }}
            >
              {block.text}
            </p>
          </div>
        </div>
      );
    case 'code':
      return (
        <pre
          style={{
            ...shared,
            margin: 0,
            padding: '12px 15px',
            borderRadius: theme.radii.sm,
            background: 'rgba(0,0,0,0.35)',
            border: `1px solid ${c.stroke.hairline}`,
            fontFamily: t.mono,
            fontSize: 12,
            lineHeight: 1.6,
            color: c.ink[10],
          }}
        >
          {block.lines.join('\n')}
        </pre>
      );
    default:
      return null;
  }
};

export const DocumentCanvas: React.FC<{
  blocks: ContentBlock[];
  reveals?: number[];
  emphasisIndex?: number;
  emphasis?: number;
  highlights?: number[];
  scrollY?: number;
  paddingTop?: number;
}> = ({ blocks, reveals, emphasisIndex = -1, emphasis = 0, highlights, scrollY = 0, paddingTop = 40 }) => (
  <div
    style={{
      position: 'absolute',
      left: SIDEBAR_WIDTH,
      right: METADATA_WIDTH,
      top: CHROME_HEIGHT,
      bottom: 0,
      overflow: 'hidden',
    }}
  >
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 19,
        padding: `${paddingTop}px 52px 40px`,
        transform: `translateY(${-scrollY}px)`,
      }}
    >
      {blocks.map((block, i) => (
        <BlockView
          key={`${block.kind}-${i}`}
          block={block}
          reveal={reveals?.[i] ?? 1}
          emphasis={i === emphasisIndex ? emphasis : 0}
          highlight={highlights?.[i] ?? 0}
        />
      ))}
    </div>
  </div>
);

/* -------------------------------------------------------------------------- */
/* Metadata panel                                                              */
/* -------------------------------------------------------------------------- */

export const MetadataPanel: React.FC<{ highlight?: number }> = ({ highlight = 0 }) => (
  <div
    style={{
      position: 'absolute',
      right: 0,
      top: CHROME_HEIGHT,
      bottom: 0,
      width: METADATA_WIDTH,
      paddingTop: 18,
      background: `linear-gradient(180deg, rgba(255,255,255,0.018) 0%, rgba(255,255,255,0) 50%), ${c.ink[2]}`,
      borderLeft: `1px solid ${c.stroke.hairline}`,
      borderBottomRightRadius: theme.radii.window,
    }}
  >
    <div
      style={{
        padding: '0 20px 14px',
        fontFamily: t.mono,
        fontSize: t.scale.micro.size,
        letterSpacing: '0.14em',
        textTransform: 'uppercase',
        color: c.ink[8],
      }}
    >
      Metadata
    </div>
    <div style={{ padding: '0 20px', display: 'flex', flexDirection: 'column', gap: 0 }}>
      {metadataFields.map((f) => (
        <div
          key={f.label}
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            height: 33,
            borderBottom: `1px solid rgba(255,255,255,0.035)`,
          }}
        >
          <span style={{ fontFamily: t.body, fontSize: 12, color: c.ink[9] }}>{f.label}</span>
          <span
            style={{
              fontFamily: t.body,
              fontSize: 12,
              fontWeight: 500,
              color: highlight > 0 ? c.accent : c.ink[11],
              opacity: 1,
            }}
          >
            {f.value}
          </span>
        </div>
      ))}
    </div>
  </div>
);

/* -------------------------------------------------------------------------- */
/* Floating toolbar                                                            */
/* -------------------------------------------------------------------------- */

export const FloatingToolbar: React.FC<{
  items: { label: string; icon?: React.ReactNode; active?: boolean }[];
  opacity?: number;
}> = ({ items, opacity = 1 }) => (
  <div
    style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: 3,
      padding: 4,
      borderRadius: theme.radii.pill,
      background: 'rgba(16,20,28,0.86)',
      backdropFilter: 'blur(24px) saturate(120%)',
      WebkitBackdropFilter: 'blur(24px) saturate(120%)',
      border: `1px solid ${c.stroke.soft}`,
      boxShadow: theme.shadows.card,
      opacity,
    }}
  >
    {items.map((item) => (
      <div
        key={item.label}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 7,
          height: 30,
          padding: '0 13px',
          borderRadius: theme.radii.pill,
          background: item.active ? 'rgba(91,140,255,0.18)' : 'transparent',
          boxShadow: item.active ? 'inset 0 0 0 1px rgba(91,140,255,0.3)' : undefined,
          color: item.active ? c.ink[12] : c.ink[10],
          fontFamily: t.body,
          fontSize: 12.5,
          fontWeight: 480,
          letterSpacing: '-0.002em',
          whiteSpace: 'nowrap',
        }}
      >
        {item.icon}
        {item.label}
      </div>
    ))}
  </div>
);
