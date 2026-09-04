import React from 'react';
import { theme } from '../../theme/contentFusion';
import { cinematicEase, editorialEase, type Easing } from '../../motion/easing';

const t = theme.typography;

type ScaleName = keyof typeof t.scale;

const styleFor = (scale: ScaleName): React.CSSProperties => {
  const s = t.scale[scale];
  return {
    fontFamily: scale === 'micro' ? t.mono : t.display,
    fontSize: s.size,
    fontWeight: s.weight,
    letterSpacing: `${s.tracking}em`,
    lineHeight: s.leading,
    margin: 0,
  };
};

/**
 * Masked type reveal.
 *
 * The line rises from behind a hard mask while tracking tightens and a small
 * amount of blur resolves. No per-letter animation — the film treats a line of
 * type as one object, which is what makes it read as editorial rather than
 * "kinetic typography".
 */
export const RevealLine: React.FC<{
  children: React.ReactNode;
  progress: number;
  scale?: ScaleName;
  color?: string;
  easing?: Easing;
  /** Extra tracking (em) at progress 0, resolving to the scale's own value. */
  trackingFrom?: number;
  rise?: number;
  align?: React.CSSProperties['textAlign'];
  style?: React.CSSProperties;
}> = ({
  children,
  progress,
  scale = 'headline',
  color = theme.colors.text.primary,
  easing = editorialEase,
  trackingFrom = 0.035,
  rise = 0.42,
  align,
  style,
}) => {
  const p = easing(Math.max(0, Math.min(1, progress)));
  const base = t.scale[scale];
  const tracking = base.tracking + (trackingFrom - base.tracking) * (1 - p);
  const height = base.size * base.leading;

  return (
    <span
      style={{
        display: 'block',
        overflow: 'hidden',
        // A hair of extra height so descenders are never clipped by the mask.
        paddingBottom: base.size * 0.16,
        marginBottom: -base.size * 0.16,
      }}
    >
      <span
        style={{
          ...styleFor(scale),
          display: 'block',
          color,
          textAlign: align,
          letterSpacing: `${tracking.toFixed(4)}em`,
          transform: `translateY(${((1 - p) * height * rise).toFixed(2)}px)`,
          opacity: Math.min(1, p * 1.35),
          filter: p < 1 ? `blur(${((1 - p) * 5).toFixed(2)}px)` : undefined,
          willChange: 'transform',
          ...style,
        }}
      >
        {children}
      </span>
    </span>
  );
};

/** Multi-line headline with a per-line stagger. */
export const Headline: React.FC<{
  lines: string[];
  progress: number;
  scale?: ScaleName;
  color?: string;
  stagger?: number;
  align?: React.CSSProperties['textAlign'];
  style?: React.CSSProperties;
}> = ({ lines, progress, scale = 'display', color, stagger = 0.14, align, style }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: 0, ...style }}>
    {lines.map((line, i) => {
      const span = 1 - stagger * (lines.length - 1);
      const local = (progress - i * stagger) / Math.max(0.001, span);
      return (
        <RevealLine key={line + i} progress={local} scale={scale} color={color} align={align}>
          {line}
        </RevealLine>
      );
    })}
  </div>
);

/** Small tracked-out label. Used for scene tags and structural annotations. */
export const MicroLabel: React.FC<{
  children: React.ReactNode;
  progress?: number;
  color?: string;
  style?: React.CSSProperties;
}> = ({ children, progress = 1, color = theme.colors.ink[9], style }) => {
  const p = cinematicEase(Math.max(0, Math.min(1, progress)));
  return (
    <span
      style={{
        ...styleFor('micro'),
        display: 'inline-block',
        textTransform: 'uppercase',
        color,
        opacity: p,
        transform: `translateY(${((1 - p) * 6).toFixed(2)}px)`,
        ...style,
      }}
    >
      {children}
    </span>
  );
};

/** Large numeric/stat treatment. */
export const Stat: React.FC<{
  value: string;
  caption?: string;
  progress?: number;
  color?: string;
}> = ({ value, caption, progress = 1, color = theme.colors.text.primary }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
    <RevealLine progress={progress} scale="numeric" color={color} trackingFrom={0.02}>
      {value}
    </RevealLine>
    {caption ? (
      <MicroLabel progress={Math.max(0, (progress - 0.3) / 0.7)}>{caption}</MicroLabel>
    ) : null}
  </div>
);

export const Caption: React.FC<{
  children: React.ReactNode;
  progress?: number;
  color?: string;
  maxWidth?: number;
  style?: React.CSSProperties;
}> = ({ children, progress = 1, color = theme.colors.ink[10], maxWidth = 560, style }) => {
  const p = cinematicEase(Math.max(0, Math.min(1, progress)));
  return (
    <p
      style={{
        ...styleFor('subhead'),
        color,
        maxWidth,
        opacity: p,
        transform: `translateY(${((1 - p) * 12).toFixed(2)}px)`,
        filter: p < 1 ? `blur(${((1 - p) * 3).toFixed(2)}px)` : undefined,
        ...style,
      }}
    >
      {children}
    </p>
  );
};
