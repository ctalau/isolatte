import React from 'react';
import { theme } from '../../theme/contentFusion';
import { cinematicEase } from '../../motion/easing';

/**
 * A human cursor. Present only when a person is acting — the film uses it to
 * make the "human is in control" moments legible.
 */
export const Cursor: React.FC<{ x: number; y: number; opacity?: number; scale?: number }> = ({
  x,
  y,
  opacity = 1,
  scale = 1,
}) => (
  <svg
    width={26}
    height={30}
    viewBox="0 0 26 30"
    fill="none"
    style={{
      position: 'absolute',
      left: x,
      top: y,
      opacity,
      transform: `scale(${scale})`,
      transformOrigin: '4px 3px',
      filter: 'drop-shadow(0 3px 7px rgba(0,0,0,0.6))',
      pointerEvents: 'none',
    }}
  >
    <path
      d="M4 2.4 18.6 14.2l-6.6.85 3.6 7.9-2.9 1.35-3.6-7.9-4.1 4.6z"
      fill="#F6F8FC"
      stroke="rgba(10,13,20,0.55)"
      strokeWidth={1.1}
      strokeLinejoin="round"
    />
  </svg>
);

/**
 * Click feedback: one expanding ring plus a short-lived fill.
 * `progress` is 0..1 and is always frame-derived.
 */
export const ClickPulse: React.FC<{
  x: number;
  y: number;
  progress: number;
  color?: string;
  size?: number;
}> = ({ x, y, progress, color = theme.colors.human, size = 54 }) => {
  if (progress <= 0 || progress >= 1) return null;
  const e = cinematicEase(progress);
  const r = size * (0.24 + e * 0.76);
  const alpha = (1 - progress) * 0.55;
  return (
    <div
      style={{
        position: 'absolute',
        left: x - r / 2,
        top: y - r / 2,
        width: r,
        height: r,
        borderRadius: '50%',
        border: `1.5px solid ${color}`,
        opacity: alpha,
        pointerEvents: 'none',
      }}
    />
  );
};

/** Interpolates a cursor along a gentle arc so it never travels in a straight line. */
export const cursorArc = (
  from: readonly [number, number],
  to: readonly [number, number],
  t: number,
  bow = 0.18,
): [number, number] => {
  const e = cinematicEase(Math.max(0, Math.min(1, t)));
  const x = from[0] + (to[0] - from[0]) * e;
  const y = from[1] + (to[1] - from[1]) * e;
  // Perpendicular offset peaking at the middle of the move.
  const dx = to[0] - from[0];
  const dy = to[1] - from[1];
  const len = Math.hypot(dx, dy) || 1;
  const arc = Math.sin(e * Math.PI) * len * bow;
  return [x + (-dy / len) * arc, y + (dx / len) * arc];
};
