import React, { useMemo } from 'react';
import { theme } from '../../theme/contentFusion';
import { hashed } from '../../motion/interpolation';
import { cinematicEase } from '../../motion/easing';

const c = theme.colors;

/**
 * A curved connection between two points in the design plane.
 *
 * The curve is a quadratic bezier whose control point is offset perpendicular
 * to the chord — this is what makes the routing read as *considered* rather
 * than as a generic node-graph edge. `progress` draws the line on.
 */
export const ConnectionLine: React.FC<{
  from: readonly [number, number];
  to: readonly [number, number];
  progress?: number;
  bow?: number;
  color?: string;
  width?: number;
  opacity?: number;
  dashed?: boolean;
  /** Draws a travelling highlight along the path — used for data movement. */
  pulse?: number;
}> = ({
  from,
  to,
  progress = 1,
  bow = 0.22,
  color = c.stroke.accent,
  width = 1.4,
  opacity = 1,
  dashed = false,
  pulse,
}) => {
  const dx = to[0] - from[0];
  const dy = to[1] - from[1];
  const len = Math.hypot(dx, dy) || 1;
  const mx = from[0] + dx / 2 + (-dy / len) * len * bow;
  const my = from[1] + dy / 2 + (dx / len) * len * bow;
  const d = `M ${from[0]} ${from[1]} Q ${mx} ${my} ${to[0]} ${to[1]}`;

  // Approximate arc length for the draw-on dash trick.
  const approx = len * (1 + bow * bow * 1.6);
  const drawn = cinematicEase(Math.max(0, Math.min(1, progress)));

  return (
    <>
      <path
        d={d}
        fill="none"
        stroke={color}
        strokeWidth={width}
        strokeLinecap="round"
        opacity={opacity}
        strokeDasharray={dashed ? '3 7' : approx}
        strokeDashoffset={dashed ? 0 : approx * (1 - drawn)}
      />
      {pulse !== undefined && pulse > 0 && pulse < 1 ? (
        <circle r={2.6} fill={color} opacity={Math.sin(pulse * Math.PI)}>
          <animateMotion dur="0.001s" repeatCount="1" fill="freeze" keyPoints={`${pulse};${pulse}`} keyTimes="0;1" path={d} />
        </circle>
      ) : null}
    </>
  );
};

/**
 * Sparse information field. Small nodes at varied depth, used only to give the
 * empty regions of a wide shot some spatial texture. Never the subject.
 */
export const ParticleField: React.FC<{
  count?: number;
  seed?: number;
  width: number;
  height: number;
  frame: number;
  opacity?: number;
}> = ({ count = 34, seed = 5, width, height, frame, opacity = 1 }) => {
  const points = useMemo(
    () =>
      Array.from({ length: count }, (_, i) => ({
        x: hashed(seed, i * 2) * width,
        y: hashed(seed, i * 2 + 1) * height,
        r: 0.9 + hashed(seed, i * 5) * 1.5,
        // Each point drifts on its own slow, incommensurate cycle.
        speed: 0.12 + hashed(seed, i * 7) * 0.2,
        phase: hashed(seed, i * 11) * Math.PI * 2,
        alpha: 0.1 + hashed(seed, i * 13) * 0.24,
      })),
    [count, seed, width, height],
  );

  return (
    <svg
      width={width}
      height={height}
      style={{ position: 'absolute', left: 0, top: 0, pointerEvents: 'none', opacity }}
    >
      {points.map((p, i) => (
        <circle
          key={i}
          cx={p.x + Math.sin(frame * 0.008 * p.speed + p.phase) * 14}
          cy={p.y + Math.cos(frame * 0.006 * p.speed + p.phase) * 10}
          r={p.r}
          fill={c.ink[10]}
          opacity={p.alpha}
        />
      ))}
    </svg>
  );
};

/**
 * A thin flowing ribbon. Used for distribution and transformation, where a
 * straight arrow would look like an infographic.
 */
export const DataRibbon: React.FC<{
  from: readonly [number, number];
  to: readonly [number, number];
  progress: number;
  bow?: number;
  color?: string;
  thickness?: number;
}> = ({ from, to, progress, bow = 0.3, color = c.accent, thickness = 2.6 }) => {
  const dx = to[0] - from[0];
  const dy = to[1] - from[1];
  const len = Math.hypot(dx, dy) || 1;
  const mx = from[0] + dx / 2 + (-dy / len) * len * bow;
  const my = from[1] + dy / 2 + (dx / len) * len * bow;
  const d = `M ${from[0]} ${from[1]} Q ${mx} ${my} ${to[0]} ${to[1]}`;
  const approx = len * (1 + bow * bow * 1.6);
  const head = cinematicEase(Math.max(0, Math.min(1, progress)));
  // A short travelling segment, not a full drawn line: this reads as movement.
  const segment = approx * 0.22;

  return (
    <path
      d={d}
      fill="none"
      stroke={color}
      strokeWidth={thickness}
      strokeLinecap="round"
      opacity={Math.sin(Math.min(1, progress) * Math.PI) * 0.9}
      strokeDasharray={`${segment} ${approx}`}
      strokeDashoffset={approx * (1 - head) - segment * head}
    />
  );
};

/** Thin structural guide with a label — used in the Structure scene. */
export const StructureGuide: React.FC<{
  x: number;
  y: number;
  width: number;
  label: string;
  color: string;
  progress: number;
}> = ({ x, y, width, label, color, progress }) => {
  const p = cinematicEase(Math.max(0, Math.min(1, progress)));
  return (
    <div
      style={{
        position: 'absolute',
        left: x,
        top: y,
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        opacity: p,
        transform: `translateX(${((1 - p) * -14).toFixed(2)}px)`,
      }}
    >
      <div style={{ width: width * p, height: 1, background: color, opacity: 0.55 }} />
      <span
        style={{
          fontFamily: theme.typography.mono,
          fontSize: 10,
          letterSpacing: '0.13em',
          textTransform: 'uppercase',
          color,
          whiteSpace: 'nowrap',
        }}
      >
        {label}
      </span>
    </div>
  );
};
