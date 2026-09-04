import React from 'react';
import { useCurrentFrame } from 'remotion';
import { theme } from '../../theme/contentFusion';
import { Background } from '../../components/effects/Backgrounds';
import { ProductMark } from '../../components/ui/ProductWindow';
import { RevealLine } from '../../components/typography/Type';
import { cinematicEase, softLanding } from '../../motion/easing';
import { ramp } from '../../motion/interpolation';

/**
 * SCENE 11 — END FRAME
 *
 * Mark, one line, one call to action. Everything else is removed. The only
 * motion is the mark settling and the type resolving; the frame then holds
 * completely still, which is what makes it read as a signature.
 */
export const EndFrame: React.FC<{ durationInFrames: number }> = ({ durationInFrames }) => {
  const f = useCurrentFrame();

  const markIn = ramp(f, 6, 40, softLanding);
  const lineIn = ramp(f, 24, 72, cinematicEase);
  const ctaIn = ramp(f, 48, 92, cinematicEase);
  const out = 1 - ramp(f, durationInFrames - 14, durationInFrames, cinematicEase);

  return (
    <div style={{ position: 'absolute', inset: 0, opacity: out }}>
      <Background name="midnight" intensity={0.5} />

      <div
        style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 34,
        }}
      >
        <div
          style={{
            opacity: markIn,
            transform: `translateY(${((1 - markIn) * 14).toFixed(2)}px) scale(${(0.96 + 0.04 * markIn).toFixed(4)})`,
          }}
        >
          <ProductMark size={72} />
        </div>

        <RevealLine progress={lineIn} scale="display" align="center">
          Content Fusion
        </RevealLine>

        <div
          style={{
            opacity: ctaIn,
            transform: `translateY(${((1 - ctaIn) * 10).toFixed(2)}px)`,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: 22,
          }}
        >
          <span
            style={{
              fontFamily: theme.typography.body,
              fontSize: 22,
              fontWeight: 440,
              letterSpacing: '-0.008em',
              color: theme.colors.ink[10],
            }}
          >
            The intelligent content layer.
          </span>
          <span
            style={{
              fontFamily: theme.typography.mono,
              fontSize: 12,
              letterSpacing: '0.16em',
              textTransform: 'uppercase',
              color: theme.colors.accent,
              padding: '11px 22px',
              borderRadius: theme.radii.pill,
              border: `1px solid rgba(91,140,255,0.34)`,
            }}
          >
            {/* PLACEHOLDER — replace with the approved call to action + URL. */}
            See it in your content
          </span>
        </div>
      </div>
    </div>
  );
};
