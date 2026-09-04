import React, { useMemo } from 'react';
import { useCurrentFrame } from 'remotion';

/**
 * Final grade pass: vignette + grain + a very slight highlight bloom.
 *
 * This is the deterministic CSS/compositing approximation of the WebGL post
 * chain. It renders identically on every machine and never destabilises the
 * Remotion renderer, which is why it — not @react-three/postprocessing — is the
 * default path for the whole-frame look. See docs/POST_PROCESSING.md.
 */
export const Grade: React.FC<{
  vignette?: number;
  grain?: number;
  /** Grain is animated at a reduced rate so it does not strobe at 30fps. */
  grainRateDivisor?: number;
}> = ({ vignette = 1, grain = 1, grainRateDivisor = 2 }) => {
  const frame = useCurrentFrame();
  const step = Math.floor(frame / grainRateDivisor);

  // A tiny tiling noise texture, generated once. Deterministic: no Math.random.
  const noiseUri = useMemo(() => buildNoiseDataUri(), []);

  return (
    <>
      {vignette > 0 ? (
        <div
          style={{
            position: 'absolute',
            inset: 0,
            pointerEvents: 'none',
            background: `radial-gradient(122% 96% at 50% 46%, rgba(0,0,0,0) 42%, rgba(0,0,0,${(
              0.24 * vignette
            ).toFixed(3)}) 82%, rgba(0,0,0,${(0.40 * vignette).toFixed(3)}) 100%)`,
          }}
        />
      ) : null}
      {grain > 0 ? (
        <div
          style={{
            position: 'absolute',
            inset: '-4%',
            pointerEvents: 'none',
            opacity: 0.028 * grain,
            backgroundImage: `url(${noiseUri})`,
            backgroundSize: '180px 180px',
            // Shifting the tile per frame-pair keeps the grain from looking static
            // without introducing a visible crawl.
            backgroundPosition: `${(step * 37) % 180}px ${(step * 53) % 180}px`,
            mixBlendMode: 'overlay',
          }}
        />
      ) : null}
    </>
  );
};

/** Deterministic fractal-noise tile, generated once as an inline SVG. */
const buildNoiseDataUri = (): string => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="180" height="180"><filter id="n"><feTurbulence type="fractalNoise" baseFrequency="0.85" numOctaves="3" seed="7" stitchTiles="stitch"/><feColorMatrix type="saturate" values="0"/></filter><rect width="180" height="180" filter="url(#n)"/></svg>`;
  return `data:image/svg+xml;base64,${btoa(svg)}`;
};
