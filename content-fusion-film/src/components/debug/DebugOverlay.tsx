import React from 'react';
import { useCurrentFrame, useVideoConfig } from 'remotion';
import { theme } from '../../theme/contentFusion';
import type { CameraState } from '../../three/camera';
import { scenes, sceneStarts } from '../../film/contentFusionFilm';

const mono: React.CSSProperties = {
  fontFamily: theme.typography.mono,
  fontSize: 13,
  color: '#8CF5C0',
  lineHeight: 1.5,
};

/**
 * Development HUD. Never enabled in a final render — the master compositions
 * pass `debug={false}` and the studio-only compositions pass `debug`.
 */
export const DebugOverlay: React.FC<{
  camera?: CameraState;
  safeAreas?: boolean;
  depthGuides?: boolean;
}> = ({ camera, safeAreas = true, depthGuides = false }) => {
  const frame = useCurrentFrame();
  const { fps, width, height } = useVideoConfig();

  const index = sceneStarts.findIndex(
    (start, i) => frame >= start && frame < start + (scenes[i]?.durationInFrames ?? 0),
  );
  const scene = index >= 0 ? scenes[index] : undefined;
  const localFrame = index >= 0 ? frame - (sceneStarts[index] ?? 0) : frame;

  return (
    <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none' }}>
      {safeAreas ? (
        <>
          {/* Title-safe (90%) and subtitle band. */}
          <div
            style={{
              position: 'absolute',
              left: '5%',
              top: '5%',
              width: '90%',
              height: '90%',
              border: '1px solid rgba(140,245,192,0.28)',
            }}
          />
          <div
            style={{
              position: 'absolute',
              left: '12%',
              right: '12%',
              bottom: '7%',
              height: '11%',
              border: '1px dashed rgba(255,196,120,0.35)',
            }}
          />
        </>
      ) : null}

      {depthGuides ? (
        <div
          style={{
            position: 'absolute',
            left: 0,
            right: 0,
            top: '50%',
            height: 1,
            background: 'rgba(140,245,192,0.2)',
          }}
        />
      ) : null}

      <div
        style={{
          position: 'absolute',
          left: 24,
          top: 24,
          padding: '12px 16px',
          borderRadius: 8,
          background: 'rgba(0,0,0,0.72)',
          border: '1px solid rgba(140,245,192,0.3)',
          ...mono,
        }}
      >
        <div>frame {frame} / {(frame / fps).toFixed(2)}s</div>
        <div>res {width}×{height}</div>
        <div>scene {scene ? `${index + 1} ${scene.id}` : '—'}</div>
        <div>local {localFrame} / {scene?.durationInFrames ?? '—'}</div>
        {camera ? (
          <>
            <div>
              cam [{camera.position.map((v) => v.toFixed(2)).join(', ')}]
            </div>
            <div>
              tgt [{camera.target.map((v) => v.toFixed(2)).join(', ')}]
            </div>
            <div>
              fov {camera.fov.toFixed(1)}  focusZ {camera.focusZ.toFixed(2)}  ap{' '}
              {camera.aperture.toFixed(2)}
            </div>
          </>
        ) : null}
      </div>
    </div>
  );
};
