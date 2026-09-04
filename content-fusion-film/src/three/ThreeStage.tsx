import React, { useMemo } from 'react';
import { ThreeCanvas } from '@remotion/three';
import { useVideoConfig } from 'remotion';
import * as THREE from 'three';
import type { CameraState } from './camera';

/**
 * Remotion ↔ React Three Fiber integration.
 *
 * @remotion/three's ThreeCanvas replaces R3F's requestAnimationFrame loop with
 * a frame-locked one, so every draw is a pure function of Remotion's current
 * frame — which is what makes 3D scenes deterministic and safe to render in
 * parallel across machines.
 *
 * DPR is pinned to 1 because the composition already renders at 4K; letting R3F
 * pick a device pixel ratio would multiply that again for no visible gain.
 */
export const ThreeStage: React.FC<{
  camera: CameraState;
  children: React.ReactNode;
  background?: string;
}> = ({ camera, children, background }) => {
  const { width, height } = useVideoConfig();

  return (
    <ThreeCanvas
      width={width}
      height={height}
      dpr={1}
      gl={{ antialias: true, alpha: true, powerPreference: 'high-performance' }}
      onCreated={({ gl }) => {
        gl.toneMapping = THREE.ACESFilmicToneMapping;
        // Slightly under 1 so highlights on UI surfaces never clip to white.
        gl.toneMappingExposure = 0.94;
        gl.outputColorSpace = THREE.SRGBColorSpace;
      }}
      style={{ position: 'absolute', inset: 0, background: background ?? 'transparent' }}
    >
      <CameraRig camera={camera} />
      <LightingRig />
      {children}
    </ThreeCanvas>
  );
};

/**
 * Drives a real PerspectiveCamera from the shared camera state, so a 3D scene
 * and a 2.5D scene describe their moves in exactly the same vocabulary.
 */
export const CameraRig: React.FC<{ camera: CameraState }> = ({ camera }) => {
  const { width, height } = useVideoConfig();

  const cam = useMemo(() => new THREE.PerspectiveCamera(camera.fov, width / height, 0.1, 200), [
    width,
    height,
    camera.fov,
  ]);

  cam.fov = camera.fov;
  cam.aspect = width / height;
  cam.position.set(camera.position[0], camera.position[1], camera.position[2]);
  cam.up.set(0, 1, 0);
  cam.lookAt(camera.target[0], camera.target[1], camera.target[2]);
  // Roll is applied after lookAt, around the camera's own view axis.
  if (camera.roll !== 0) cam.rotateZ((camera.roll * Math.PI) / 180);
  cam.updateProjectionMatrix();

  return <primitive object={cam} attach="camera" />;
};

/**
 * Soft studio lighting — product photography, not a game.
 *
 * One large key from above-front-left, a broad cool fill from below-right so
 * shadowed faces do not go black, and a tight rim from behind to separate the
 * subject from the background. No point lights, no specular hotspots.
 */
export const LightingRig: React.FC<{ intensity?: number }> = ({ intensity = 1 }) => (
  <>
    <ambientLight intensity={0.55 * intensity} color="#9FB3D9" />
    {/* Key: a large rectangular source reads as a softbox on flat UI planes. */}
    <directionalLight
      position={[-5, 6.5, 7]}
      intensity={1.5 * intensity}
      color="#EAF0FF"
    />
    {/* Fill: cool, weak, from the opposite side. */}
    <directionalLight position={[6, -3, 4]} intensity={0.42 * intensity} color="#6E86C0" />
    {/* Rim: behind and above, brand-tinted, to catch card edges. */}
    <directionalLight position={[2, 4, -8]} intensity={0.85 * intensity} color="#5B8CFF" />
    <hemisphereLight args={['#26324A', '#05070B', 0.5 * intensity]} />
  </>
);
