import React, { useMemo } from 'react';
import * as THREE from 'three';
import { cardTexture, type CardSpec } from './textures';

/**
 * A UI card as a physical object.
 *
 * Materials follow the brief's restraint: no metalness, no mirror, mid-high
 * roughness with a whisper of clearcoat so edges catch the rim light the way a
 * coated display would. Geometry and material are memoised and shared across
 * instances of the same size, which is what keeps a 4K frame affordable.
 */

const geometryCache = new Map<string, THREE.PlaneGeometry>();

const sharedPlane = (w: number, h: number): THREE.PlaneGeometry => {
  const key = `${w}x${h}`;
  const existing = geometryCache.get(key);
  if (existing) return existing;
  const g = new THREE.PlaneGeometry(w, h);
  geometryCache.set(key, g);
  return g;
};

export const SpatialCard: React.FC<{
  spec: CardSpec;
  /** World size of the card. Aspect should match spec.width/height. */
  size: [number, number];
  position: [number, number, number];
  rotation?: [number, number, number];
  opacity?: number;
  scale?: number;
}> = ({ spec, size, position, rotation = [0, 0, 0], opacity = 1, scale = 1 }) => {
  const texture = useMemo(() => cardTexture(spec), [spec]);
  const geometry = useMemo(() => sharedPlane(size[0], size[1]), [size]);

  return (
    <mesh position={position} rotation={rotation} scale={scale} geometry={geometry}>
      {/*
        UI surfaces are emissive as well as lit. A purely lit material would
        render the authored card art at whatever the key light happens to
        deliver, and dark UI on a dark stage disappears. Feeding the same
        texture to `emissiveMap` holds the card at its authored luminance while
        the lit component still supplies edge falloff and the rim highlight —
        the surface behaves like a display, not like painted card.
      */}
      <meshPhysicalMaterial
        map={texture}
        emissive="#ffffff"
        emissiveMap={texture}
        emissiveIntensity={0.82}
        transparent
        opacity={opacity}
        roughness={0.68}
        metalness={0}
        clearcoat={0.08}
        clearcoatRoughness={0.6}
        side={THREE.FrontSide}
        depthWrite={opacity > 0.98}
      />
    </mesh>
  );
};

/**
 * A soft ground shadow under a card. A blurred radial sprite rather than a real
 * shadow map: shadow maps at 4K are expensive and, on flat planes lit by a
 * softbox, visually indistinguishable from this.
 */
export const CardShadow: React.FC<{
  position: [number, number, number];
  size: [number, number];
  opacity?: number;
}> = ({ position, size, opacity = 0.5 }) => {
  const texture = useMemo(() => {
    const canvas = document.createElement('canvas');
    canvas.width = 128;
    canvas.height = 128;
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('2D context unavailable for shadow sprite');
    const g = ctx.createRadialGradient(64, 64, 0, 64, 64, 64);
    g.addColorStop(0, 'rgba(0,0,0,0.85)');
    g.addColorStop(0.55, 'rgba(0,0,0,0.28)');
    g.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, 128, 128);
    const t = new THREE.CanvasTexture(canvas);
    t.colorSpace = THREE.SRGBColorSpace;
    return t;
  }, []);

  return (
    <mesh position={position} rotation={[0, 0, 0]}>
      <planeGeometry args={size} />
      <meshBasicMaterial map={texture} transparent opacity={opacity} depthWrite={false} />
    </mesh>
  );
};

/**
 * A curved ribbon between two points in 3D — the routing element for the
 * publishing and hero-system shots. Built as a tube around a quadratic bezier
 * so it reads as a considered path, not a graph edge.
 */
export const RoutingRibbon: React.FC<{
  from: [number, number, number];
  to: [number, number, number];
  /** 0..1 — how much of the path is drawn. */
  progress: number;
  color?: string;
  radius?: number;
  /** Perpendicular bow of the control point, in world units. */
  bow?: number;
  opacity?: number;
}> = ({ from, to, progress, color = '#5B8CFF', radius = 0.012, bow = 0.9, opacity = 0.9 }) => {
  const curve = useMemo(() => {
    const a = new THREE.Vector3(...from);
    const b = new THREE.Vector3(...to);
    const mid = a.clone().add(b).multiplyScalar(0.5);
    // Bow the control point away from the world origin so ribbons splay
    // outward instead of crossing through the centre of the composition.
    const outward = mid.clone().normalize().multiplyScalar(bow);
    mid.add(new THREE.Vector3(outward.x, outward.y + bow * 0.35, outward.z * 0.4));
    return new THREE.QuadraticBezierCurve3(a, mid, b);
  }, [from, to, bow]);

  const clamped = Math.max(0.001, Math.min(1, progress));
  const geometry = useMemo(() => {
    const segments = Math.max(2, Math.round(48 * clamped));
    const points = curve.getPoints(96).slice(0, Math.max(2, Math.round(96 * clamped)));
    const partial = new THREE.CatmullRomCurve3(points);
    return new THREE.TubeGeometry(partial, segments, radius, 6, false);
  }, [curve, clamped, radius]);

  return (
    <mesh geometry={geometry}>
      <meshBasicMaterial color={color} transparent opacity={opacity} />
    </mesh>
  );
};
