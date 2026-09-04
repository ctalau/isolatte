import * as THREE from 'three';
import { theme } from '../theme/contentFusion';

/**
 * UI-as-texture (product representation "Mode 4").
 *
 * The 3D scenes need real UI on their surfaces, but troika/drei text pipelines
 * cannot use the project's variable web font, and a WebGL text renderer would
 * not match the DOM scenes typographically. So the 3D scenes draw their cards
 * into a 2D canvas — using the *same* loaded Inter face — and map that canvas
 * onto a plane. The result is pixel-identical typography across both renderers.
 *
 * Textures are cached by cache key and disposed by three when the scene tears
 * down; they are drawn once, not per frame, which is what keeps 4K viable.
 */

const cache = new Map<string, THREE.CanvasTexture>();

/** Device-pixel scale for texture rendering. 2 is enough at our card sizes. */
const TEX_SCALE = 2;

const roundRect = (
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  w: number,
  h: number,
  r: number,
) => {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
};

export type CardSpec = {
  key: string;
  width: number;
  height: number;
  title: string;
  subtitle?: string;
  /** Accent stripe colour; also tints the card's border. */
  accent?: string;
  /** Number of placeholder content rules drawn under the title. */
  rules?: number;
  kind?: 'channel' | 'document' | 'component';
};

export const cardTexture = (spec: CardSpec): THREE.CanvasTexture => {
  const existing = cache.get(spec.key);
  if (existing) return existing;

  const c = theme.colors;
  const w = spec.width;
  const h = spec.height;
  const canvas = document.createElement('canvas');
  canvas.width = w * TEX_SCALE;
  canvas.height = h * TEX_SCALE;
  const ctx = canvas.getContext('2d');
  if (!ctx) throw new Error('2D context unavailable for card texture');
  ctx.scale(TEX_SCALE, TEX_SCALE);

  const accent = spec.accent ?? c.accent;

  // Surface: vertical falloff matching the DOM scenes' key light.
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, '#242C3A');
  grad.addColorStop(1, '#151A23');
  ctx.fillStyle = grad;
  roundRect(ctx, 0.5, 0.5, w - 1, h - 1, 14);
  ctx.fill();

  ctx.strokeStyle = 'rgba(255,255,255,0.11)';
  ctx.lineWidth = 1;
  ctx.stroke();

  // Accent stripe: short, top-left, never a full-width band.
  ctx.fillStyle = accent;
  roundRect(ctx, 22, 22, 26, 3, 1.5);
  ctx.fill();

  ctx.fillStyle = c.text.primary;
  ctx.font = `560 ${Math.round(h * 0.105)}px "Inter Variable", Inter, sans-serif`;
  ctx.textBaseline = 'alphabetic';
  ctx.fillText(spec.title, 22, 22 + h * 0.155);

  if (spec.subtitle) {
    ctx.fillStyle = c.ink[9];
    ctx.font = `420 ${Math.round(h * 0.072)}px "Inter Variable", Inter, sans-serif`;
    ctx.fillText(spec.subtitle, 22, 22 + h * 0.26);
  }

  const rules = spec.rules ?? 4;
  const top = 22 + h * (spec.subtitle ? 0.36 : 0.27);
  for (let i = 0; i < rules; i++) {
    const rowW = (w - 44) * [0.94, 0.78, 0.86, 0.52, 0.7, 0.4][i % 6]!;
    ctx.fillStyle = `rgba(199,206,218,${0.2 - i * 0.018})`;
    roundRect(ctx, 22, top + i * (h * 0.082), rowW, 4, 2);
    ctx.fill();
  }

  const texture = new THREE.CanvasTexture(canvas);
  texture.anisotropy = 8;
  texture.colorSpace = THREE.SRGBColorSpace;
  texture.needsUpdate = true;
  cache.set(spec.key, texture);
  return texture;
};

/** Frees every cached texture. Called when a 3D scene unmounts. */
export const disposeCardTextures = () => {
  cache.forEach((t) => t.dispose());
  cache.clear();
};
