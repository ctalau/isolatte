import React, { useMemo } from 'react';
import { useCurrentFrame } from 'remotion';
import { theme } from '../../theme/contentFusion';
import { Background } from '../../components/effects/Backgrounds';
import { SpatialUI } from '../../components/spatial/SpatialContext';
import { UIPlane } from '../../components/spatial/UIPlane';
import { Headline } from '../../components/typography/Type';
import { cameraShot, evaluateShot } from '../../three/camera';
import { cinematicEase, objectMerge, softLanding } from '../../motion/easing';
import { mix, ramp } from '../../motion/interpolation';
import { headlines } from '../../film/narration';

const c = theme.colors;
const t = theme.typography;

const CARD_W = 396;
const CARD_H = 210;

/**
 * SCENE 08 — LOCALIZATION
 *
 * One card divides into language layers, fans through depth, and recombines.
 * No globe, no flags, no map — the only localization signal is the language
 * code and the text itself, which is the honest signal.
 */

const localized = [
  { code: 'EN', title: 'Configure single sign-on', body: 'Connect your identity provider so members sign in with your organization credentials.' },
  { code: 'DE', title: 'Single Sign-on konfigurieren', body: 'Verbinden Sie Ihren Identitätsanbieter, damit sich Mitglieder mit Ihren Unternehmensdaten anmelden.' },
  { code: 'FR', title: 'Configurer l’authentification unique', body: 'Connectez votre fournisseur d’identité pour que les membres se connectent avec vos identifiants.' },
  { code: 'JA', title: 'シングルサインオンの設定', body: 'ID プロバイダーを接続すると、メンバーは組織の資格情報でサインインできます。' },
  { code: 'ES', title: 'Configurar el inicio de sesión único', body: 'Conecte su proveedor de identidad para que los miembros inicien sesión con sus credenciales.' },
  { code: 'RO', title: 'Configurarea autentificării unice', body: 'Conectați furnizorul de identitate pentru ca membrii să se autentifice cu datele organizației.' },
];

export const Localization: React.FC<{ durationInFrames: number }> = ({ durationInFrames }) => {
  const f = useCurrentFrame();

  const shot = useMemo(
    () =>
      cameraShot({
        id: 'localization',
        durationInFrames,
        keyframes: [
          { at: 0, position: [1.5, 0, 7.4], target: [1.55, 0, 0], fov: 31, focusZ: 0.1, aperture: 0.5 },
          {
            // A few degrees of orbit is all the fan needs to become legible.
            at: 0.55,
            position: [0.62, 0.28, 7.1],
            target: [0.9, 0.02, -0.2],
            fov: 32,
            focusZ: 0.1,
            aperture: 0.75,
            easing: cinematicEase,
          },
          {
            at: 1,
            position: [0.55, 0.05, 7.5],
            target: [0.75, 0.0, 0],
            fov: 31,
            focusZ: 0.08,
            aperture: 0.4,
            easing: softLanding,
          },
        ],
        handheld: { amount: 0.012, seed: 22 },
      }),
    [durationInFrames],
  );

  const camera = evaluateShot(shot, f);

  const fan = ramp(f, 16, 76, cinematicEase);
  const recombine = ramp(f, durationInFrames - 54, durationInFrames - 10, objectMerge);
  const spread = fan * (1 - recombine);

  const headlineProgress = ramp(f, 60, 112, cinematicEase);
  const headlineOut = 1 - ramp(f, durationInFrames - 30, durationInFrames - 8, cinematicEase);

  return (
    <div style={{ position: 'absolute', inset: 0 }}>
      <Background name="midnight" />

      <SpatialUI camera={camera} depthCue={0.16}>
        {localized.map((l, i) => {
          const appear = ramp(f, 6 + i * 5, 34 + i * 5, cinematicEase);
          // A down-right cascade rather than a symmetric fan: every card keeps
          // its top-left corner visible, which is where the language code and
          // the title live. The group sits right of centre so the headline owns
          // the lower left without a scrim.
          return (
            <UIPlane
              key={l.code}
              // Cascade up-and-left from the front card: each card behind keeps
              // its own top-left corner clear, which is where the language code
              // and the title sit.
              x={mix(1.5, 2.35 - i * 0.42, spread)}
              y={mix(0, -0.55 + i * 0.28, spread)}
              z={mix(0, 0.8 - i * 0.3, spread)}
              rotationY={mix(0, -6.5, spread)}
              rotationX={mix(0, 1.6, spread)}
              scale={mix(1, 0.98, spread)}
              opacity={appear * mix(1, 1 - i * 0.03, spread)}
              width={CARD_W}
              height={CARD_H}
            >
              <div
                style={{
                  width: CARD_W,
                  height: CARD_H,
                  padding: '18px 22px',
                  borderRadius: theme.radii.lg,
                  background: `linear-gradient(158deg, rgba(255,255,255,0.055) 0%, rgba(255,255,255,0.012) 100%), rgba(18,22,30,0.96)`,
                  border: `1px solid ${i === 0 ? 'rgba(91,140,255,0.3)' : c.stroke.hairline}`,
                  boxShadow: theme.shadows.card,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 12,
                }}
              >
                <span
                  style={{
                    fontFamily: t.mono,
                    fontSize: 10,
                    letterSpacing: '0.16em',
                    color: i === 0 ? c.accent : c.ink[8],
                  }}
                >
                  {l.code}
                </span>
                <span
                  style={{
                    fontFamily: t.display,
                    fontSize: 19,
                    fontWeight: 555,
                    letterSpacing: '-0.014em',
                    lineHeight: 1.22,
                    color: c.text.primary,
                  }}
                >
                  {l.title}
                </span>
                <span
                  style={{
                    fontFamily: t.body,
                    fontSize: 13,
                    lineHeight: 1.55,
                    color: c.ink[10],
                  }}
                >
                  {l.body}
                </span>
              </div>
            </UIPlane>
          );
        })}
      </SpatialUI>

      <div style={{ position: 'absolute', left: 148, bottom: 116, opacity: headlineOut }}>
        <Headline lines={[...headlines.localization]} progress={headlineProgress} scale="display" />
      </div>
    </div>
  );
};
