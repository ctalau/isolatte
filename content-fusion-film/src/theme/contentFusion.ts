/**
 * Content Fusion — central brand + motion theme.
 *
 * Every visual constant used by the film lives here. Scenes must not invent
 * their own colours, radii or shadow recipes; if a scene needs a new value it
 * belongs in this file so the whole film moves together.
 *
 * The palette is deliberately monochrome-with-one-accent. Premium product film
 * gets its richness from light, depth and typography — not from hue variety.
 */

/** Neutral ramp, cool-shifted. 0 = deepest background, 12 = pure highlight. */
const ink = {
  0: '#06070A',
  1: '#0A0C11',
  2: '#0E1117',
  3: '#13171F',
  4: '#191E28',
  5: '#212734',
  6: '#2C3342',
  7: '#3B4354',
  8: '#525C70',
  9: '#727D92',
  10: '#9BA5B7',
  11: '#C7CEDA',
  12: '#F2F5FA',
} as const;

/** Light ("cloud") ramp for the bright environment variant. */
const paper = {
  0: '#FFFFFF',
  1: '#FBFCFE',
  2: '#F4F6FA',
  3: '#EBEFF5',
  4: '#DFE5EE',
  5: '#CBD3E0',
  6: '#AAB4C4',
  7: '#7C8697',
  8: '#525B6B',
  9: '#333B48',
  10: '#1A2029',
} as const;

export const contentFusionTheme = {
  colors: {
    ink,
    paper,

    /** Single brand accent. Calm, slightly cool blue — never neon. */
    accent: '#5B8CFF',
    accentDim: '#3A5FB8',
    accentGlow: 'rgba(91, 140, 255, 0.28)',

    /**
     * Secondary accent, used *only* for human-in-the-loop moments
     * (approval, governance). Warm so it reads as "a person did this".
     */
    human: '#E8B473',
    humanDim: '#8A6A44',

    /** Semantic content-model colours for structure/taxonomy overlays. */
    structure: {
      title: '#5B8CFF',
      metadata: '#9BA5B7',
      block: '#C7CEDA',
      reusable: '#7FD1C0',
      taxonomy: '#B79BE8',
    },

    text: {
      primary: ink[12],
      secondary: ink[10],
      tertiary: ink[9],
      onLight: paper[10],
      onLightSecondary: paper[8],
    },

    stroke: {
      hairline: 'rgba(255,255,255,0.06)',
      soft: 'rgba(255,255,255,0.10)',
      strong: 'rgba(255,255,255,0.18)',
      accent: 'rgba(91,140,255,0.45)',
    },

    /**
     * The reconstructed app surface. Modelled on the real Content Fusion
     * review UI (light workspace, blue actions/links, amber callouts) so the
     * on-screen product reads as the actual app rather than an art-directed
     * dark reskin — even though the film's cinematic backgrounds around it
     * stay on the dark `ink` palette.
     */
    ui: {
      canvas: paper[1],
      surface: paper[0],
      surfaceRaised: paper[0],
      sidebar: paper[2],
      panel: '#FFFFFF',
      border: paper[4],
      borderStrong: paper[5],
      textPrimary: paper[10],
      textSecondary: paper[8],
      textTertiary: paper[7],
      accent: '#1656D6',
      accentHover: '#0F45B3',
      accentSoft: 'rgba(22,86,214,0.08)',
      accentSoftStrong: 'rgba(22,86,214,0.14)',
      diffRemovedBg: '#EAF1FB',
      diffRemovedBorder: '#CBDCF3',
      diffAddedBg: '#E7F6F3',
      diffAddedBorder: '#BFE7DE',
      calloutBg: '#F3F2DE',
      calloutBorder: '#E4E1B8',
      calloutIcon: '#E08A1E',
      brandMark: '#EC5B24',
    },
  },

  typography: {
    /** Loaded locally from @fontsource so renders are network-independent. */
    display: "'Inter Variable', 'Inter', -apple-system, system-ui, sans-serif",
    body: "'Inter Variable', 'Inter', -apple-system, system-ui, sans-serif",
    mono: "'JetBrains Mono', ui-monospace, 'SF Mono', Menlo, monospace",

    /**
     * Sizes are authored for the 1920×1080 design space and scaled up by the
     * composition. Tracking values are the expensive part: display type gets
     * negative tracking, micro-labels get wide positive tracking.
     */
    scale: {
      display: { size: 96, weight: 560, tracking: -0.034, leading: 1.02 },
      headline: { size: 62, weight: 560, tracking: -0.026, leading: 1.08 },
      title: { size: 34, weight: 560, tracking: -0.018, leading: 1.15 },
      subhead: { size: 24, weight: 480, tracking: -0.01, leading: 1.35 },
      body: { size: 17, weight: 420, tracking: -0.002, leading: 1.55 },
      caption: { size: 14, weight: 460, tracking: 0.004, leading: 1.4 },
      micro: { size: 11, weight: 560, tracking: 0.14, leading: 1.2 },
      numeric: { size: 72, weight: 500, tracking: -0.03, leading: 1 },
    },
  },

  spacing: (n: number) => n * 8,

  radii: {
    xs: 4,
    sm: 8,
    md: 12,
    lg: 18,
    xl: 26,
    window: 14,
    pill: 999,
  },

  /**
   * Shadows are physically motivated: one tight contact shadow plus one wide
   * ambient shadow. Depth multiplies the ambient blur, never the contact one.
   */
  shadows: {
    contact: '0 1px 2px rgba(0,0,0,0.45)',
    card: '0 2px 6px rgba(0,0,0,0.35), 0 18px 44px rgba(0,0,0,0.42)',
    panel: '0 3px 10px rgba(0,0,0,0.4), 0 40px 90px rgba(0,0,0,0.55)',
    window: '0 6px 18px rgba(0,0,0,0.42), 0 70px 160px rgba(0,0,0,0.62)',
    lifted: '0 8px 24px rgba(0,0,0,0.48), 0 90px 200px rgba(0,0,0,0.7)',
  },

  gradients: {
    /** Very low-contrast field; the movement should be almost subliminal. */
    midnightField:
      'radial-gradient(120% 90% at 50% 8%, #1A2130 0%, #0D1016 46%, #06070A 100%)',
    cloudField:
      'radial-gradient(110% 85% at 50% 0%, #FFFFFF 0%, #F2F5FA 52%, #E4E9F1 100%)',
    stage:
      'radial-gradient(70% 55% at 50% 42%, rgba(91,140,255,0.10) 0%, rgba(91,140,255,0) 70%)',
    glassSurface:
      'linear-gradient(158deg, rgba(255,255,255,0.075) 0%, rgba(255,255,255,0.022) 38%, rgba(255,255,255,0.008) 100%)',
    edgeSheen:
      'linear-gradient(100deg, rgba(255,255,255,0) 38%, rgba(255,255,255,0.16) 50%, rgba(255,255,255,0) 62%)',
  },

  motion: {
    /** Frames, at 30fps. Named so scene code never hardcodes durations. */
    beat: 9,
    phrase: 24,
    section: 60,
    /** Standard entrance stagger between sibling elements. */
    stagger: 4,
    /** Spring presets — critically damped, no cartoon bounce. */
    springs: {
      settle: { damping: 200, mass: 0.9, stiffness: 88 },
      lift: { damping: 26, mass: 0.55, stiffness: 120 },
      snap: { damping: 30, mass: 0.4, stiffness: 220 },
    },
  },

  /**
   * Canonical Z language, in world units. The camera lives around z = 6–8, so
   * these offsets read as depth without ever tipping into a "3D website" look.
   */
  depth: {
    backgroundAtmosphere: -4,
    ambientContent: -2,
    productWindow: 0,
    mainContent: 0.05,
    navigation: 0.08,
    activeObject: 0.18,
    aiPanel: 0.25,
    focusedCard: 0.4,
    foreground: 1.6,
  },
} as const;

export type ContentFusionTheme = typeof contentFusionTheme;
export const theme = contentFusionTheme;
