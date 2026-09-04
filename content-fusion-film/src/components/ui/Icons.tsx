import React from 'react';

/** Minimal 16px stroke icon set. Geometric, 1.4px stroke, no filled blobs. */
const base = (children: React.ReactNode, size: number, color: string, sw: number) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 16 16"
    fill="none"
    stroke={color}
    strokeWidth={sw}
    strokeLinecap="round"
    strokeLinejoin="round"
    style={{ display: 'block', flex: '0 0 auto' }}
  >
    {children}
  </svg>
);

export type IconProps = { size?: number; color?: string; strokeWidth?: number };

export const IconMap: React.FC<IconProps> = ({ size = 14, color = 'currentColor', strokeWidth = 1.35 }) =>
  base(
    <>
      <path d="M2.5 4.2 6 2.8l4 1.4 3.5-1.4v9L10 13.2l-4-1.4-3.5 1.4z" />
      <path d="M6 2.8v8.9M10 4.2v9" />
    </>,
    size,
    color,
    strokeWidth,
  );

export const IconTopic: React.FC<IconProps> = ({ size = 14, color = 'currentColor', strokeWidth = 1.35 }) =>
  base(
    <>
      <path d="M4 2.2h5l3 3v8.6H4z" />
      <path d="M9 2.2v3h3" />
      <path d="M6 8.6h4M6 10.9h2.6" />
    </>,
    size,
    color,
    strokeWidth,
  );

export const IconComponent: React.FC<IconProps> = ({ size = 14, color = 'currentColor', strokeWidth = 1.35 }) =>
  base(
    <>
      <rect x="2.6" y="2.6" width="4.6" height="4.6" rx="1" />
      <rect x="8.8" y="8.8" width="4.6" height="4.6" rx="1" />
      <path d="M7.2 4.9h3.2a1 1 0 0 1 1 1v2.9" />
    </>,
    size,
    color,
    strokeWidth,
  );

export const IconLibrary: React.FC<IconProps> = ({ size = 14, color = 'currentColor', strokeWidth = 1.35 }) =>
  base(
    <>
      <path d="M3 3.2v9.6M6 2.6v10.8M9.2 3.4l3.4 9.2" />
    </>,
    size,
    color,
    strokeWidth,
  );

export const IconSparkle: React.FC<IconProps> = ({ size = 14, color = 'currentColor', strokeWidth = 1.35 }) =>
  base(
    <>
      <path d="M8 2.2c.5 2.6 1.2 3.3 3.8 3.8-2.6.5-3.3 1.2-3.8 3.8-.5-2.6-1.2-3.3-3.8-3.8C6.8 5.5 7.5 4.8 8 2.2Z" />
      <path d="M12.2 10.4c.25 1.2.55 1.5 1.75 1.75-1.2.25-1.5.55-1.75 1.75-.25-1.2-.55-1.5-1.75-1.75 1.2-.25 1.5-.55 1.75-1.75Z" />
    </>,
    size,
    color,
    strokeWidth,
  );

export const IconCheck: React.FC<IconProps> = ({ size = 14, color = 'currentColor', strokeWidth = 1.6 }) =>
  base(<path d="M3.2 8.4 6.3 11.4 12.8 4.9" />, size, color, strokeWidth);

export const IconInfo: React.FC<IconProps> = ({ size = 14, color = 'currentColor', strokeWidth = 1.35 }) =>
  base(
    <>
      <circle cx="8" cy="8" r="5.8" />
      <path d="M8 7.2v3.6M8 5.2v.1" />
    </>,
    size,
    color,
    strokeWidth,
  );

export const IconGlobe: React.FC<IconProps> = ({ size = 14, color = 'currentColor', strokeWidth = 1.35 }) =>
  base(
    <>
      <circle cx="8" cy="8" r="5.8" />
      <path d="M2.4 8h11.2M8 2.2c1.6 1.8 2.4 3.8 2.4 5.8S9.6 12 8 13.8C6.4 12 5.6 10 5.6 8S6.4 4 8 2.2Z" />
    </>,
    size,
    color,
    strokeWidth,
  );

export const IconBranch: React.FC<IconProps> = ({ size = 14, color = 'currentColor', strokeWidth = 1.35 }) =>
  base(
    <>
      <circle cx="4.6" cy="3.8" r="1.6" />
      <circle cx="4.6" cy="12.2" r="1.6" />
      <circle cx="11.4" cy="8" r="1.6" />
      <path d="M4.6 5.4v5.2M6.2 3.8h2.4a1.2 1.2 0 0 1 1.2 1.2v1.5" />
    </>,
    size,
    color,
    strokeWidth,
  );
