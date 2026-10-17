import Svg, { Circle, Path, Rect } from 'react-native-svg';

/** Line icons drawn on a 24-unit grid, matching the website's icon set. */
const PATHS: Record<string, React.ReactNode> = {
  link: <><Path d="M10 14a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1" /><Path d="M14 10a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1" /></>,
  globe: <><Circle cx="12" cy="12" r="9" /><Path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" /></>,
  qr: <><Rect x="4" y="4" width="6" height="6" rx="1" /><Rect x="14" y="4" width="6" height="6" rx="1" /><Rect x="4" y="14" width="6" height="6" rx="1" /><Path d="M14 14h2v2h-2zM18 18h2v2h-2zM14 18h2" /></>,
  mail: <><Rect x="3" y="5" width="18" height="14" rx="2" /><Path d="m3 7 9 6 9-6" /></>,
  key: <><Circle cx="8" cy="15" r="4" /><Path d="m11 12 8-8M16 7l3 3" /></>,
  file: <><Path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" /><Path d="M14 3v5h5" /></>,
  server: <><Rect x="4" y="4" width="16" height="7" rx="2" /><Rect x="4" y="13" width="16" height="7" rx="2" /><Path d="M8 8h.01M8 17h.01" /></>,
  search: <><Circle cx="11" cy="11" r="7" /><Path d="m20 20-4-4" /></>,
  layers: <><Path d="m12 3 9 5-9 5-9-5z" /><Path d="m3 13 9 5 9-5" /></>,
  lock: <><Rect x="5" y="11" width="14" height="10" rx="2" /><Path d="M8 11V7a4 4 0 0 1 8 0v4" /></>,
  home: <Path d="M4 11 12 4l8 7v9h-5v-6H9v6H4z" />,
  clock: <><Circle cx="12" cy="12" r="9" /><Path d="M12 7v5l3 2" /></>,
  bolt: <Path d="M13 2 4 14h7l-1 8 9-12h-7z" />,
  spark: <Path d="M12 3l2 5.5L19.5 10 14 12l-2 5.5L10 12 4.5 10 10 8.5z" />,
  user: <><Circle cx="12" cy="8" r="4" /><Path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6" /></>,
  paste: <><Rect x="8" y="3" width="8" height="4" rx="1" /><Path d="M8 5H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2" /></>,
  check: <Path d="m5 12 5 5 9-10" />,
  alert: <><Path d="M12 3 2 20h20z" /><Path d="M12 10v4M12 17h.01" /></>,
  share: <><Path d="M12 3v12M7 8l5-5 5 5" /><Path d="M5 14v5a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-5" /></>,
  send: <Path d="M4 12 20 4l-6 16-3-7z" />,
  refresh: <><Path d="M20 11a8 8 0 1 0-2.3 5.7" /><Path d="M20 4v7h-7" /></>,
  back: <Path d="m15 5-7 7 7 7" />,
  chevron: <Path d="m9 5 7 7-7 7" />,
  logout: <><Path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3" /><Path d="M10 17l-5-5 5-5M5 12h11" /></>,
  trash: <><Path d="M4 7h16M10 11v6M14 11v6" /><Path d="M6 7l1 13h10l1-13M9 7V4h6v3" /></>,
  shield: <Path d="M12 3 5 6v6c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V6z" />,
  doc: <><Path d="M7 3h7l5 5v13H7z" /><Path d="M10 13h6M10 17h6" /></>,
  close: <Path d="M6 6l12 12M18 6 6 18" />,
  external: <><Path d="M14 4h6v6M20 4l-9 9" /><Path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" /></>,
};

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 22, color = '#67e8f9', stroke = 2 }: { name: IconName; size?: number; color?: string; stroke?: number }) {
  return (
    <Svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth={stroke} strokeLinecap="round" strokeLinejoin="round">
      {PATHS[name]}
    </Svg>
  );
}
