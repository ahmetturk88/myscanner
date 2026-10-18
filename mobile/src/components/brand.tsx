import Svg, { Circle, Defs, G, LinearGradient, Path, RadialGradient, Rect, Stop } from 'react-native-svg';

/** The MyScanner mark: an S drawn by the scan path, inside a scanner frame. */
export function BrandMark({ size = 32, beam = true }: { size?: number; beam?: boolean }) {
  return (
    <Svg width={size} height={size} viewBox="0 0 120 120">
      <Defs>
        <LinearGradient id="g1" x1="0" y1="1" x2="1" y2="0"><Stop offset="0" stopColor="#22d3ee" /><Stop offset="1" stopColor="#8b5cf6" /></LinearGradient>
        <LinearGradient id="sv" x1="94" y1="20" x2="26" y2="100" gradientUnits="userSpaceOnUse">
          <Stop offset="0" stopColor="#22d3ee" /><Stop offset=".5" stopColor="#3b82f6" /><Stop offset="1" stopColor="#a855f7" />
        </LinearGradient>
        <RadialGradient id="glow"><Stop offset="0" stopColor="#a5f3fc" stopOpacity=".95" /><Stop offset="1" stopColor="#22d3ee" stopOpacity="0" /></RadialGradient>
      </Defs>
      <Path d="M10 32V20a10 10 0 0 1 10-10h12M88 10h12a10 10 0 0 1 10 10v12M110 88v12a10 10 0 0 1-10 10H88M32 110H20a10 10 0 0 1-10-10V88"
        fill="none" stroke="url(#g1)" strokeWidth={6} strokeLinecap="round" />
      <G transform="translate(60 60) scale(.66) translate(-60 -60)">
        <Path d="M94 26H43a17 17 0 0 0 0 34h34a17 17 0 0 1 0 34H26" fill="none" stroke="url(#sv)" strokeWidth={14} strokeLinecap="round" />
        <Circle cx="26" cy="94" r="15" fill="url(#glow)" />
        <Circle cx="26" cy="94" r="6" fill="#ecfeff" />
      </G>
      {beam ? <Rect x="20" y="58.6" width="80" height="2.8" rx="1.4" fill="#ecfeff" /> : null}
    </Svg>
  );
}
