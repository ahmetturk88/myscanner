import { Text, View } from 'react-native';
import Animated from 'react-native-reanimated';

import { Icon } from '@/components/icon';
import { enter, Pulse } from '@/components/motion';
import { Chips } from '@/components/ui';
import { colors } from '@/lib/theme';
import type { Tool } from '@/lib/tools';

/** The tool's icon, with rings that ripple while it works. */
export function ToolBadge({ tool, busy }: { tool: Tool; busy?: boolean }) {
  return (
    <View style={{ marginBottom: 10, alignSelf: 'flex-start' }}>
      <Pulse size={58} active={!!busy}>
        <View style={{ width: 58, height: 58, borderRadius: 20, alignItems: 'center', justifyContent: 'center',
          backgroundColor: 'rgba(119,220,255,.08)', borderWidth: 1, borderColor: 'rgba(119,220,255,.3)' }}>
          <Icon name={tool.icon} size={27} color={colors.cyan} />
        </View>
      </Pulse>
    </View>
  );
}

/** The heading with its accent words in brand cyan. */
export function Accent({ text, accent }: { text: string; accent?: string }) {
  const cut = accent ? text.lastIndexOf(accent) : -1;
  if (cut < 0) return <>{text}</>;
  return <>{text.slice(0, cut)}<Text style={{ color: colors.cyan }}>{accent}</Text>{text.slice(cut + accent!.length)}</>;
}

export function ToolChips({ tool }: { tool: Tool }) {
  return <Animated.View entering={enter(1)}><Chips items={tool.chips} /></Animated.View>;
}
