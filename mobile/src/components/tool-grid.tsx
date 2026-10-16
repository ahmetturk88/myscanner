import { router } from 'expo-router';
import { Pressable, Text, View } from 'react-native';

import { Icon } from '@/components/icon';
import { colors } from '@/lib/theme';
import { TOOLS, type Tool } from '@/lib/tools';

export function ToolGrid({ onUrl }: { onUrl: () => void }) {
  const open = (tool: Tool) => {
    if (tool.route === 'url') onUrl();
    else if (tool.route) router.push(tool.route);
    else router.push({ pathname: '/tool/[name]', params: { name: tool.name } });
  };
  return (
    <View style={{ flexDirection: 'row', flexWrap: 'wrap', rowGap: 16 }}>
      {TOOLS.map((tool) => (
        <Pressable key={tool.name} accessibilityRole="button" accessibilityLabel={tool.title} onPress={() => open(tool)}
          style={({ pressed }) => ({ width: '20%', alignItems: 'center', gap: 7, opacity: pressed ? 0.6 : 1 })}>
          <View style={{ width: 54, height: 54, borderRadius: 18, alignItems: 'center', justifyContent: 'center',
            backgroundColor: tool.color + '22', borderWidth: 1, borderColor: tool.color + '59' }}>
            <Icon name={tool.icon} size={23} color={tool.color} />
          </View>
          <Text numberOfLines={2} style={{ color: colors.soft, fontSize: 11, fontWeight: '600', textAlign: 'center', lineHeight: 14 }}>{tool.short}</Text>
        </Pressable>
      ))}
    </View>
  );
}
