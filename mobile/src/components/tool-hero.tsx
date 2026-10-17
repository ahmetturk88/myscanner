import { View } from 'react-native';

import { Appear } from '@/components/motion';
import { Chips, Eyebrow, Hero, Lead } from '@/components/ui';
import type { Tool } from '@/lib/tools';

/** The top of a tool page: eyebrow, heading with its accent, lead and chips, as on the website. */
export function ToolHero({ tool }: { tool: Tool }) {
  return (
    <Appear>
      <View style={{ gap: 14, marginTop: 10 }}>
        <Eyebrow>{tool.kicker}</Eyebrow>
        <Hero title={tool.heading} accent={tool.accent} size={34} />
        <Lead>{tool.lead}</Lead>
        <Chips items={tool.chips} />
      </View>
    </Appear>
  );
}
