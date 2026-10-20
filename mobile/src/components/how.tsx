import { Text, View } from 'react-native';
import Animated from 'react-native-reanimated';

import { enter } from '@/components/motion';
import { t } from '@/lib/i18n';
import { colors, fonts } from '@/lib/theme';

/** "How it works": the tool's steps as a short numbered timeline. */
export function HowItWorks({ steps }: { steps: [string, string][] }) {
  if (!steps.length) return null;
  return (
    <View style={{ gap: 4, marginTop: 6 }}>
      <Text style={{ color: colors.text, fontSize: 18, fontFamily: fonts.bold, marginBottom: 8 }}>{t('How it works')}</Text>
      {steps.map(([title, text], i) => (
        <Animated.View key={title} entering={enter(i + 2)} style={{ flexDirection: 'row', gap: 14 }}>
          <View style={{ alignItems: 'center' }}>
            <View style={{ width: 30, height: 30, borderRadius: 15, alignItems: 'center', justifyContent: 'center', backgroundColor: 'rgba(119,220,255,.08)', borderWidth: 1, borderColor: 'rgba(119,220,255,.3)' }}>
              <Text style={{ color: colors.cyan, fontFamily: fonts.monoBold, fontSize: 12 }}>{i + 1}</Text>
            </View>
            {i < steps.length - 1 ? <View style={{ flex: 1, width: 1, backgroundColor: 'rgba(119,220,255,.2)', marginVertical: 4 }} /> : null}
          </View>
          <View style={{ flex: 1, gap: 3, paddingBottom: 16 }}>
            <Text style={{ color: colors.text, fontSize: 15, fontFamily: fonts.bold, marginTop: 5 }}>{title}</Text>
            <Text style={{ color: colors.muted, fontSize: 13.5, lineHeight: 20, fontFamily: fonts.regular }}>{text}</Text>
          </View>
        </Animated.View>
      ))}
    </View>
  );
}
