/** expo-haptics, silenced when the user turns vibration off in Settings. */
import * as Haptics from 'expo-haptics';

import { getSettings } from '@/lib/settings';

export { ImpactFeedbackStyle, NotificationFeedbackType } from 'expo-haptics';

const on = () => getSettings().haptics;

export const notificationAsync = (type?: Haptics.NotificationFeedbackType) => (on() ? Haptics.notificationAsync(type) : Promise.resolve());
export const impactAsync = (style?: Haptics.ImpactFeedbackStyle) => (on() ? Haptics.impactAsync(style) : Promise.resolve());
export const selectionAsync = () => (on() ? Haptics.selectionAsync() : Promise.resolve());
