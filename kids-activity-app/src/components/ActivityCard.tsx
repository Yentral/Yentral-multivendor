import React from 'react';
import { Pressable, Text, View, StyleSheet } from 'react-native';
import type { Activity } from '@/types';
import { CATEGORY_LABELS } from '@/data/activities';
import { colors, radius, spacing, typography } from '@/theme';

type Props = {
  activity: Activity;
  onPress: () => void;
};

export function ActivityCard({ activity, onPress }: Props) {
  return (
    <Pressable onPress={onPress} style={({ pressed }) => [styles.card, pressed && styles.pressed]}>
      <View style={[styles.thumb, { backgroundColor: activity.thumbnailColor }]}>
        <Text style={styles.emoji}>{activity.emoji}</Text>
      </View>
      <View style={styles.body}>
        <View style={styles.metaRow}>
          <Text style={styles.category}>{CATEGORY_LABELS[activity.category]}</Text>
          <Text style={styles.duration}>{activity.durationMinutes} min</Text>
        </View>
        <Text style={styles.title} numberOfLines={2}>
          {activity.title}
        </Text>
        <Text style={styles.description} numberOfLines={2}>
          {activity.shortDescription}
        </Text>
        <View style={styles.ageRow}>
          {activity.ageGroups.map((age) => (
            <View key={age} style={styles.ageBadge}>
              <Text style={styles.ageText}>{age} jr</Text>
            </View>
          ))}
        </View>
      </View>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: colors.surface,
    borderRadius: radius.lg,
    marginBottom: spacing.md,
    overflow: 'hidden',
    shadowColor: '#000',
    shadowOpacity: 0.06,
    shadowRadius: 8,
    shadowOffset: { width: 0, height: 2 },
    elevation: 2,
  },
  pressed: {
    opacity: 0.85,
  },
  thumb: {
    height: 140,
    alignItems: 'center',
    justifyContent: 'center',
  },
  emoji: {
    fontSize: 64,
  },
  body: {
    padding: spacing.md,
  },
  metaRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: spacing.xs,
  },
  category: {
    ...typography.chip,
    color: colors.primary,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
  },
  duration: {
    ...typography.small,
    color: colors.textMuted,
  },
  title: {
    ...typography.subheading,
    color: colors.text,
    marginBottom: spacing.xs,
  },
  description: {
    ...typography.body,
    color: colors.textMuted,
    marginBottom: spacing.sm,
  },
  ageRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: spacing.xs,
  },
  ageBadge: {
    backgroundColor: colors.background,
    borderRadius: radius.pill,
    paddingHorizontal: spacing.sm,
    paddingVertical: 2,
    marginRight: spacing.xs,
  },
  ageText: {
    ...typography.chip,
    color: colors.textMuted,
  },
});
