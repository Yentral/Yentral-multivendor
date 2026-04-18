import React from 'react';
import { ScrollView, StyleSheet, Text, View, Pressable } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import { activities, CATEGORY_LABELS } from '@/data/activities';
import { VideoPlayer } from '@/components/VideoPlayer';
import { colors, radius, spacing, typography } from '@/theme';
import type { RootStackParamList } from '@/navigation/types';

type Props = NativeStackScreenProps<RootStackParamList, 'Detail'>;

export function DetailScreen({ route, navigation }: Props) {
  const activity = activities.find((a) => a.id === route.params.id);

  if (!activity) {
    return (
      <SafeAreaView style={styles.safe}>
        <Text style={styles.missing}>Activiteit niet gevonden.</Text>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.safe} edges={['top']}>
      <ScrollView contentContainerStyle={styles.content}>
        <View style={styles.topRow}>
          <Pressable
            onPress={() => navigation.goBack()}
            style={styles.backButton}
            accessibilityLabel="Terug"
          >
            <Text style={styles.backIcon}>←</Text>
          </Pressable>
          <Text style={styles.category}>{CATEGORY_LABELS[activity.category]}</Text>
        </View>

        <Text style={styles.title}>{activity.title}</Text>

        <View style={styles.metaRow}>
          <View style={styles.metaPill}>
            <Text style={styles.metaText}>⏱ {activity.durationMinutes} min</Text>
          </View>
          {activity.ageGroups.map((age) => (
            <View key={age} style={styles.metaPill}>
              <Text style={styles.metaText}>{age} jaar</Text>
            </View>
          ))}
        </View>

        <View style={styles.videoWrapper}>
          <VideoPlayer
            videoUrl={activity.videoUrl}
            emoji={activity.emoji}
            thumbnailColor={activity.thumbnailColor}
          />
        </View>

        <Text style={styles.description}>{activity.description}</Text>

        <Section title="Wat leert je kind?" icon="🎓">
          {activity.learningGoals.map((goal) => (
            <BulletRow key={goal} text={goal} />
          ))}
        </Section>

        <Section title="Wat heb je nodig?" icon="🧰">
          {activity.materials.map((m) => (
            <BulletRow key={m} text={m} />
          ))}
        </Section>

        <Section title="Zo doe je het" icon="✨">
          {activity.steps.map((step, idx) => (
            <View key={idx} style={styles.stepRow}>
              <View style={styles.stepNumber}>
                <Text style={styles.stepNumberText}>{idx + 1}</Text>
              </View>
              <Text style={styles.stepText}>{step}</Text>
            </View>
          ))}
        </Section>
      </ScrollView>
    </SafeAreaView>
  );
}

function Section({
  title,
  icon,
  children,
}: {
  title: string;
  icon: string;
  children: React.ReactNode;
}) {
  return (
    <View style={styles.section}>
      <Text style={styles.sectionTitle}>
        {icon}  {title}
      </Text>
      <View style={styles.sectionBody}>{children}</View>
    </View>
  );
}

function BulletRow({ text }: { text: string }) {
  return (
    <View style={styles.bulletRow}>
      <View style={styles.bullet} />
      <Text style={styles.bulletText}>{text}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  safe: {
    flex: 1,
    backgroundColor: colors.background,
  },
  content: {
    padding: spacing.md,
    paddingBottom: spacing.xxl,
  },
  topRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: spacing.md,
  },
  backButton: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: colors.surface,
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: spacing.md,
  },
  backIcon: {
    fontSize: 22,
    color: colors.text,
  },
  category: {
    ...typography.chip,
    color: colors.primary,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
  },
  title: {
    ...typography.title,
    color: colors.text,
    marginBottom: spacing.sm,
  },
  metaRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    marginBottom: spacing.md,
    gap: spacing.xs,
  },
  metaPill: {
    backgroundColor: colors.surface,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.xs,
    borderRadius: radius.pill,
    marginRight: spacing.xs,
    marginBottom: spacing.xs,
  },
  metaText: {
    ...typography.chip,
    color: colors.textMuted,
  },
  videoWrapper: {
    marginBottom: spacing.lg,
  },
  description: {
    ...typography.body,
    color: colors.text,
    lineHeight: 24,
    marginBottom: spacing.lg,
  },
  section: {
    backgroundColor: colors.surface,
    borderRadius: radius.lg,
    padding: spacing.md,
    marginBottom: spacing.md,
  },
  sectionTitle: {
    ...typography.heading,
    color: colors.text,
    marginBottom: spacing.md,
  },
  sectionBody: {
    gap: spacing.sm,
  },
  bulletRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    marginBottom: spacing.sm,
  },
  bullet: {
    width: 8,
    height: 8,
    borderRadius: 4,
    backgroundColor: colors.accent,
    marginTop: 8,
    marginRight: spacing.sm,
  },
  bulletText: {
    ...typography.body,
    color: colors.text,
    flex: 1,
    lineHeight: 22,
  },
  stepRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    marginBottom: spacing.md,
  },
  stepNumber: {
    width: 28,
    height: 28,
    borderRadius: 14,
    backgroundColor: colors.primary,
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: spacing.sm,
  },
  stepNumberText: {
    color: '#fff',
    fontWeight: '700',
    fontSize: 14,
  },
  stepText: {
    ...typography.body,
    color: colors.text,
    flex: 1,
    lineHeight: 22,
  },
  missing: {
    ...typography.body,
    textAlign: 'center',
    marginTop: spacing.xxl,
    color: colors.textMuted,
  },
});
