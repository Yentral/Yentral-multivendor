import React, { useMemo, useState } from 'react';
import {
  FlatList,
  StyleSheet,
  Text,
  View,
  ScrollView,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import { activities, AGE_GROUPS, CATEGORY_LABELS } from '@/data/activities';
import { ActivityCard } from '@/components/ActivityCard';
import { FilterChip } from '@/components/FilterChip';
import { colors, spacing, typography } from '@/theme';
import type { RootStackParamList } from '@/navigation/types';
import type { AgeGroup, Category } from '@/types';

type Props = NativeStackScreenProps<RootStackParamList, 'Home'>;

const CATEGORIES = Object.keys(CATEGORY_LABELS) as Category[];

export function HomeScreen({ navigation }: Props) {
  const [ageFilter, setAgeFilter] = useState<AgeGroup | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<Category | null>(null);

  const filtered = useMemo(() => {
    return activities.filter((a) => {
      const ageMatch = !ageFilter || a.ageGroups.includes(ageFilter);
      const catMatch = !categoryFilter || a.category === categoryFilter;
      return ageMatch && catMatch;
    });
  }, [ageFilter, categoryFilter]);

  return (
    <SafeAreaView style={styles.safe} edges={['top']}>
      <FlatList
        data={filtered}
        keyExtractor={(item) => item.id}
        contentContainerStyle={styles.listContent}
        ListHeaderComponent={
          <View>
            <View style={styles.header}>
              <Text style={styles.greeting}>Hoi! 👋</Text>
              <Text style={styles.title}>Wat gaan jullie vandaag ontdekken?</Text>
            </View>

            <Text style={styles.sectionLabel}>Leeftijd</Text>
            <ScrollView
              horizontal
              showsHorizontalScrollIndicator={false}
              contentContainerStyle={styles.chipsRow}
            >
              <FilterChip
                label="Alle"
                active={ageFilter === null}
                onPress={() => setAgeFilter(null)}
              />
              {AGE_GROUPS.map((g) => (
                <FilterChip
                  key={g.value}
                  label={g.label}
                  active={ageFilter === g.value}
                  onPress={() => setAgeFilter(g.value)}
                />
              ))}
            </ScrollView>

            <Text style={styles.sectionLabel}>Categorie</Text>
            <ScrollView
              horizontal
              showsHorizontalScrollIndicator={false}
              contentContainerStyle={styles.chipsRow}
            >
              <FilterChip
                label="Alle"
                active={categoryFilter === null}
                onPress={() => setCategoryFilter(null)}
              />
              {CATEGORIES.map((c) => (
                <FilterChip
                  key={c}
                  label={CATEGORY_LABELS[c]}
                  active={categoryFilter === c}
                  onPress={() => setCategoryFilter(c)}
                />
              ))}
            </ScrollView>

            <Text style={styles.resultsLabel}>
              {filtered.length} {filtered.length === 1 ? 'activiteit' : 'activiteiten'}
            </Text>
          </View>
        }
        renderItem={({ item }) => (
          <ActivityCard
            activity={item}
            onPress={() => navigation.navigate('Detail', { id: item.id })}
          />
        )}
        ListEmptyComponent={
          <View style={styles.empty}>
            <Text style={styles.emptyEmoji}>🔍</Text>
            <Text style={styles.emptyText}>
              Geen activiteiten gevonden. Probeer een ander filter.
            </Text>
          </View>
        }
      />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safe: {
    flex: 1,
    backgroundColor: colors.background,
  },
  listContent: {
    paddingHorizontal: spacing.md,
    paddingBottom: spacing.xl,
  },
  header: {
    marginTop: spacing.md,
    marginBottom: spacing.lg,
  },
  greeting: {
    ...typography.subheading,
    color: colors.textMuted,
  },
  title: {
    ...typography.title,
    color: colors.text,
    marginTop: spacing.xs,
  },
  sectionLabel: {
    ...typography.small,
    color: colors.textMuted,
    marginTop: spacing.md,
    marginBottom: spacing.sm,
    textTransform: 'uppercase',
    letterSpacing: 1,
    fontWeight: '700',
  },
  chipsRow: {
    paddingRight: spacing.md,
    paddingBottom: spacing.xs,
  },
  resultsLabel: {
    ...typography.small,
    color: colors.textMuted,
    marginTop: spacing.lg,
    marginBottom: spacing.sm,
  },
  empty: {
    alignItems: 'center',
    paddingVertical: spacing.xxl,
  },
  emptyEmoji: {
    fontSize: 56,
    marginBottom: spacing.md,
  },
  emptyText: {
    ...typography.body,
    color: colors.textMuted,
    textAlign: 'center',
  },
});
