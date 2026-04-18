import React, { useRef, useState } from 'react';
import { StyleSheet, Text, View, Pressable } from 'react-native';
import { ResizeMode, Video, AVPlaybackStatus } from 'expo-av';
import { colors, radius, spacing, typography } from '@/theme';

type Props = {
  videoUrl: string | null;
  emoji: string;
  thumbnailColor: string;
};

export function VideoPlayer({ videoUrl, emoji, thumbnailColor }: Props) {
  const videoRef = useRef<Video>(null);
  const [status, setStatus] = useState<AVPlaybackStatus | null>(null);

  if (!videoUrl) {
    return (
      <View style={[styles.placeholder, { backgroundColor: thumbnailColor }]}>
        <Text style={styles.placeholderEmoji}>{emoji}</Text>
        <View style={styles.placeholderBadge}>
          <Text style={styles.placeholderBadgeText}>Video komt binnenkort</Text>
        </View>
        <Text style={styles.placeholderHint}>
          Voeg een video toe in{' '}
          <Text style={styles.code}>src/data/activities.ts</Text>
        </Text>
      </View>
    );
  }

  const isPlaying = status?.isLoaded ? status.isPlaying : false;

  return (
    <View style={styles.wrapper}>
      <Video
        ref={videoRef}
        style={styles.video}
        source={{ uri: videoUrl }}
        useNativeControls
        resizeMode={ResizeMode.CONTAIN}
        onPlaybackStatusUpdate={setStatus}
      />
      {!isPlaying && status?.isLoaded && (
        <Pressable
          style={styles.playOverlay}
          onPress={() => videoRef.current?.playAsync()}
          accessibilityLabel="Video afspelen"
        >
          <View style={styles.playButton}>
            <Text style={styles.playIcon}>▶</Text>
          </View>
        </Pressable>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  wrapper: {
    width: '100%',
    aspectRatio: 16 / 9,
    backgroundColor: '#000',
    borderRadius: radius.md,
    overflow: 'hidden',
  },
  video: {
    width: '100%',
    height: '100%',
  },
  playOverlay: {
    ...StyleSheet.absoluteFillObject,
    alignItems: 'center',
    justifyContent: 'center',
  },
  playButton: {
    width: 72,
    height: 72,
    borderRadius: 36,
    backgroundColor: 'rgba(255,255,255,0.9)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  playIcon: {
    fontSize: 28,
    color: colors.primary,
    marginLeft: 4,
  },
  placeholder: {
    width: '100%',
    aspectRatio: 16 / 9,
    borderRadius: radius.md,
    alignItems: 'center',
    justifyContent: 'center',
    padding: spacing.lg,
  },
  placeholderEmoji: {
    fontSize: 80,
    marginBottom: spacing.md,
  },
  placeholderBadge: {
    backgroundColor: 'rgba(255,255,255,0.7)',
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.xs,
    borderRadius: radius.pill,
    marginBottom: spacing.sm,
  },
  placeholderBadgeText: {
    ...typography.chip,
    color: colors.text,
  },
  placeholderHint: {
    ...typography.small,
    color: colors.text,
    textAlign: 'center',
    opacity: 0.8,
  },
  code: {
    fontFamily: 'Courier',
    fontWeight: '700',
  },
});
