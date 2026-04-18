# Speel & Leer

Een React Native (Expo) app die ouders inspireert met educatieve activiteiten om samen met hun kind te doen. Elke activiteit heeft een plek voor een korte uitlegvideo, leerdoelen, een materiaallijstje en stap-voor-stap instructies.

## Features

- 🎬 **Video per activiteit** — elke activiteit heeft een eigen video-speler (je eigen URLs)
- 🔍 **Filters** — op leeftijd (2-4, 4-6, 6-10) en op categorie (wetenschap, taal, rekenen, …)
- 🎓 **Leerdoelen** — elk idee vertelt wat je kind leert
- 🧰 **Materialen & stappen** — alles wat je nodig hebt en hoe je het doet
- 📱 **iOS / Android / Web** — via Expo draait het overal

## Snel starten

```bash
cd kids-activity-app
npm install
npm start
```

Scan vervolgens de QR code met de **Expo Go** app (iOS / Android) of druk `w` voor web.

## Eigen videos toevoegen

Open `src/data/activities.ts`. Elke activiteit heeft een `videoUrl` veld dat standaard op `null` staat:

```ts
{
  id: 'regenboog-melk',
  title: 'Regenboog in melk',
  videoUrl: null,            // ← vervang door je eigen URL
  // ...
}
```

Vervang `null` door een publieke MP4 / HLS URL, bijvoorbeeld:

```ts
videoUrl: 'https://example.com/videos/regenboog-melk.mp4',
```

De ingebouwde speler (`expo-av`) ondersteunt MP4, HLS (.m3u8) en de meeste gangbare web-video formaten. Lokale bestanden kun je via `require('./assets/videos/...')` laden — pas dan ook het `videoUrl` type aan.

## Projectstructuur

```
kids-activity-app/
├── App.tsx                      # Entry + navigatie
├── app.json                     # Expo config
├── src/
│   ├── components/
│   │   ├── ActivityCard.tsx     # Kaart in de lijst
│   │   ├── FilterChip.tsx       # Filter chip
│   │   └── VideoPlayer.tsx      # Speler met placeholder state
│   ├── data/
│   │   └── activities.ts        # ⭐ Hier voeg je activiteiten/videos toe
│   ├── navigation/types.ts
│   ├── screens/
│   │   ├── HomeScreen.tsx       # Lijst + filters
│   │   └── DetailScreen.tsx     # Video + uitleg + stappen
│   ├── theme/index.ts           # Kleuren, typografie, spacing
│   └── types/index.ts           # TypeScript types
```

## Een nieuwe activiteit toevoegen

Voeg een object toe aan de `activities` array in `src/data/activities.ts`:

```ts
{
  id: 'bloemen-persen',
  title: 'Bloemen persen',
  shortDescription: 'Maak prachtige natuurkunst',
  description: 'Lange versie van de beschrijving…',
  videoUrl: 'https://example.com/bloemen.mp4',
  thumbnailColor: colors.card4,
  emoji: '🌸',
  ageGroups: ['4-6', '6-10'],
  category: 'natuur',
  durationMinutes: 30,
  materials: ['Bloemen', 'Zware boeken', 'Vloeipapier'],
  steps: ['Zoek bloemen', 'Leg tussen papier', '...'],
  learningGoals: ['Plantkunde', 'Geduld', 'Fijne motoriek'],
}
```

## Volgende stappen (ideeën)

- Activiteiten opslaan als "gedaan" / favoriet
- Zoekveld met tekst
- Notities per activiteit (wat vond je kind ervan?)
- Een backend zodat ouders activiteiten kunnen delen
- Offline video caching
