export type AgeGroup = '2-4' | '4-6' | '6-10';

export type Category =
  | 'knutselen'
  | 'wetenschap'
  | 'taal'
  | 'rekenen'
  | 'beweging'
  | 'natuur'
  | 'muziek'
  | 'koken';

export interface Activity {
  id: string;
  title: string;
  shortDescription: string;
  description: string;
  videoUrl: string | null;
  thumbnailColor: string;
  emoji: string;
  ageGroups: AgeGroup[];
  category: Category;
  durationMinutes: number;
  materials: string[];
  steps: string[];
  learningGoals: string[];
}
