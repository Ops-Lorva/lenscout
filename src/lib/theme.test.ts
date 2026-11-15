import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

// DA « Console » (maquette lenscout-hallmark) : ambre pour les actions, polices
// embarquées. Ces tests lisent les fichiers tels qu'ils partent dans le bundle.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const read = (p: string) => readFileSync(resolve(root, p), 'utf8');
const css = read('src/app.css');

/** Teinte HSL (degrés) d'une couleur `#rrggbb`. */
function hue(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const max = Math.max(r, g, b);
  const d = max - Math.min(r, g, b);
  if (d === 0) return 0;
  const h = max === r ? ((g - b) / d) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4;
  return (h * 60 + 360) % 360;
}
const amber = (hex: string) => hue(hex) >= 25 && hue(hex) <= 50;

describe('couleur d\'action', () => {
  it('est ambre dans les deux thèmes', () => {
    const acts = [...css.matchAll(/--act:\s*(#[0-9a-f]{6})/gi)].map((m) => m[1]);
    expect(acts.length).toBeGreaterThanOrEqual(2);
    for (const a of acts) expect(amber(a), a).toBe(true);
  });

  it('ne garde plus le bleu de l\'ancienne palette', () => {
    for (const p of ['src/app.css', 'src/lib/components/Sidebar.svelte']) {
      expect(read(p)).not.toMatch(/#2f6fed|#4d8dff/i);
    }
  });
});

describe('polices', () => {
  const faces = [...css.matchAll(/@font-face\s*{[^}]*}/g)].map((m) => m[0]);

  it.each(['Host Grotesk', 'Atkinson Hyperlegible Mono'])('%s est embarquée en woff2 local', (family) => {
    const mine = faces.filter((f) => f.includes(`'${family}'`));
    expect(mine.length).toBeGreaterThan(0);
    for (const f of mine) {
      const url = f.match(/url\(([^)]+)\)/)![1].replace(/['"]/g, '');
      expect(url).not.toMatch(/^https?:/);
      expect(url.endsWith('.woff2')).toBe(true);
      expect(existsSync(resolve(root, 'src', url)), url).toBe(true);
    }
  });

  it('la licence OFL accompagne les fichiers', () => {
    expect(read('src/fonts/OFL-host-grotesk.txt')).toContain('SIL Open Font License');
    expect(read('src/fonts/OFL-atkinson-hyperlegible-mono.txt')).toContain('SIL Open Font License');
  });
});

describe('icône macOS adaptative', () => {
  it.each(['point.svg', 'point-sombre.svg', 'cone.svg', 'cone-sombre.svg'])('%s est ambre', (f) => {
    const svg = read(`src-tauri/icons/AppIcon.icon/Assets/${f}`);
    const fills = [...svg.matchAll(/fill="(#[0-9a-f]{6})"/gi)].map((m) => m[1]);
    expect(fills.length).toBeGreaterThan(0);
    for (const c of fills) expect(amber(c), c).toBe(true);
  });
});
