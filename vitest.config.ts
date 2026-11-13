import { defineConfig } from 'vitest/config';
import { fileURLToPath, URL } from 'node:url';

// Les tests ne montent pas de composants : fonctions pures seulement, donc
// pas besoin du plugin SvelteKit — juste l'alias `$lib`.
export default defineConfig({
  resolve: {
    alias: { $lib: fileURLToPath(new URL('./src/lib', import.meta.url)) },
  },
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
});
