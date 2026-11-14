import { defineConfig } from "vite";
import { sveltekit } from "@sveltejs/kit/vite";
// Tauri n'a pas de serveur Node pour le SSR : adapter-static avec repli sur
// index.html (mode SPA). SvelteKit 3 lit sa configuration ici, plus dans
// svelte.config.js. https://v2.tauri.app/start/frontend/sveltekit/
import adapter from "@sveltejs/adapter-static";
import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

// `process` est bien typé depuis que @types/node est là : la directive
// d'exception ne couvrait plus rien, et une directive inutile est elle-même
// signalée en erreur.
const host = process.env.TAURI_DEV_HOST;

// https://vite.dev/config/
export default defineConfig(async () => ({
  plugins: [
    sveltekit({
      preprocess: vitePreprocess(),
      adapter: adapter({ fallback: "index.html" }),
      // SvelteKit 3 remplace $lib par #lib : on garde $lib partout.
      alias: { $lib: "src/lib" },
    }),
  ],

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },
}));
