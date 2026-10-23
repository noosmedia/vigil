import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

// Vite-Konfiguration für die Tauri-Oberfläche, fester Port 5296
export default defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  server: { port: 5296, strictPort: true, host: '127.0.0.1' },
  build: { target: 'safari16', outDir: 'dist', emptyOutDir: true },
})
