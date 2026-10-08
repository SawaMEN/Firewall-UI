import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': new URL('./src', import.meta.url).pathname,
    },
  },
  build: {
    outDir: '../internal/webassets/dist',
    emptyOutDir: true,

  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8088',
      '/panel/api': 'http://127.0.0.1:8088',
    },
  },
});
