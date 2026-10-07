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
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined;
          if (id.includes('/antd/') || id.includes('@ant-design')) return 'antd';
          if (id.includes('/react/') || id.includes('/react-dom/')) return 'react';
          if (id.includes('i18next')) return 'i18n';
          return 'vendor';
        },
      },
    },
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8088',
      '/panel/api': 'http://127.0.0.1:8088',
    },
  },
});
