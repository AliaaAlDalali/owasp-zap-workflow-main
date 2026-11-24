import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// In development the API is reached through /api on the same origin, so the
// session cookie stays first-party and no CORS setup is needed.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: process.env.HIMAAK_API_TARGET ?? 'http://127.0.0.1:8000',
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
});
