
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import { VitePWA } from 'vite-plugin-pwa';

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '');
  return {
    plugins: [
      react(),
      VitePWA({
        registerType: 'autoUpdate',
        includeAssets: ['favicon.ico', 'apple-touch-icon.png', 'mask-icon.svg'],
        manifest: {
          name: 'RedToy',
          short_name: 'RedToy',
          description: 'A playful Red Team cheatsheet powered by Gemini AI',
          theme_color: '#FF4D4D',
          background_color: '#FFF5F5',
          display: 'standalone',
          orientation: 'any',
          scope: '/',
          start_url: '/',
          icons: [
            {
              src: 'pwa-192x192.png',
              sizes: '192x192',
              type: 'image/png'
            },
            {
              src: 'pwa-512x512.png',
              sizes: '512x512',
              type: 'image/png'
            },
            {
              src: 'pwa-512x512.png',
              sizes: '512x512',
              type: 'image/png',
              purpose: 'any'
            },
            {
              src: 'pwa-512x512.png',
              sizes: '512x512',
              type: 'image/png',
              purpose: 'maskable'
            }
          ]
        }
      })
    ],
    // This ensures your repository name is handled correctly if deployed to a subpath
    // Change '/your-repo-name/' to './' for relative paths or your actual repo name
    base: './',
    define: {
      // This allows 'process.env.API_KEY' to work in the client-side code
      'process.env.API_KEY': JSON.stringify(env.API_KEY)
    }
  };
});
