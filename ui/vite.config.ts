import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// API_PROXY_TARGET lets this point at a different host than localhost.
// Needed under docker-compose: the frontend and backend run in separate
// containers, so "localhost:8000" from inside the frontend container means
// the frontend container itself, not the backend one. docker-compose.yml
// sets this to http://backend:8000 (the compose service name resolves via
// Docker's internal DNS); local `npm run dev` outside Docker keeps using
// the localhost default.
const apiProxyTarget = process.env.API_PROXY_TARGET || 'http://localhost:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: apiProxyTarget,
        changeOrigin: true,
      },
    },
  },
})
