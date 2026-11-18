import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev (npm run dev on :5173) we proxy /api and /ws to the backend on :8000.
// In production the nginx container does the proxying instead.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: true },
      "/ws": { target: "ws://localhost:8000", ws: true },
    },
  },
});
