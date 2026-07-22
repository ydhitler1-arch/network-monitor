import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:5000",
    },
  },
  build: {
    // recharts itself is ~150kB gzipped regardless of chunking strategy —
    // fine for a single-page local dashboard, not worth code-splitting
    // further since the chart renders immediately on load either way.
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ["react", "react-dom"],
          recharts: ["recharts"],
        },
      },
    },
  },
});
