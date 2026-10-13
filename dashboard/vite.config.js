import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev (npm run dev, port 5173) API calls are proxied to the gateway on :8080.
const gateway = process.env.BYTESHIELD_URL || "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": gateway, "/v1": gateway, "/mcp": gateway },
  },
});
