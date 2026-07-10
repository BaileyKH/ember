import { defineConfig } from "drizzle-kit";
import { cfg } from './src/config'

export default defineConfig({
  schema: "./src/db/schema.ts",
  out: "./src/db/migrations",
  dialect: "postgresql",
  dbCredentials: {
    url: cfg.dbUrl,
  },
});