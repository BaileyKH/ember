import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";

import * as schema from "./schema.js";
import { cfg } from "../config.js";

const conn = postgres(cfg.dbUrl);
export const db = drizzle(conn, { schema });