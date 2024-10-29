import { DrizzlePostgreSQLAdapter } from "@lucia-auth/adapter-drizzle";
import { db } from "../db";
import { users, sessions } from "../db/schema";

export const adapter = new DrizzlePostgreSQLAdapter(db, sessions, users);
