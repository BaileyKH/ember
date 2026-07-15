import { db } from "../index.js";
import { NewUser, users } from "../schema.js";
import { eq, sql } from "drizzle-orm";

export async function createUser(user: NewUser) {
    const [result] = await db
        .insert(users)
        .values(user)
        .returning()

    return result
}

export async function reset() {
    return await db.delete(users)
}

export async function getUserByEmail(email: string) {
    const [result] = await db
        .select()
        .from(users)
        .where(eq(users.email, email))

    return result
}

export async function getUserByUsername(username: string) {
    const [result] = await db
        .select()
        .from(users)
        .where(sql`lower(${users.username}) = ${username.toLowerCase().trim()}`)

    return result
}