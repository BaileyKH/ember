import { db } from "../index.js";
import { NewUser, passwordResetTokens, refreshTokens, users } from "../schema.js";
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

export async function getUserById(id: string) {
    const [result] = await db.select().from(users).where(eq(users.id, id));
    return result;
}

export async function changePasswordAndRevokeSessions(
    userId: string,
    hashedPassword: string,
) {
    return db.transaction(async (tx) => {
        const [updatedUser] = await tx
            .update(users)
            .set({
                hashedPassword,
                sessionVersion: sql`${users.sessionVersion} + 1`,
                updatedAt: new Date(),
            })
            .where(eq(users.id, userId))
            .returning();

        if (!updatedUser) return undefined;

        await tx
            .update(refreshTokens)
            .set({ revokedAt: new Date(), updatedAt: new Date() })
            .where(eq(refreshTokens.userId, userId));

        await tx
            .delete(passwordResetTokens)
            .where(eq(passwordResetTokens.userId, userId));

        return updatedUser;
    });
}

export async function getUserByUsername(username: string) {
    const [result] = await db
        .select()
        .from(users)
        .where(sql`lower(${users.username}) = ${username.toLowerCase().trim()}`)

    return result
}
