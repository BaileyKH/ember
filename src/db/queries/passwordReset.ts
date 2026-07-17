import { and, eq, gt, isNull } from "drizzle-orm";
import { hashPasswordResetToken } from "../../auth.js";
import { db } from "../index.js";
import { passwordResetTokens, refreshTokens, users } from "../schema.js";
import { sql } from "drizzle-orm";

const RESET_TOKEN_LIFETIME_MS = 30 * 60 * 1000;

export async function createPasswordResetToken(token: string, userId: string) {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + RESET_TOKEN_LIFETIME_MS);

    return db.transaction(async (tx) => {
        await tx
            .delete(passwordResetTokens)
            .where(eq(passwordResetTokens.userId, userId));

        const [created] = await tx
            .insert(passwordResetTokens)
            .values({
                tokenHash: hashPasswordResetToken(token),
                userId,
                expiresAt,
            })
            .returning({ expiresAt: passwordResetTokens.expiresAt });

        return created;
    });
}

export async function deletePasswordResetToken(token: string) {
    await db
        .delete(passwordResetTokens)
        .where(eq(passwordResetTokens.tokenHash, hashPasswordResetToken(token)));
}

export async function getUserByValidPasswordResetToken(token: string) {
    const [result] = await db
        .select({ user: users })
        .from(passwordResetTokens)
        .innerJoin(users, eq(users.id, passwordResetTokens.userId))
        .where(and(
            eq(passwordResetTokens.tokenHash, hashPasswordResetToken(token)),
            isNull(passwordResetTokens.usedAt),
            gt(passwordResetTokens.expiresAt, new Date()),
        ));

    return result?.user;
}

export async function consumePasswordResetToken(
    token: string,
    userId: string,
    hashedPassword: string,
) {
    const now = new Date();
    const tokenHash = hashPasswordResetToken(token);

    return db.transaction(async (tx) => {
        const [consumed] = await tx
            .update(passwordResetTokens)
            .set({ usedAt: now })
            .where(and(
                eq(passwordResetTokens.tokenHash, tokenHash),
                eq(passwordResetTokens.userId, userId),
                isNull(passwordResetTokens.usedAt),
                gt(passwordResetTokens.expiresAt, now),
            ))
            .returning({ userId: passwordResetTokens.userId });

        if (!consumed) return false;

        await tx
            .update(users)
            .set({
                hashedPassword,
                sessionVersion: sql`${users.sessionVersion} + 1`,
                updatedAt: now,
            })
            .where(eq(users.id, userId));

        await tx
            .update(refreshTokens)
            .set({ revokedAt: now, updatedAt: now })
            .where(eq(refreshTokens.userId, userId));

        await tx
            .delete(passwordResetTokens)
            .where(eq(passwordResetTokens.userId, userId));

        return true;
    });
}
