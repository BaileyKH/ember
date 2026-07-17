import { db } from "../index.js";
import { refreshTokens, users } from "../schema.js";
import { and, eq, gt, isNull } from "drizzle-orm";
import { hashRefreshToken, makeRefreshToken } from "../../auth.js";

export async function createRefreshToken(token: string, userId: string) {
    const tokenHash = hashRefreshToken(token)
    const thirtyDays = 30 * 24 * 60 * 60 * 1000;
    const expireDate = new Date(Date.now() + thirtyDays); 

    const [result] = await db.insert(refreshTokens).values({
        tokenHash: tokenHash,
        userId: userId,
        expiresAt: expireDate,
        revokedAt: null
    }).returning({ expiresAt: refreshTokens.expiresAt })

    return result
}

export async function getUserByRefreshToken(token: string) {
    const tokenHash = hashRefreshToken(token)

    const [result] = await db
        .select({ user: users })
        .from(refreshTokens)
        .innerJoin(users, eq(users.id, refreshTokens.userId))
        .where(and(
            eq(refreshTokens.tokenHash, tokenHash),
            isNull(refreshTokens.revokedAt),
            gt(refreshTokens.expiresAt, new Date())
        ))

    return result?.user
}

export async function revokeRefreshToken(token: string) {
    const tokenHash = hashRefreshToken(token)
    
    const result = await db.update(refreshTokens)
        .set({ revokedAt: new Date(), updatedAt: new Date() })
        .where(eq(refreshTokens.tokenHash, tokenHash))
        .returning()

    return result.length > 0
}

export async function rotateRefreshToken(token: string) {
    const oldTokenHash = hashRefreshToken(token);
    const newToken = makeRefreshToken();
    const newTokenHash = hashRefreshToken(newToken);
    const now = new Date();

    return db.transaction(async (tx) => {
        const [consumedToken] = await tx
            .update(refreshTokens)
            .set({
                revokedAt: now,
                updatedAt: now,
            })
            .where(
                and(
                    eq(refreshTokens.tokenHash, oldTokenHash),
                    isNull(refreshTokens.revokedAt),
                    gt(refreshTokens.expiresAt, now),
                ),
            )
            .returning({
                userId: refreshTokens.userId,
                familyId: refreshTokens.familyId,
                expiresAt: refreshTokens.expiresAt,
            });

        if (consumedToken) {
            const [user] = await tx
                .select({ sessionVersion: users.sessionVersion })
                .from(users)
                .where(eq(users.id, consumedToken.userId));

            if (!user) {
                return { status: "invalid" as const };
            }

            await tx.insert(refreshTokens).values({
                tokenHash: newTokenHash,
                familyId: consumedToken.familyId,
                userId: consumedToken.userId,
                expiresAt: consumedToken.expiresAt,
                revokedAt: null,
            });

            return {
                status: "rotated" as const,
                userId: consumedToken.userId,
                sessionVersion: user.sessionVersion,
                refreshToken: newToken,
                expiresAt: consumedToken.expiresAt,
            };
        }

        const [presentedToken] = await tx
            .select({
                familyId: refreshTokens.familyId,
                revokedAt: refreshTokens.revokedAt,
                expiresAt: refreshTokens.expiresAt,
            })
            .from(refreshTokens)
            .where(eq(refreshTokens.tokenHash, oldTokenHash));

        if (!presentedToken || presentedToken.expiresAt <= now) {
            return {
                status: "invalid" as const,
            };
        }

        if (presentedToken.revokedAt) {
            await tx
                .update(refreshTokens)
                .set({
                    revokedAt: now,
                    updatedAt: now,
                })
                .where(
                    and(
                        eq(
                            refreshTokens.familyId,
                            presentedToken.familyId,
                        ),
                        isNull(refreshTokens.revokedAt),
                    ),
                );

            return {
                status: "reused" as const,
            };
        }

        return {
            status: "invalid" as const,
        };
    });
}
