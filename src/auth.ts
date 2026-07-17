import { Request } from "express";
import { randomBytes, createHash } from "crypto";
import * as argon2 from "argon2"
import jwt from "jsonwebtoken"
import { type JwtPayload } from "jsonwebtoken";
import { UserNotAuthenticatedError } from "./api/errors.js";

export const ACCESS_TOKEN_ISSUER = "ember-access";
export const ACCESS_TOKEN_AUDIENCE = "ember-api";
export const MIN_JWT_SECRET_BYTES = 32;
export const MIN_PASSWORD_LENGTH = 10;
export const MAX_PASSWORD_LENGTH = 128;

const PASSWORD_HASH_OPTIONS = {
    type: argon2.argon2id,
    memoryCost: 65_536,
    timeCost: 3,
    parallelism: 4,
} as const;

export const DUMMY_PASSWORD_HASH =
    "$argon2id$v=19$m=65536,t=3,p=4$rbKOVM9vIqMgmkCgUTgsjA$opmgiz5VbiPzW5LPMfZggOxIc0SPYrid26pP7up988k";

export async function hashPassword(password: string): Promise<string> {
    return await argon2.hash(password, PASSWORD_HASH_OPTIONS)
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
    return await argon2.verify(hash, password)
}

type Payload = Pick<JwtPayload, "iss" | "aud" | "sub" | "iat" | "exp"> & {
    ver: number;
};

export function assertValidJWTSecret(secret: string): void {
    if (Buffer.byteLength(secret, "utf8") < MIN_JWT_SECRET_BYTES) {
        throw new Error(
            `JWT secret must be at least ${MIN_JWT_SECRET_BYTES} bytes`,
        );
    }
}

export function makeJWT(
    userId: string,
    secret: string,
    expiresIn: number,
    sessionVersion = 0,
) {
    assertValidJWTSecret(secret);
    const issuedAt = Math.floor(Date.now() / 1000);
    const expiresAt = issuedAt + expiresIn;
    const token = jwt.sign(
        {
            iss: ACCESS_TOKEN_ISSUER,
            aud: ACCESS_TOKEN_AUDIENCE,
            sub: userId,
            iat: issuedAt,
            exp: expiresAt,
            ver: sessionVersion,
        } satisfies Payload,
        secret,
        { algorithm: "HS256" }
    )

    return token
}

export function validateJWTSession(
    tokenString: string,
    secret: string,
): { userId: string; sessionVersion: number } {
    assertValidJWTSecret(secret);
    let decoded: string | JwtPayload;
    try {
        decoded = jwt.verify(tokenString, secret, {
            algorithms: ["HS256"],
            issuer: ACCESS_TOKEN_ISSUER,
            audience: ACCESS_TOKEN_AUDIENCE,
        });
    } catch {
        throw new UserNotAuthenticatedError("Invalid or expired token");
    }

    if (typeof decoded === "string") {
        throw new UserNotAuthenticatedError("Invalid token payload");
    }

    const userID = decoded.sub;
    if (!userID) {
        throw new UserNotAuthenticatedError("Missing subject (user ID)");
    }

    if (!Number.isSafeInteger(decoded.ver) || decoded.ver < 0) {
        throw new UserNotAuthenticatedError("Invalid token payload");
    }

    return { userId: userID, sessionVersion: decoded.ver };
}

export function validateJWT(tokenString: string, secret: string): string {
    return validateJWTSession(tokenString, secret).userId;
}

export function getBearerToken(req: Request): string {
    const authRes = req.get("Authorization")

    if (typeof authRes !== "string" || authRes.length < 1) {
        throw new UserNotAuthenticatedError("Invalid Authorization Token")
    }
    const token = authRes.trim().split(/\s+/);

    if (token.length !== 2 || token[0].toLowerCase() !== "bearer" || !token[1]) {
        throw new UserNotAuthenticatedError("Invalid Authorization Token")
    }

    return token[1]
}

export function makeRefreshToken(): string {
    const buf = randomBytes(32)
    return buf.toString("hex")
}

export function hashRefreshToken(token: string): string {
    return createHash("sha256")
        .update(token, "utf8")
        .digest("hex");
}

export function makePasswordResetToken(): string {
    return randomBytes(32).toString("hex");
}

export function hashPasswordResetToken(token: string): string {
    return createHash("sha256").update(token, "utf8").digest("hex");
}
