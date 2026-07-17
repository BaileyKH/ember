import {
  verifyPassword,
  makeJWT,
  makeRefreshToken,
  DUMMY_PASSWORD_HASH,
} from "../auth.js";
import { type PublicUser } from "./users.js";
import { type CookieOptions, Request, Response} from 'express'
import { type ApiConfig } from "../config.js";
import { createRefreshToken, revokeRefreshToken, rotateRefreshToken } from "../db/queries/refresh.js";
import { getUserByEmail } from "../db/queries/users.js";
import { BadRequestError, UserNotAuthenticatedError } from "./errors.js";
import { assertTrustedOrigin } from "./security.js";

export const REFRESH_COOKIE_NAME = "ember_refresh";

function refreshCookieOptions(cfg: ApiConfig): CookieOptions {
    return {
        httpOnly: true,
        secure: cfg.platform !== "dev",
        sameSite: "strict",
        path: "/api",
    };
}

function getRefreshTokenCookie(req: Request): string {
    const token = req.cookies?.[REFRESH_COOKIE_NAME];
    if (typeof token !== "string" || token.length === 0) {
        throw new UserNotAuthenticatedError("Invalid or expired refresh token");
    }

    return token;
}

function preventTokenCaching(res: Response): void {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Pragma", "no-cache");
}

export async function handlerLogin(cfg: ApiConfig, req: Request, res: Response) {
    assertTrustedOrigin(cfg, req);
    const { email, password } = req.body;
    if (typeof email !== "string" || email.length === 0) {
        throw new BadRequestError("Invalid username or password")
    }

    if (typeof password !== "string" || password.length === 0) {
        throw new BadRequestError("Invalid username or password")
    }

    const normalizedEmail = email.toLowerCase().trim()

    const user = await getUserByEmail(normalizedEmail);
    const passwordHash = user?.hashedPassword ?? DUMMY_PASSWORD_HASH;
    const valid = await verifyPassword(passwordHash, password);
    if (!user || !valid) {
        throw new UserNotAuthenticatedError("Invalid username or password");
    }

    const accessExpiresMs = 60 * 60;
    const accessToken = makeJWT(
        user.id,
        cfg.jwtSecret,
        accessExpiresMs,
        user.sessionVersion,
    );
    const refreshToken = makeRefreshToken();

    const storedToken = await createRefreshToken(refreshToken, user.id);
    if (!storedToken) {
        throw new Error("Failed to create refresh token");
    }

    res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
        ...refreshCookieOptions(cfg),
        expires: storedToken.expiresAt,
    });
    preventTokenCaching(res);

    const validatedUser: PublicUser = {
        id: user.id,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        email: user.email,
        profileImg: user.profileImg,
        username: user.username
    }

    return res.status(200).json({ User: validatedUser, token: accessToken })

}

export async function handlerRefresh(cfg: ApiConfig, req: Request, res: Response,) {
    assertTrustedOrigin(cfg, req);
    const refreshToken = getRefreshTokenCookie(req);
    const rotated = await rotateRefreshToken(refreshToken);

    if (!rotated) {
        res.clearCookie(REFRESH_COOKIE_NAME, refreshCookieOptions(cfg));
        throw new UserNotAuthenticatedError(
            "Invalid or expired refresh token",
        );
    }

    if (rotated.status !== "rotated") {
        res.clearCookie(REFRESH_COOKIE_NAME, refreshCookieOptions(cfg));
        if (rotated.status === "reused") {
            console.warn("Refresh-token reuse detected");
        }

        throw new UserNotAuthenticatedError(
            "Invalid or expired refresh token",
        );
    }

    const oneHourSeconds = 60 * 60;
    const accessToken = makeJWT(
        rotated.userId,
        cfg.jwtSecret,
        oneHourSeconds,
        rotated.sessionVersion,
    );

    res.cookie(REFRESH_COOKIE_NAME, rotated.refreshToken, {
        ...refreshCookieOptions(cfg),
        expires: rotated.expiresAt,
    });
    preventTokenCaching(res);

    return res.status(200).json({
        token: accessToken,
    });
}

export async function handlerRevoke(cfg: ApiConfig, req: Request, res: Response) {
    assertTrustedOrigin(cfg, req);
    const refreshToken = getRefreshTokenCookie(req);

    await revokeRefreshToken(refreshToken);
    res.clearCookie(REFRESH_COOKIE_NAME, refreshCookieOptions(cfg));
    return res.sendStatus(204);
}
