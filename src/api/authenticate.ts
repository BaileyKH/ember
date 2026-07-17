import type { NextFunction, Request, Response } from "express";
import type { ApiConfig } from "../config.js";
import type { ExistingUser } from "../db/schema.js";
import { getUserById } from "../db/queries/users.js";
import { getBearerToken, validateJWTSession } from "../auth.js";
import { UserNotAuthenticatedError } from "./errors.js";

const AUTHENTICATED_USER_LOCAL = "authenticatedUser";

export async function authenticateRequest(
    cfg: ApiConfig,
    req: Request,
): Promise<ExistingUser> {
    const token = getBearerToken(req);
    const claims = validateJWTSession(token, cfg.jwtSecret);
    const user = await getUserById(claims.userId);

    if (!user || user.sessionVersion !== claims.sessionVersion) {
        throw new UserNotAuthenticatedError("Invalid or expired token");
    }

    return user;
}

export function middlewareAuthenticate(cfg: ApiConfig) {
    return (req: Request, res: Response, next: NextFunction): void => {
        authenticateRequest(cfg, req)
            .then((user) => {
                res.locals[AUTHENTICATED_USER_LOCAL] = user;
                next();
            })
            .catch(next);
    };
}

export function getAuthenticatedUser(res: Response): ExistingUser {
    const user = res.locals[AUTHENTICATED_USER_LOCAL];
    if (!user) {
        throw new UserNotAuthenticatedError("Authentication required");
    }

    return user;
}
