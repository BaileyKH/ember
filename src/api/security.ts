import type { NextFunction, Request, Response } from "express";
import type { ApiConfig } from "../config.js";
import { UserForbiddenError } from "./errors.js";

function sameOriginAsRequest(req: Request, origin: string): boolean {
    const host = req.get("host");
    return Boolean(host && origin === `${req.protocol}://${host}`);
}

export function assertTrustedOrigin(cfg: ApiConfig, req: Request): void {
    const origin = req.get("origin");
    const fetchSite = req.get("sec-fetch-site");

    if (!origin || fetchSite === "cross-site") {
        throw new UserForbiddenError("Untrusted request origin");
    }

    const configuredFrontend = cfg.frontendOrigin === origin;
    if (!configuredFrontend && !sameOriginAsRequest(req, origin)) {
        throw new UserForbiddenError("Untrusted request origin");
    }
}

export function middlewareTrustedOrigin(cfg: ApiConfig) {
    return (req: Request, _res: Response, next: NextFunction) => {
        try {
            assertTrustedOrigin(cfg, req);
            next();
        } catch (error) {
            next(error);
        }
    };
}

export function middlewareCors(cfg: ApiConfig) {
    return (req: Request, res: Response, next: NextFunction) => {
        const origin = req.get("origin");
        const allowed = Boolean(origin && cfg.frontendOrigin === origin);

        if (allowed) {
            res.vary("Origin");
            res.setHeader("Access-Control-Allow-Origin", origin!);
            res.setHeader("Access-Control-Allow-Credentials", "true");
            res.setHeader(
                "Access-Control-Allow-Headers",
                "Authorization, Content-Type",
            );
            res.setHeader(
                "Access-Control-Allow-Methods",
                "GET, POST, PUT, PATCH, DELETE, OPTIONS",
            );
        }

        if (req.method === "OPTIONS") {
            return allowed
                ? res.sendStatus(204)
                : res.status(403).json({ error: "Untrusted request origin" });
        }

        return next();
    };
}
