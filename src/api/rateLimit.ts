import { createHmac } from "crypto";
import type { Request } from "express";
import { ipKeyGenerator, rateLimit } from "express-rate-limit";
import type { ApiConfig } from "../config.js";

const TOO_MANY_ATTEMPTS = {
    error: "Too many login attempts. Please try again later.",
};

type LoginRateLimitOverrides = {
    ipLimit?: number;
    ipWindowMs?: number;
    accountIpLimit?: number;
    accountIpWindowMs?: number;
};

type PasswordRateLimitOverrides = {
    forgotIpLimit?: number;
    forgotIpWindowMs?: number;
    forgotAccountIpLimit?: number;
    forgotAccountIpWindowMs?: number;
    resetIpLimit?: number;
    resetIpWindowMs?: number;
    changeIpLimit?: number;
    changeIpWindowMs?: number;
};

function normalizedLoginEmail(req: Request): string {
    return typeof req.body?.email === "string"
        ? req.body.email.toLowerCase().trim()
        : "missing-email";
}

export function accountIpRateLimitKey(cfg: ApiConfig, req: Request): string {
    const accountKey = createHmac("sha256", cfg.rateLimitSecret)
        .update(normalizedLoginEmail(req), "utf8")
        .digest("hex");
    const ipKey = req.ip ? ipKeyGenerator(req.ip) : "unknown-ip";

    return `${ipKey}:${accountKey}`;
}

export function createLoginRateLimiters(
    cfg: ApiConfig,
    overrides: LoginRateLimitOverrides = {},
) {
    const loginIpLimiter = rateLimit({
        windowMs: overrides.ipWindowMs ?? 10 * 60 * 1000,
        limit: overrides.ipLimit ?? 30,
        standardHeaders: "draft-8",
        legacyHeaders: false,
        message: TOO_MANY_ATTEMPTS,
    });

    const loginAccountIpLimiter = rateLimit({
        windowMs: overrides.accountIpWindowMs ?? 15 * 60 * 1000,
        limit: overrides.accountIpLimit ?? 10,
        keyGenerator: (req) => accountIpRateLimitKey(cfg, req),
        skipSuccessfulRequests: true,
        standardHeaders: "draft-8",
        legacyHeaders: false,
        message: TOO_MANY_ATTEMPTS,
    });

    return { loginIpLimiter, loginAccountIpLimiter };
}

export function createPasswordRateLimiters(
    cfg: ApiConfig,
    overrides: PasswordRateLimitOverrides = {},
) {
    const forgotPasswordIpLimiter = rateLimit({
        windowMs: overrides.forgotIpWindowMs ?? 15 * 60 * 1000,
        limit: overrides.forgotIpLimit ?? 10,
        standardHeaders: "draft-8",
        legacyHeaders: false,
        message: { error: "Too many password-reset requests. Please try again later." },
    });

    const forgotPasswordAccountIpLimiter = rateLimit({
        windowMs: overrides.forgotAccountIpWindowMs ?? 60 * 60 * 1000,
        limit: overrides.forgotAccountIpLimit ?? 3,
        keyGenerator: (req) => accountIpRateLimitKey(cfg, req),
        standardHeaders: "draft-8",
        legacyHeaders: false,
        message: { error: "Too many password-reset requests. Please try again later." },
    });

    const resetPasswordIpLimiter = rateLimit({
        windowMs: overrides.resetIpWindowMs ?? 15 * 60 * 1000,
        limit: overrides.resetIpLimit ?? 10,
        standardHeaders: "draft-8",
        legacyHeaders: false,
        message: { error: "Too many password-reset attempts. Please try again later." },
    });

    const changePasswordIpLimiter = rateLimit({
        windowMs: overrides.changeIpWindowMs ?? 15 * 60 * 1000,
        limit: overrides.changeIpLimit ?? 10,
        standardHeaders: "draft-8",
        legacyHeaders: false,
        message: { error: "Too many password-change attempts. Please try again later." },
    });

    return {
        forgotPasswordIpLimiter,
        forgotPasswordAccountIpLimiter,
        resetPasswordIpLimiter,
        changePasswordIpLimiter,
    };
}

export function createRegistrationRateLimiter() {
    return rateLimit({
        windowMs: 60 * 60 * 1000,
        limit: 10,
        standardHeaders: "draft-8",
        legacyHeaders: false,
        message: { error: "Too many registration attempts. Please try again later." },
    });
}
