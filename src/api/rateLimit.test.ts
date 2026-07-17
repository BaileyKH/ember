import { EventEmitter } from "events";
import type { NextFunction, Request, Response } from "express";
import { describe, expect, it } from "vitest";
import type { ApiConfig } from "../config.js";
import {
    accountIpRateLimitKey,
    createLoginRateLimiters,
} from "./rateLimit.js";

const cfg: ApiConfig = {
    dbUrl: "postgres://unused-in-unit-tests",
    port: "3000",
    platform: "test",
    jwtSecret: "test-jwt-secret",
    rateLimitSecret: "test-rate-limit-secret-at-least-32-bytes",
};

function createTestLimiters(options: {
    ipLimit: number;
    accountIpLimit: number;
}) {
    return createLoginRateLimiters(
        cfg,
        {
            ...options,
            ipWindowMs: 60_000,
            accountIpWindowMs: 60_000,
        },
    );
}

class MockResponse extends EventEmitter {
    statusCode = 200;
    body: unknown;
    headers = new Map<string, string | number | readonly string[]>();
    onFinished: () => void = () => undefined;

    setHeader(name: string, value: string | number | readonly string[]) {
        this.headers.set(name.toLowerCase(), value);
        return this;
    }

    getHeader(name: string) {
        return this.headers.get(name.toLowerCase());
    }

    append(name: string, value: string | readonly string[]) {
        const key = name.toLowerCase();
        const current = this.headers.get(key);
        const additions = typeof value === "string" ? [value] : [...value];

        if (current === undefined) {
            this.headers.set(key, additions);
        } else {
            const existing = Array.isArray(current) ? current : [String(current)];
            this.headers.set(key, [...existing, ...additions]);
        }

        return this;
    }

    status(code: number) {
        this.statusCode = code;
        return this;
    }

    send(body?: unknown) {
        this.body = body;
        this.emit("finish");
        queueMicrotask(this.onFinished);
        return this;
    }
}

async function login(
    limiters: ReturnType<typeof createTestLimiters>,
    email: string,
    password = "wrong-password",
) {
    const request = {
        body: { email, password },
        ip: "192.0.2.1",
        app: { get: () => false },
        headers: {},
        method: "POST",
        originalUrl: "/login",
    } as unknown as Request;
    const response = new MockResponse();

    return new Promise<MockResponse>((resolve, reject) => {
        response.onFinished = () => resolve(response);

        const handleNext = (next: () => void): NextFunction => (error) => {
            if (error) {
                reject(error);
                return;
            }

            next();
        };

        limiters.loginIpLimiter(
            request,
            response as unknown as Response,
            handleNext(() => {
                limiters.loginAccountIpLimiter(
                    request,
                    response as unknown as Response,
                    handleNext(() => {
                        if (password === "correct-password") {
                            response.status(204).send();
                            return;
                        }

                        response.status(401).send({
                            error: "Invalid username or password",
                        });
                    }),
                );
            }),
        );
    });
}

describe("accountIpRateLimitKey", () => {
    it("normalizes email without exposing it in the stored limiter key", () => {
        const first = accountIpRateLimitKey(cfg, {
            body: { email: " Person@Example.COM " },
            ip: "192.0.2.1",
        } as Request);
        const second = accountIpRateLimitKey(cfg, {
            body: { email: "person@example.com" },
            ip: "192.0.2.1",
        } as Request);

        expect(first).toBe(second);
        expect(first).not.toContain("person@example.com");
    });

    it("separates the same account across different IP addresses", () => {
        const first = accountIpRateLimitKey(cfg, {
            body: { email: "person@example.com" },
            ip: "192.0.2.1",
        } as Request);
        const second = accountIpRateLimitKey(cfg, {
            body: { email: "person@example.com" },
            ip: "192.0.2.2",
        } as Request);

        expect(first).not.toBe(second);
    });
});

describe("login rate limiters", () => {
    it("blocks an IP after the broad attempt limit", async () => {
        const limiters = createTestLimiters({ ipLimit: 2, accountIpLimit: 100 });

        expect((await login(limiters, "one@example.com")).statusCode).toBe(401);
        expect((await login(limiters, "two@example.com")).statusCode).toBe(401);

        const limited = await login(limiters, "three@example.com");
        expect(limited.statusCode).toBe(429);
        expect(limited.getHeader("retry-after")).toBeTruthy();
        expect(limited.getHeader("ratelimit")).toBeTruthy();
        expect(limited.body).toEqual({
            error: "Too many login attempts. Please try again later.",
        });
    });

    it("shares a failure bucket across normalized versions of an email", async () => {
        const limiters = createTestLimiters({ ipLimit: 100, accountIpLimit: 2 });

        expect((await login(limiters, " Person@Example.COM ")).statusCode).toBe(401);
        expect((await login(limiters, "person@example.com")).statusCode).toBe(401);
        expect((await login(limiters, "PERSON@example.com")).statusCode).toBe(429);
    });

    it("keeps different account buckets independent", async () => {
        const limiters = createTestLimiters({ ipLimit: 100, accountIpLimit: 1 });

        expect((await login(limiters, "first@example.com")).statusCode).toBe(401);
        expect((await login(limiters, "second@example.com")).statusCode).toBe(401);
        expect((await login(limiters, "first@example.com")).statusCode).toBe(429);
    });

    it("does not retain successful requests in the failed-attempt bucket", async () => {
        const limiters = createTestLimiters({ ipLimit: 100, accountIpLimit: 1 });

        expect(
            (await login(limiters, "person@example.com", "correct-password"))
                .statusCode,
        ).toBe(204);
        expect((await login(limiters, "person@example.com")).statusCode).toBe(401);
        expect((await login(limiters, "person@example.com")).statusCode).toBe(429);
    });
});
