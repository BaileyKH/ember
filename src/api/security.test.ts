import { describe, expect, it, vi } from "vitest";
import type { NextFunction, Request, Response } from "express";
import type { ApiConfig } from "../config.js";
import { assertTrustedOrigin, middlewareCors } from "./security.js";
import { UserForbiddenError } from "./errors.js";

const cfg: ApiConfig = {
    dbUrl: "postgres://unused-in-unit-tests",
    port: "3000",
    platform: "test",
    jwtSecret: "test-jwt-secret",
    rateLimitSecret: "test-rate-limit-secret-at-least-32-bytes",
    frontendOrigin: "https://app.example.com",
};

function makeRequest(options: {
    origin?: string;
    fetchSite?: string;
    host?: string;
    protocol?: string;
    method?: string;
}): Request {
    const headers: Record<string, string | undefined> = {
        origin: options.origin,
        "sec-fetch-site": options.fetchSite,
        host: options.host ?? "api.example.com",
    };

    return {
        method: options.method ?? "POST",
        protocol: options.protocol ?? "https",
        get: (name: string) => headers[name.toLowerCase()],
    } as Request;
}

function makeResponse() {
    const vary = vi.fn();
    const setHeader = vi.fn();
    const sendStatus = vi.fn();
    const status = vi.fn();
    const json = vi.fn();
    const response = {
        vary,
        setHeader,
        sendStatus,
        status,
        json,
    } as unknown as Response;

    status.mockReturnValue(response);
    json.mockReturnValue(response);
    sendStatus.mockReturnValue(response);

    return { response, vary, setHeader, sendStatus, status, json };
}

describe("assertTrustedOrigin", () => {
    it("allows the configured frontend origin", () => {
        const request = makeRequest({
            origin: cfg.frontendOrigin,
            fetchSite: "same-site",
        });

        expect(() => assertTrustedOrigin(cfg, request)).not.toThrow();
    });

    it("allows the API's own origin without frontend configuration", () => {
        const request = makeRequest({
            origin: "https://api.example.com",
            fetchSite: "same-origin",
        });

        expect(() =>
            assertTrustedOrigin({ ...cfg, frontendOrigin: undefined }, request),
        ).not.toThrow();
    });

    it.each([
        { origin: undefined, fetchSite: "same-origin", reason: "missing origin" },
        {
            origin: "https://evil.example",
            fetchSite: "cross-site",
            reason: "cross-site request",
        },
        {
            origin: "https://evil.example",
            fetchSite: "same-site",
            reason: "origin not on the allowlist",
        },
    ])("rejects $reason", ({ origin, fetchSite }) => {
        const request = makeRequest({ origin, fetchSite });

        expect(() => assertTrustedOrigin(cfg, request)).toThrow(
            UserForbiddenError,
        );
    });
});

describe("middlewareCors", () => {
    it("answers an allowed credentialed preflight request", () => {
        const request = makeRequest({
            method: "OPTIONS",
            origin: cfg.frontendOrigin,
            fetchSite: "same-site",
        });
        const { response, vary, setHeader, sendStatus } = makeResponse();
        const next = vi.fn() as NextFunction;

        middlewareCors(cfg)(request, response, next);

        expect(vary).toHaveBeenCalledWith("Origin");
        expect(setHeader).toHaveBeenCalledWith(
            "Access-Control-Allow-Origin",
            cfg.frontendOrigin,
        );
        expect(setHeader).toHaveBeenCalledWith(
            "Access-Control-Allow-Credentials",
            "true",
        );
        expect(sendStatus).toHaveBeenCalledWith(204);
        expect(next).not.toHaveBeenCalled();
    });

    it("rejects an untrusted preflight origin", () => {
        const request = makeRequest({
            method: "OPTIONS",
            origin: "https://evil.example",
            fetchSite: "cross-site",
        });
        const { response, status, json } = makeResponse();
        const next = vi.fn() as NextFunction;

        middlewareCors(cfg)(request, response, next);

        expect(status).toHaveBeenCalledWith(403);
        expect(json).toHaveBeenCalledWith({ error: "Untrusted request origin" });
        expect(next).not.toHaveBeenCalled();
    });
});
