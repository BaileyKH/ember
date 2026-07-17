import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Request, Response } from "express";
import type { ApiConfig } from "../config.js";
import { BadRequestError, UserNotAuthenticatedError } from "./errors.js";

const mocks = vi.hoisted(() => ({
    verifyPassword: vi.fn(),
    makeJWT: vi.fn(),
    makeRefreshToken: vi.fn(),
    createRefreshToken: vi.fn(),
    revokeRefreshToken: vi.fn(),
    rotateRefreshToken: vi.fn(),
    getUserByEmail: vi.fn(),
}));

vi.mock("../auth.js", () => ({
    DUMMY_PASSWORD_HASH: "dummy-password-hash",
    verifyPassword: mocks.verifyPassword,
    makeJWT: mocks.makeJWT,
    makeRefreshToken: mocks.makeRefreshToken,
}));

vi.mock("../db/queries/refresh.js", () => ({
    createRefreshToken: mocks.createRefreshToken,
    revokeRefreshToken: mocks.revokeRefreshToken,
    rotateRefreshToken: mocks.rotateRefreshToken,
}));

vi.mock("../db/queries/users.js", () => ({
    getUserByEmail: mocks.getUserByEmail,
}));

import { handlerLogin, handlerRefresh, handlerRevoke } from "./auth.js";

const cfg: ApiConfig = {
    dbUrl: "postgres://unused-in-unit-tests",
    port: "3000",
    platform: "test",
    jwtSecret: "test-jwt-secret",
    rateLimitSecret: "test-rate-limit-secret-at-least-32-bytes",
    frontendOrigin: "https://app.example.com",
};

const user = {
    id: "45d56584-fb3d-47cc-9fcb-a504d1e2714c",
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
    updatedAt: new Date("2026-01-02T00:00:00.000Z"),
    email: "person@example.com",
    profileImg: null,
    username: "person",
    hashedPassword: "argon2-hash",
    sessionVersion: 2,
};

function makeRequest(
    body: unknown = {},
    options: {
        cookies?: Record<string, unknown>;
        origin?: string;
        fetchSite?: string;
    } = {},
): Request {
    const headers: Record<string, string | undefined> = {
        origin: options.origin ?? cfg.frontendOrigin,
        "sec-fetch-site": options.fetchSite ?? "same-site",
        host: "api.example.com",
    };

    return {
        body,
        cookies: options.cookies ?? {},
        protocol: "https",
        get: (name: string) => headers[name.toLowerCase()],
    } as Request;
}

function makeResponse() {
    const status = vi.fn();
    const json = vi.fn();
    const sendStatus = vi.fn();
    const cookie = vi.fn();
    const clearCookie = vi.fn();
    const setHeader = vi.fn();
    const response = {
        status,
        json,
        sendStatus,
        cookie,
        clearCookie,
        setHeader,
    } as unknown as Response;

    status.mockReturnValue(response);
    json.mockReturnValue(response);
    sendStatus.mockReturnValue(response);

    return { response, status, json, sendStatus, cookie, clearCookie, setHeader };
}

beforeEach(() => {
    vi.clearAllMocks();
});

describe("handlerLogin", () => {
    it("normalizes the email, validates the password, and returns public user data and tokens", async () => {
        const { response, status, json, cookie, setHeader } = makeResponse();
        const request = makeRequest({
            email: "  Person@Example.COM ",
            password: "correct-password",
        });

        mocks.getUserByEmail.mockResolvedValue(user);
        mocks.verifyPassword.mockResolvedValue(true);
        mocks.makeJWT.mockReturnValue("access-token");
        mocks.makeRefreshToken.mockReturnValue("raw-refresh-token");
        const refreshExpiresAt = new Date("2026-01-31T00:00:00.000Z");
        mocks.createRefreshToken.mockResolvedValue({ expiresAt: refreshExpiresAt });

        await handlerLogin(cfg, request, response);

        expect(mocks.getUserByEmail).toHaveBeenCalledWith("person@example.com");
        expect(mocks.verifyPassword).toHaveBeenCalledWith(
            user.hashedPassword,
            "correct-password",
        );
        expect(mocks.makeJWT).toHaveBeenCalledWith(
            user.id,
            cfg.jwtSecret,
            60 * 60,
            user.sessionVersion,
        );
        expect(mocks.createRefreshToken).toHaveBeenCalledWith(
            "raw-refresh-token",
            user.id,
        );
        expect(status).toHaveBeenCalledWith(200);
        expect(setHeader).toHaveBeenCalledWith("Cache-Control", "no-store");
        expect(setHeader).toHaveBeenCalledWith("Pragma", "no-cache");
        expect(cookie).toHaveBeenCalledWith("ember_refresh", "raw-refresh-token", {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            path: "/api",
            expires: refreshExpiresAt,
        });
        expect(json).toHaveBeenCalledWith({
            User: {
                id: user.id,
                createdAt: user.createdAt,
                updatedAt: user.updatedAt,
                email: user.email,
                profileImg: user.profileImg,
                username: user.username,
            },
            token: "access-token",
        });
        expect(json.mock.calls[0][0]).not.toHaveProperty("refreshToken");
        expect(json.mock.calls[0][0].User).not.toHaveProperty("hashedPassword");
    });

    it.each([
        { body: { password: "password" }, reason: "missing email" },
        { body: { email: "person@example.com" }, reason: "missing password" },
        { body: { email: 42, password: "password" }, reason: "non-string email" },
        {
            body: { email: "person@example.com", password: 42 },
            reason: "non-string password",
        },
    ])("rejects invalid credentials input: $reason", async ({ body }) => {
        const { response } = makeResponse();

        await expect(handlerLogin(cfg, makeRequest(body), response)).rejects.toBeInstanceOf(
            BadRequestError,
        );

        expect(mocks.getUserByEmail).not.toHaveBeenCalled();
    });

    it("uses the same authentication error when the account does not exist", async () => {
        const { response } = makeResponse();
        mocks.getUserByEmail.mockResolvedValue(undefined);
        mocks.verifyPassword.mockResolvedValue(false);

        await expect(
            handlerLogin(
                cfg,
                makeRequest({ email: "missing@example.com", password: "password" }),
                response,
            ),
        ).rejects.toMatchObject({
            constructor: UserNotAuthenticatedError,
            message: "Invalid username or password",
        });

        expect(mocks.verifyPassword).toHaveBeenCalledWith(
            "dummy-password-hash",
            "password",
        );
        expect(mocks.createRefreshToken).not.toHaveBeenCalled();
    });

    it("rejects an incorrect password without creating tokens", async () => {
        const { response } = makeResponse();
        mocks.getUserByEmail.mockResolvedValue(user);
        mocks.verifyPassword.mockResolvedValue(false);

        await expect(
            handlerLogin(
                cfg,
                makeRequest({ email: user.email, password: "wrong-password" }),
                response,
            ),
        ).rejects.toBeInstanceOf(UserNotAuthenticatedError);

        expect(mocks.makeRefreshToken).not.toHaveBeenCalled();
        expect(mocks.createRefreshToken).not.toHaveBeenCalled();
    });

    it("rejects an untrusted request origin before checking credentials", async () => {
        const { response } = makeResponse();
        const request = makeRequest(
            { email: user.email, password: "password" },
            { origin: "https://evil.example" },
        );

        await expect(handlerLogin(cfg, request, response)).rejects.toMatchObject({
            message: "Untrusted request origin",
        });

        expect(mocks.getUserByEmail).not.toHaveBeenCalled();
    });
});

describe("handlerRefresh", () => {
    it("returns a new access token and rotates the refresh cookie", async () => {
        const { response, status, json, cookie, setHeader } = makeResponse();
        const request = makeRequest({}, {
            cookies: { ember_refresh: "presented-refresh-token" },
        });
        const refreshExpiresAt = new Date("2026-01-31T00:00:00.000Z");

        mocks.rotateRefreshToken.mockResolvedValue({
            status: "rotated",
            userId: user.id,
            sessionVersion: user.sessionVersion,
            refreshToken: "replacement-refresh-token",
            expiresAt: refreshExpiresAt,
        });
        mocks.makeJWT.mockReturnValue("replacement-access-token");

        await handlerRefresh(cfg, request, response);

        expect(mocks.rotateRefreshToken).toHaveBeenCalledWith(
            "presented-refresh-token",
        );
        expect(mocks.makeJWT).toHaveBeenCalledWith(
            user.id,
            cfg.jwtSecret,
            60 * 60,
            user.sessionVersion,
        );
        expect(status).toHaveBeenCalledWith(200);
        expect(setHeader).toHaveBeenCalledWith("Cache-Control", "no-store");
        expect(setHeader).toHaveBeenCalledWith("Pragma", "no-cache");
        expect(cookie).toHaveBeenCalledWith(
            "ember_refresh",
            "replacement-refresh-token",
            {
                httpOnly: true,
                secure: true,
                sameSite: "strict",
                path: "/api",
                expires: refreshExpiresAt,
            },
        );
        expect(json).toHaveBeenCalledWith({
            token: "replacement-access-token",
        });
        expect(json.mock.calls[0][0]).not.toHaveProperty("refreshToken");
    });

    it.each(["invalid", "reused"])(
        "rejects a %s refresh result without minting an access token",
        async (rotationStatus) => {
            const { response, clearCookie } = makeResponse();
            const warning = vi.spyOn(console, "warn").mockImplementation(() => undefined);

            mocks.rotateRefreshToken.mockResolvedValue({ status: rotationStatus });

            await expect(
                handlerRefresh(
                    cfg,
                    makeRequest({}, {
                        cookies: { ember_refresh: "presented-refresh-token" },
                    }),
                    response,
                ),
            ).rejects.toBeInstanceOf(UserNotAuthenticatedError);

            expect(mocks.makeJWT).not.toHaveBeenCalled();
            expect(clearCookie).toHaveBeenCalledWith("ember_refresh", {
                httpOnly: true,
                secure: true,
                sameSite: "strict",
                path: "/api",
            });
            expect(warning).toHaveBeenCalledTimes(rotationStatus === "reused" ? 1 : 0);
            warning.mockRestore();
        },
    );

    it("rejects a request without a refresh cookie", async () => {
        const { response } = makeResponse();

        await expect(
            handlerRefresh(cfg, makeRequest(), response),
        ).rejects.toBeInstanceOf(UserNotAuthenticatedError);

        expect(mocks.rotateRefreshToken).not.toHaveBeenCalled();
    });
});

describe("handlerRevoke", () => {
    it("revokes the presented refresh token and returns 204", async () => {
        const { response, sendStatus, clearCookie } = makeResponse();
        const request = makeRequest({}, {
            cookies: { ember_refresh: "presented-refresh-token" },
        });

        mocks.revokeRefreshToken.mockResolvedValue(true);

        await handlerRevoke(cfg, request, response);

        expect(mocks.revokeRefreshToken).toHaveBeenCalledWith(
            "presented-refresh-token",
        );
        expect(clearCookie).toHaveBeenCalledWith("ember_refresh", {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            path: "/api",
        });
        expect(sendStatus).toHaveBeenCalledWith(204);
    });
});
