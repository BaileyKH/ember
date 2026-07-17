import { beforeEach, describe, expect, it, vi } from "vitest";
import type { NextFunction, Request, Response } from "express";
import type { ApiConfig } from "../config.js";
import { UserNotAuthenticatedError } from "./errors.js";

const mocks = vi.hoisted(() => ({
    getBearerToken: vi.fn(),
    validateJWTSession: vi.fn(),
    getUserById: vi.fn(),
}));

vi.mock("../auth.js", () => ({
    getBearerToken: mocks.getBearerToken,
    validateJWTSession: mocks.validateJWTSession,
}));

vi.mock("../db/queries/users.js", () => ({
    getUserById: mocks.getUserById,
}));

import {
    authenticateRequest,
    getAuthenticatedUser,
    middlewareAuthenticate,
} from "./authenticate.js";

const cfg: ApiConfig = {
    dbUrl: "postgres://unused",
    port: "3000",
    platform: "test",
    jwtSecret: "j".repeat(32),
    rateLimitSecret: "r".repeat(32),
};

const user = {
    id: "45d56584-fb3d-47cc-9fcb-a504d1e2714c",
    createdAt: new Date(),
    updatedAt: new Date(),
    email: "person@example.com",
    profileImg: null,
    username: "person",
    hashedPassword: "argon2-hash",
    sessionVersion: 4,
};

beforeEach(() => {
    vi.clearAllMocks();
    mocks.getBearerToken.mockReturnValue("access-token");
    mocks.validateJWTSession.mockReturnValue({
        userId: user.id,
        sessionVersion: user.sessionVersion,
    });
    mocks.getUserById.mockResolvedValue(user);
});

describe("authenticateRequest", () => {
    it("validates the bearer token and current database session version", async () => {
        const req = {} as Request;

        await expect(authenticateRequest(cfg, req)).resolves.toBe(user);
        expect(mocks.getBearerToken).toHaveBeenCalledWith(req);
        expect(mocks.validateJWTSession).toHaveBeenCalledWith(
            "access-token",
            cfg.jwtSecret,
        );
        expect(mocks.getUserById).toHaveBeenCalledWith(user.id);
    });

    it("rejects a token issued before the user's session version changed", async () => {
        mocks.validateJWTSession.mockReturnValue({
            userId: user.id,
            sessionVersion: user.sessionVersion - 1,
        });

        await expect(authenticateRequest(cfg, {} as Request))
            .rejects.toBeInstanceOf(UserNotAuthenticatedError);
    });

    it("rejects a valid token when its user no longer exists", async () => {
        mocks.getUserById.mockResolvedValue(undefined);

        await expect(authenticateRequest(cfg, {} as Request))
            .rejects.toBeInstanceOf(UserNotAuthenticatedError);
    });
});

describe("middlewareAuthenticate", () => {
    it("places the authenticated user in response locals", async () => {
        const req = {} as Request;
        const res = { locals: {} } as Response;
        const next = vi.fn() as NextFunction;

        middlewareAuthenticate(cfg)(req, res, next);

        await vi.waitFor(() => expect(next).toHaveBeenCalledWith());
        expect(getAuthenticatedUser(res)).toBe(user);
    });

    it("passes authentication failures to Express without setting a user", async () => {
        const error = new UserNotAuthenticatedError("Invalid or expired token");
        mocks.validateJWTSession.mockImplementation(() => {
            throw error;
        });
        const res = { locals: {} } as Response;
        const next = vi.fn() as NextFunction;

        middlewareAuthenticate(cfg)({} as Request, res, next);

        await vi.waitFor(() => expect(next).toHaveBeenCalledWith(error));
        expect(() => getAuthenticatedUser(res)).toThrow("Authentication required");
    });
});
