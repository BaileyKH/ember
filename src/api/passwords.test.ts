import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Request, Response } from "express";
import type { ApiConfig } from "../config.js";
import { BadRequestError, UserNotAuthenticatedError } from "./errors.js";

const mocks = vi.hoisted(() => ({
    getBearerToken: vi.fn(),
    validateJWTSession: vi.fn(),
    verifyPassword: vi.fn(),
    hashPassword: vi.fn(),
    makePasswordResetToken: vi.fn(),
    getUserByEmail: vi.fn(),
    getUserById: vi.fn(),
    changePasswordAndRevokeSessions: vi.fn(),
    createPasswordResetToken: vi.fn(),
    deletePasswordResetToken: vi.fn(),
    getUserByValidPasswordResetToken: vi.fn(),
    consumePasswordResetToken: vi.fn(),
    validateNewPassword: vi.fn(),
    assertDeliveryConfigured: vi.fn(),
    deliverPasswordReset: vi.fn(),
}));

vi.mock("../auth.js", () => ({
    getBearerToken: mocks.getBearerToken,
    validateJWTSession: mocks.validateJWTSession,
    verifyPassword: mocks.verifyPassword,
    hashPassword: mocks.hashPassword,
    makePasswordResetToken: mocks.makePasswordResetToken,
}));

vi.mock("../db/queries/users.js", () => ({
    getUserByEmail: mocks.getUserByEmail,
    getUserById: mocks.getUserById,
    changePasswordAndRevokeSessions: mocks.changePasswordAndRevokeSessions,
}));

vi.mock("../db/queries/passwordReset.js", () => ({
    createPasswordResetToken: mocks.createPasswordResetToken,
    deletePasswordResetToken: mocks.deletePasswordResetToken,
    getUserByValidPasswordResetToken: mocks.getUserByValidPasswordResetToken,
    consumePasswordResetToken: mocks.consumePasswordResetToken,
}));

vi.mock("../passwordPolicy.js", () => ({
    validateNewPassword: mocks.validateNewPassword,
}));

vi.mock("../passwordResetDelivery.js", () => ({
    assertPasswordResetDeliveryConfigured: mocks.assertDeliveryConfigured,
    deliverPasswordReset: mocks.deliverPasswordReset,
}));

import {
    handlerChangePassword,
    handlerRequestPasswordReset,
    handlerResetPassword,
} from "./passwords.js";

const cfg: ApiConfig = {
    dbUrl: "postgres://unused",
    port: "3000",
    platform: "test",
    jwtSecret: "j".repeat(32),
    rateLimitSecret: "r".repeat(32),
    frontendOrigin: "https://app.example.com",
    passwordResetUrl: "https://app.example.com/reset-password",
    passwordResetWebhookUrl: "https://mailer.example.com/reset",
    passwordResetWebhookSecret: "w".repeat(32),
};

const user = {
    id: "45d56584-fb3d-47cc-9fcb-a504d1e2714c",
    createdAt: new Date(),
    updatedAt: new Date(),
    email: "person@example.com",
    profileImg: null,
    username: "person",
    hashedPassword: "old-hash",
    sessionVersion: 4,
};

function request(body: unknown, authorization?: string): Request {
    const headers: Record<string, string | undefined> = {
        origin: cfg.frontendOrigin,
        "sec-fetch-site": "same-site",
        host: "api.example.com",
        authorization,
    };
    return {
        body,
        protocol: "https",
        get: (name: string) => headers[name.toLowerCase()],
    } as Request;
}

function response() {
    const status = vi.fn();
    const json = vi.fn();
    const clearCookie = vi.fn();
    const setHeader = vi.fn();
    const res = {
        status,
        json,
        clearCookie,
        setHeader,
        locals: { authenticatedUser: user },
    } as unknown as Response;
    status.mockReturnValue(res);
    json.mockReturnValue(res);
    return { res, status, json, clearCookie };
}

beforeEach(() => {
    vi.clearAllMocks();
    mocks.makePasswordResetToken.mockReturnValue("a".repeat(64));
    mocks.hashPassword.mockResolvedValue("new-hash");
    mocks.validateNewPassword.mockResolvedValue("a secure new password");
});

describe("authenticated password changes", () => {
    it("changes the password and revokes sessions after verifying the current password", async () => {
        const { res, status, clearCookie } = response();
        mocks.verifyPassword.mockResolvedValueOnce(true).mockResolvedValueOnce(false);
        mocks.changePasswordAndRevokeSessions.mockResolvedValue({ ...user, sessionVersion: 5 });

        await handlerChangePassword(cfg, request({
            currentPassword: "old password",
            newPassword: "a secure new password",
        }, "Bearer access-token"), res);

        expect(mocks.validateNewPassword).toHaveBeenCalledWith(
            "a secure new password",
            { email: user.email, username: user.username },
        );
        expect(mocks.changePasswordAndRevokeSessions).toHaveBeenCalledWith(
            user.id,
            "new-hash",
        );
        expect(clearCookie).toHaveBeenCalled();
        expect(status).toHaveBeenCalledWith(200);
    });

    it("requires the centralized middleware to provide an authenticated user", async () => {
        const { res } = response();
        res.locals = {};

        await expect(handlerChangePassword(cfg, request({}, "Bearer access-token"), res))
            .rejects.toBeInstanceOf(UserNotAuthenticatedError);
        expect(mocks.verifyPassword).not.toHaveBeenCalled();
    });

    it("requires the current password", async () => {
        const { res } = response();
        mocks.verifyPassword.mockResolvedValue(false);

        await expect(handlerChangePassword(cfg, request({
            currentPassword: "wrong password",
            newPassword: "a secure new password",
        }), res)).rejects.toMatchObject({ message: "Current password is incorrect" });
        expect(mocks.changePasswordAndRevokeSessions).not.toHaveBeenCalled();
    });
});

describe("forgotten-password reset", () => {
    it("consumes the token, changes the password, and revokes sessions", async () => {
        const { res, status, clearCookie } = response();
        mocks.getUserByValidPasswordResetToken.mockResolvedValue(user);
        mocks.verifyPassword.mockResolvedValue(false);
        mocks.consumePasswordResetToken.mockResolvedValue(true);

        await handlerResetPassword(cfg, request({
            token: "a".repeat(64),
            newPassword: "a secure new password",
        }), res);

        expect(mocks.consumePasswordResetToken).toHaveBeenCalledWith(
            "a".repeat(64),
            user.id,
            "new-hash",
        );
        expect(clearCookie).toHaveBeenCalled();
        expect(status).toHaveBeenCalledWith(200);
    });

    it("rejects malformed and already-consumed tokens", async () => {
        const { res } = response();
        await expect(handlerResetPassword(cfg, request({
            token: "not-a-token",
            newPassword: "a secure new password",
        }), res)).rejects.toBeInstanceOf(BadRequestError);

        mocks.getUserByValidPasswordResetToken.mockResolvedValue(user);
        mocks.verifyPassword.mockResolvedValue(false);
        mocks.consumePasswordResetToken.mockResolvedValue(false);
        await expect(handlerResetPassword(cfg, request({
            token: "a".repeat(64),
            newPassword: "a secure new password",
        }), res)).rejects.toMatchObject({
            message: "Invalid or expired password-reset token",
        });
    });

    it("returns the same public response while only creating a token for a real account", async () => {
        const existingResponse = response();
        mocks.getUserByEmail.mockResolvedValue(user);
        mocks.createPasswordResetToken.mockResolvedValue({
            expiresAt: new Date("2026-01-01T00:30:00Z"),
        });
        mocks.deliverPasswordReset.mockResolvedValue(undefined);

        await handlerRequestPasswordReset(
            cfg,
            request({ email: " Person@Example.com " }),
            existingResponse.res,
        );

        expect(mocks.createPasswordResetToken).toHaveBeenCalledWith("a".repeat(64), user.id);
        expect(existingResponse.status).toHaveBeenCalledWith(202);
        expect(existingResponse.json).toHaveBeenCalledWith({
            message: "If an account exists for that email, a password-reset link will be sent",
        });

        vi.clearAllMocks();
        const missingResponse = response();
        mocks.makePasswordResetToken.mockReturnValue("b".repeat(64));
        mocks.getUserByEmail.mockResolvedValue(undefined);
        await handlerRequestPasswordReset(
            cfg,
            request({ email: "missing@example.com" }),
            missingResponse.res,
        );

        expect(mocks.createPasswordResetToken).not.toHaveBeenCalled();
        expect(missingResponse.json).toHaveBeenCalledWith({
            message: "If an account exists for that email, a password-reset link will be sent",
        });
    });
});
