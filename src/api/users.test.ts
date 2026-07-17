import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Request, Response } from "express";

const mocks = vi.hoisted(() => ({
    validateNewPassword: vi.fn(),
    hashPassword: vi.fn(),
    createUser: vi.fn(),
}));

vi.mock("../passwordPolicy.js", () => ({
    validateNewPassword: mocks.validateNewPassword,
}));

vi.mock("../auth.js", () => ({
    hashPassword: mocks.hashPassword,
}));

vi.mock("../db/queries/users.js", () => ({
    createUser: mocks.createUser,
}));

import { handlerUserCreate } from "./users.js";

const createdUser = {
    id: "45d56584-fb3d-47cc-9fcb-a504d1e2714c",
    createdAt: new Date(),
    updatedAt: new Date(),
    email: "person@example.com",
    profileImg: null,
    username: "person",
    hashedPassword: "argon2-hash",
    sessionVersion: 0,
};

function response() {
    const status = vi.fn();
    const json = vi.fn();
    const res = { status, json } as unknown as Response;
    status.mockReturnValue(res);
    json.mockReturnValue(res);
    return { res, status, json };
}

beforeEach(() => {
    vi.clearAllMocks();
    mocks.validateNewPassword.mockResolvedValue("a secure password");
    mocks.hashPassword.mockResolvedValue("argon2-hash");
    mocks.createUser.mockResolvedValue(createdUser);
});

describe("user registration password policy", () => {
    it("validates the complete password before hashing and stores no plaintext", async () => {
        const { res, status, json } = response();
        const req = {
            body: {
                email: " Person@Example.COM ",
                username: " person ",
                password: "a secure password",
            },
        } as Request;

        await handlerUserCreate(req, res);

        expect(mocks.validateNewPassword).toHaveBeenCalledWith(
            "a secure password",
            { email: "person@example.com", username: "person" },
        );
        expect(mocks.hashPassword).toHaveBeenCalledWith("a secure password");
        expect(mocks.createUser).toHaveBeenCalledWith({
            email: "person@example.com",
            username: "person",
            hashedPassword: "argon2-hash",
        });
        expect(status).toHaveBeenCalledWith(201);
        expect(json.mock.calls[0][0]).not.toHaveProperty("hashedPassword");
        expect(json.mock.calls[0][0]).not.toHaveProperty("sessionVersion");
    });

    it("does not hash or create a user when password validation fails", async () => {
        const { res } = response();
        mocks.validateNewPassword.mockRejectedValue(new Error("weak password"));

        await expect(handlerUserCreate({
            body: {
                email: "person@example.com",
                username: "person",
                password: "weak password",
            },
        } as Request, res)).rejects.toThrow("weak password");

        expect(mocks.hashPassword).not.toHaveBeenCalled();
        expect(mocks.createUser).not.toHaveBeenCalled();
    });
});
