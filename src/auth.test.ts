import { describe, it, expect } from "vitest";
import { Request } from "express";
import jwt from "jsonwebtoken";
import {
    ACCESS_TOKEN_AUDIENCE,
    ACCESS_TOKEN_ISSUER,
    DUMMY_PASSWORD_HASH,
    makeJWT,
    validateJWT,
    validateJWTSession,
    getBearerToken,
    verifyPassword,
} from "./auth.js";

describe("Dummy password verification", () => {
    it("uses a valid Argon2id hash and rejects an arbitrary password", async () => {
        await expect(
            verifyPassword(DUMMY_PASSWORD_HASH, "not-the-dummy-password"),
        ).resolves.toBe(false);
    });
});

describe("Validating JWTs", () => {
    const userID = "user123";
    const secret = "a".repeat(32);
    const expiresIn = 60;

    it("should create a valid JWT token", () => {
        const result = makeJWT(userID, secret, expiresIn)
        const validatedJWT = validateJWT(result, secret)
        expect(validatedJWT).toBe(userID)
        expect(jwt.decode(result)).toMatchObject({
            aud: ACCESS_TOKEN_AUDIENCE,
            iss: ACCESS_TOKEN_ISSUER,
            ver: 0,
        });
    })

    it("should throw an error for expired token", () => {
        const expired = -1
        const result = makeJWT(userID, secret, expired)

        expect(() => validateJWT(result, secret)).toThrow()
    })

    it("should throw an error for incorrect secret", () => {
        const wrongSecret = "b".repeat(32)
        const result = makeJWT(userID, secret, expiresIn)

        expect(() => validateJWT(result, wrongSecret)).toThrow()
    })

    it("should reject a token intended for another audience", () => {
        const result = jwt.sign(
            {
                iss: ACCESS_TOKEN_ISSUER,
                aud: "another-service",
                sub: userID,
            },
            secret,
            { algorithm: "HS256", expiresIn },
        );

        expect(() => validateJWT(result, secret)).toThrow()
    })

    it("should reject an HS256 secret shorter than 32 bytes", () => {
        expect(() => makeJWT(userID, "too-short", expiresIn)).toThrow(
            "JWT secret must be at least 32 bytes",
        );
    })

    it("includes and validates the session version", () => {
        const result = makeJWT(userID, secret, expiresIn, 7);
        expect(validateJWTSession(result, secret)).toEqual({
            userId: userID,
            sessionVersion: 7,
        });
    });

    it("rejects a token without a session version", () => {
        const legacyToken = jwt.sign(
            {
                iss: ACCESS_TOKEN_ISSUER,
                aud: ACCESS_TOKEN_AUDIENCE,
                sub: userID,
            },
            secret,
            { algorithm: "HS256", expiresIn },
        );

        expect(() => validateJWT(legacyToken, secret)).toThrow(
            "Invalid token payload",
        );
    });
})

describe("Validating Auth Header", () => {

    function getMockRequest(headers: Record<string, string>) {
        return {
            get: (key: string) => headers[key],
        };
    }

    it("should return a valid token", () => {
        const validToken = "Bearer 1234567890"
        const req = getMockRequest({ "Authorization": validToken }) as unknown as Request;
        const result = getBearerToken(req)

        expect(result).toBe("1234567890")
    })

    it("should throw an error for incorrect auth", () => {
        const invalidToken = "1234567890"
        const req = getMockRequest({ "Authorization": invalidToken }) as unknown as Request;

        expect(() => getBearerToken(req)).toThrow()
    })

    it("should throw an error for missing auth", () => {
        const req = getMockRequest({}) as unknown as Request;

        expect(() => getBearerToken(req)).toThrow()
    })
})
