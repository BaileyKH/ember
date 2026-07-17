import { afterEach, describe, expect, it, vi } from "vitest";
import {
    assertPasswordLength,
    isCompromisedPassword,
    validateNewPassword,
} from "./passwordPolicy.js";
import { BadRequestError, ServiceUnavailableError } from "./api/errors.js";

afterEach(() => {
    vi.unstubAllGlobals();
});

describe("password length policy", () => {
    it.each(["short", "a".repeat(129)])("rejects an invalid length", (password) => {
        expect(() => assertPasswordLength(password)).toThrow(BadRequestError);
    });

    it("allows long passphrases, spaces, and Unicode without composition rules", () => {
        expect(() => assertPasswordLength("correct horse battery staple 🏕️")).not.toThrow();
        expect(() => assertPasswordLength("all lowercase words are allowed")).not.toThrow();
    });
});

describe("compromised-password checks", () => {
    it("uses the padded HIBP range API and detects a matching hash suffix", async () => {
        const fetcher = vi.fn(async () => new Response(
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\nFFFF:0",
        ));

        await expect(isCompromisedPassword("password", fetcher)).resolves.toBe(true);
        expect(fetcher).toHaveBeenCalledWith(
            "https://api.pwnedpasswords.com/range/5BAA6",
            expect.objectContaining({
                headers: expect.objectContaining({ "Add-Padding": "true" }),
            }),
        );
    });

    it("rejects account-specific passwords without making a network request", async () => {
        const fetcher = vi.fn();
        vi.stubGlobal("fetch", fetcher);

        await expect(validateNewPassword(
            "person@example.com",
            { email: "person@example.com", username: "person" },
        )).rejects.toThrow("must not match your email or username");
        expect(fetcher).not.toHaveBeenCalled();
    });

    it("rejects passwords found in the breach corpus", async () => {
        vi.stubGlobal("fetch", vi.fn(async () => new Response(
            "5A8D778E5022FAB701977C5D840BBC486D0:2",
        )));

        await expect(validateNewPassword("Hello World")).rejects.toThrow(
            "data breach",
        );
    });

    it("fails safely when password validation is unavailable", async () => {
        const fetcher = vi.fn(async () => {
            throw new Error("offline");
        });

        await expect(isCompromisedPassword("a safe long password", fetcher))
            .rejects.toBeInstanceOf(ServiceUnavailableError);
    });
});
