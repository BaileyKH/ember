import { createHash } from "crypto";
import { MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH } from "./auth.js";
import { BadRequestError, ServiceUnavailableError } from "./api/errors.js";

export type PasswordContext = {
    email?: string;
    username?: string;
};

export function assertPasswordLength(password: unknown): asserts password is string {
    if (typeof password !== "string") {
        throw new BadRequestError("Password must be a string");
    }

    const characterCount = Array.from(password).length;
    if (characterCount < MIN_PASSWORD_LENGTH || characterCount > MAX_PASSWORD_LENGTH) {
        throw new BadRequestError(
            `Password must be between ${MIN_PASSWORD_LENGTH} and ${MAX_PASSWORD_LENGTH} characters`,
        );
    }
}

function isContextSpecificPassword(password: string, context: PasswordContext): boolean {
    const candidate = password.toLocaleLowerCase("en-US");
    const email = context.email?.trim().toLocaleLowerCase("en-US");
    const username = context.username?.trim().toLocaleLowerCase("en-US");
    const emailLocalPart = email?.split("@", 1)[0];

    return ["ember", email, emailLocalPart, username]
        .filter((value): value is string => Boolean(value && value.length >= MIN_PASSWORD_LENGTH))
        .includes(candidate);
}

export async function isCompromisedPassword(
    password: string,
    fetcher: typeof fetch = fetch,
): Promise<boolean> {
    const hash = createHash("sha1")
        .update(password, "utf8")
        .digest("hex")
        .toUpperCase();
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    let response: Response;
    try {
        response = await fetcher(
            `https://api.pwnedpasswords.com/range/${prefix}`,
            {
                headers: {
                    "Add-Padding": "true",
                    "User-Agent": "Ember-Password-Security",
                },
                signal: AbortSignal.timeout(5_000),
            },
        );
    } catch {
        throw new ServiceUnavailableError(
            "Password safety validation is temporarily unavailable",
        );
    }

    if (!response.ok) {
        throw new ServiceUnavailableError(
            "Password safety validation is temporarily unavailable",
        );
    }

    const matches = (await response.text()).split(/\r?\n/);
    return matches.some((line) => {
        const [candidateSuffix, count] = line.split(":", 2);
        return candidateSuffix === suffix && Number(count) > 0;
    });
}

export async function validateNewPassword(
    password: unknown,
    context: PasswordContext = {},
): Promise<string> {
    assertPasswordLength(password);

    if (isContextSpecificPassword(password, context)) {
        throw new BadRequestError(
            "Password must not match your email or username",
        );
    }

    if (await isCompromisedPassword(password)) {
        throw new BadRequestError(
            "This password has appeared in a data breach. Choose a different password",
        );
    }

    return password;
}
