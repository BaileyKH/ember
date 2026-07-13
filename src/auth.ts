import { randomBytes } from "crypto";
import * as argon2 from "argon2"

export const ACCESS_TOKEN_ISSUER = "ember-access";

export async function hashPassword(password: string): Promise<string> {
    return await argon2.hash(password)
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
    return await argon2.verify(hash, password)
}