import type { Request, Response } from "express";
import type { ApiConfig } from "../config.js";
import {
    hashPassword,
    makePasswordResetToken,
    verifyPassword,
} from "../auth.js";
import {
    changePasswordAndRevokeSessions,
    getUserByEmail,
} from "../db/queries/users.js";
import {
    consumePasswordResetToken,
    createPasswordResetToken,
    deletePasswordResetToken,
    getUserByValidPasswordResetToken,
} from "../db/queries/passwordReset.js";
import {
    assertPasswordResetDeliveryConfigured,
    deliverPasswordReset,
} from "../passwordResetDelivery.js";
import { validateNewPassword } from "../passwordPolicy.js";
import { BadRequestError, UserNotAuthenticatedError } from "./errors.js";
import { assertTrustedOrigin } from "./security.js";
import { getAuthenticatedUser } from "./authenticate.js";

const RESET_REQUEST_MESSAGE =
    "If an account exists for that email, a password-reset link will be sent";
const RESET_TOKEN_PATTERN = /^[a-f0-9]{64}$/i;
const RESET_REQUEST_MINIMUM_MS = 250;

function clearRefreshCookie(cfg: ApiConfig, res: Response): void {
    res.clearCookie("ember_refresh", {
        httpOnly: true,
        secure: cfg.platform !== "dev",
        sameSite: "strict",
        path: "/api",
    });
}

function waitForMinimumDuration(startedAt: number): Promise<void> {
    const remaining = RESET_REQUEST_MINIMUM_MS - (Date.now() - startedAt);
    return remaining > 0
        ? new Promise((resolve) => setTimeout(resolve, remaining))
        : Promise.resolve();
}

export async function handlerRequestPasswordReset(
    cfg: ApiConfig,
    req: Request,
    res: Response,
) {
    assertTrustedOrigin(cfg, req);
    assertPasswordResetDeliveryConfigured(cfg);
    const startedAt = Date.now();
    const email = req.body?.email;

    if (typeof email !== "string" || email.trim().length === 0) {
        throw new BadRequestError("Please provide a valid email address");
    }

    const normalizedEmail = email.toLowerCase().trim();
    const token = makePasswordResetToken();
    const user = await getUserByEmail(normalizedEmail);

    if (user) {
        const created = await createPasswordResetToken(token, user.id);
        if (!created) throw new Error("Failed to create password-reset token");

        void deliverPasswordReset(
            cfg,
            user.email,
            token,
            created.expiresAt,
        ).catch(async (error) => {
            await deletePasswordResetToken(token).catch(() => undefined);
            console.error(
                error instanceof Error
                    ? `Password-reset delivery failed: ${error.message}`
                    : "Password-reset delivery failed",
            );
        });
    }

    await waitForMinimumDuration(startedAt);
    res.setHeader("Cache-Control", "no-store");

    return res.status(202).json({
        message: RESET_REQUEST_MESSAGE,
        ...(cfg.platform === "dev" ? { resetToken: token } : {}),
    });
}

export async function handlerResetPassword(
    cfg: ApiConfig,
    req: Request,
    res: Response,
) {
    assertTrustedOrigin(cfg, req);
    const { token, newPassword } = req.body ?? {};

    if (typeof token !== "string" || !RESET_TOKEN_PATTERN.test(token)) {
        throw new BadRequestError("Invalid or expired password-reset token");
    }

    const user = await getUserByValidPasswordResetToken(token);
    if (!user) {
        throw new BadRequestError("Invalid or expired password-reset token");
    }

    await validateNewPassword(newPassword, {
        email: user.email,
        username: user.username,
    });

    if (await verifyPassword(user.hashedPassword, newPassword)) {
        throw new BadRequestError("New password must be different from the current password");
    }

    const hashedPassword = await hashPassword(newPassword);
    const consumed = await consumePasswordResetToken(
        token,
        user.id,
        hashedPassword,
    );
    if (!consumed) {
        throw new BadRequestError("Invalid or expired password-reset token");
    }

    clearRefreshCookie(cfg, res);
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).json({
        message: "Password reset successfully. Please sign in again",
    });
}

export async function handlerChangePassword(
    cfg: ApiConfig,
    req: Request,
    res: Response,
) {
    assertTrustedOrigin(cfg, req);
    const user = getAuthenticatedUser(res);

    const { currentPassword, newPassword } = req.body ?? {};
    if (typeof currentPassword !== "string") {
        throw new BadRequestError("Current password is required");
    }

    if (!(await verifyPassword(user.hashedPassword, currentPassword))) {
        throw new UserNotAuthenticatedError("Current password is incorrect");
    }

    await validateNewPassword(newPassword, {
        email: user.email,
        username: user.username,
    });

    if (await verifyPassword(user.hashedPassword, newPassword)) {
        throw new BadRequestError("New password must be different from the current password");
    }

    const hashedPassword = await hashPassword(newPassword);
    const updated = await changePasswordAndRevokeSessions(user.id, hashedPassword);
    if (!updated) {
        throw new UserNotAuthenticatedError("Invalid or expired token");
    }

    clearRefreshCookie(cfg, res);
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).json({
        message: "Password changed successfully. Please sign in again",
    });
}
