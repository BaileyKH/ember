import type { ApiConfig } from "./config.js";
import { ServiceUnavailableError } from "./api/errors.js";

export function assertPasswordResetDeliveryConfigured(cfg: ApiConfig): void {
    if (cfg.platform === "dev") return;

    if (
        !cfg.passwordResetUrl ||
        !cfg.passwordResetWebhookUrl ||
        !cfg.passwordResetWebhookSecret
    ) {
        throw new ServiceUnavailableError(
            "Password reset is temporarily unavailable",
        );
    }
}

export async function deliverPasswordReset(
    cfg: ApiConfig,
    email: string,
    token: string,
    expiresAt: Date,
): Promise<void> {
    if (
        !cfg.passwordResetUrl ||
        !cfg.passwordResetWebhookUrl ||
        !cfg.passwordResetWebhookSecret
    ) {
        return;
    }

    const resetUrl = new URL(cfg.passwordResetUrl);
    resetUrl.searchParams.set("token", token);

    const response = await fetch(cfg.passwordResetWebhookUrl, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${cfg.passwordResetWebhookSecret}`,
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            to: email,
            resetUrl: resetUrl.toString(),
            expiresAt: expiresAt.toISOString(),
        }),
        signal: AbortSignal.timeout(10_000),
    });

    if (!response.ok) {
        throw new Error(`Password-reset delivery failed with status ${response.status}`);
    }
}
