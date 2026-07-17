import express, { Request, Response, NextFunction } from "express";
import cookieParser from "cookie-parser";
import { cfg } from "./config.js";
import { middlewareErrorHandler } from "./api/middleware.js";
import { middlewareCors, middlewareTrustedOrigin } from "./api/security.js";
import {
    createLoginRateLimiters,
    createPasswordRateLimiters,
    createRegistrationRateLimiter,
} from "./api/rateLimit.js";
import { handlerUserCreate } from "./api/users.js";
import { handlerLogin, handlerRefresh, handlerRevoke } from "./api/auth.js";
import { handlerReset } from "./api/reset.js";
import {
    handlerChangePassword,
    handlerRequestPasswordReset,
    handlerResetPassword,
} from "./api/passwords.js";
import { middlewareAuthenticate } from "./api/authenticate.js";

const app = express()
const PORT = cfg.port
const { loginIpLimiter, loginAccountIpLimiter } = createLoginRateLimiters(cfg)
const registrationLimiter = createRegistrationRateLimiter()
const {
    forgotPasswordIpLimiter,
    forgotPasswordAccountIpLimiter,
    resetPasswordIpLimiter,
    changePasswordIpLimiter,
} = createPasswordRateLimiters(cfg)

app.disable("x-powered-by");
if (cfg.trustProxy !== undefined) {
    app.set("trust proxy", cfg.trustProxy);
}
app.use(express.json());
app.use(cookieParser());
app.use(middlewareCors(cfg));

app.post(
    "/api/users",
    middlewareTrustedOrigin(cfg),
    registrationLimiter,
    (req: Request, res: Response, next: NextFunction) => {
        Promise.resolve(handlerUserCreate(req, res)).catch(next)
    },
)

app.post(
    "/api/login",
    middlewareTrustedOrigin(cfg),
    loginIpLimiter,
    loginAccountIpLimiter,
    (req: Request, res: Response, next: NextFunction) => {
        Promise.resolve(handlerLogin(cfg, req, res)).catch(next)
    },
)

app.post("/api/refresh", (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(handlerRefresh(cfg, req, res)).catch(next)
})

app.post("/api/reset", (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(handlerReset(cfg, req, res)).catch(next)
})

app.post("/api/revoke", (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(handlerRevoke(cfg, req, res)).catch(next)
})

app.post(
    "/api/password/forgot",
    middlewareTrustedOrigin(cfg),
    forgotPasswordIpLimiter,
    forgotPasswordAccountIpLimiter,
    (req: Request, res: Response, next: NextFunction) => {
        Promise.resolve(handlerRequestPasswordReset(cfg, req, res)).catch(next)
    },
)

app.post(
    "/api/password/reset",
    middlewareTrustedOrigin(cfg),
    resetPasswordIpLimiter,
    (req: Request, res: Response, next: NextFunction) => {
        Promise.resolve(handlerResetPassword(cfg, req, res)).catch(next)
    },
)

app.post(
    "/api/password/change",
    middlewareTrustedOrigin(cfg),
    changePasswordIpLimiter,
    middlewareAuthenticate(cfg),
    (req: Request, res: Response, next: NextFunction) => {
        Promise.resolve(handlerChangePassword(cfg, req, res)).catch(next)
    },
)

app.use(middlewareErrorHandler);

app.listen(PORT, () => {
    console.log(`Server started on Port: ${PORT}`)
})
