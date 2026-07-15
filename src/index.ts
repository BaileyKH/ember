import express, { Request, Response, NextFunction } from "express";
import { cfg } from "./config.js";
import { middlewareErrorHandler } from "./api/middleware.js";
import { handlerUserCreate } from "./api/users.js";
import { handlerReset } from "./api/reset.js";

const app = express()
const PORT = cfg.port

app.use(express.json());

app.post("/api/users", (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(handlerUserCreate(req, res)).catch(next)
})

app.post("/api/reset", (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(handlerReset(cfg, req, res)).catch(next)
})

app.use(middlewareErrorHandler);

app.listen(PORT, () => {
    console.log(`Server started on Port: ${PORT}`)
})