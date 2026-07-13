import express, { Request, Response, NextFunction } from "express";
import { cfg } from "./config.js";
import { middlewareErrorHandler } from "./api/middleware.js";
import { handlerUserCreate } from "./api/users.js";

const app = express()
const PORT = cfg.port

app.use(express.json());

app.use(middlewareErrorHandler);

app.post("/api/users", (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(handlerUserCreate(req, res)).catch(next)
})

app.listen(PORT, () => {
    console.log(`Server started on Port: ${PORT}`)
})