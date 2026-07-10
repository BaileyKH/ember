import express from "express";
import { cfg } from "./config.js";
import { middlewareErrorHandler } from "./api/middleware.js";

const app = express()
const PORT = cfg.port

app.use(express.json());

app.use(middlewareErrorHandler);

app.listen(PORT, () => {
    console.log(`Server started on Port: ${PORT}`)
})