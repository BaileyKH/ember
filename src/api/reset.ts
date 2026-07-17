import express, { Request, Response, NextFunction } from "express";
import { type ApiConfig } from "../config.js";
import { reset } from "../db/queries/users.js";
import { UserForbiddenError } from "./errors.js";
import { assertTrustedOrigin } from "./security.js";

export async function handlerReset(cfg: ApiConfig, req: Request, res: Response) {
  assertTrustedOrigin(cfg, req);

  if (cfg.platform !== "dev") {
    throw new UserForbiddenError("Reset is only allowed in dev environment.");
  }

  await reset();
  return res.status(200).json({ message: "Database reset to initial state" });
}
