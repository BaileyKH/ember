import { Request, Response, NextFunction } from "express";
import { cfg } from "../config.js";
import {
  BadRequestError,
  NotFoundError,
  UserForbiddenError,
  UserNotAuthenticatedError,
} from "./errors.js";


export function middlewareErrorHandler(err: Error, req: Request, res: Response, next: NextFunction) {
  let statusCode = 500;
  let message = "Something went wrong on our end";

  if (err instanceof BadRequestError) {
    statusCode = 400;
    message = err.message;
  } else if (err instanceof UserNotAuthenticatedError) {
    statusCode = 401;
    message = err.message;
  } else if (err instanceof UserForbiddenError) {
    statusCode = 403;
    message = err.message;
  } else if (err instanceof NotFoundError) {
    statusCode = 404;
    message = err.message;
  }

  if (statusCode >= 500) {
    const errStr = errStringFromError(err);
    if (cfg.platform === "dev") {
      message = errStr;
    }
    console.log(errStr);
  }

  return res.status(statusCode).json({ error: message })
}

function errStringFromError(err: unknown) {
  if (typeof err === "string") return err;
  if (err instanceof Error) return err.message;
  return "An unknown error occurred";
}