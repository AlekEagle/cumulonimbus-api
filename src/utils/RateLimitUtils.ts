import { Request, Response } from "express";
import { Errors } from "./TemplateResponses.js";

export function keyGenerator(req: Request) {
  return req.user
    ? req.user.id
    : (Array.isArray(req.headers["x-forwarded-for"])
        ? req.headers["x-forwarded-for"][0]
        : req.headers["x-forwarded-for"]) || req.ip;
}

export function handler(_: Request, res: Response) {
  res.status(429).send(new Errors.RateLimited());
}

const defaultRateLimitConfig = {
  windowMs: 60 * 1000 * 1, // 1 minutes
  max: 100,
  keyGenerator,
  handler,
  skipFailedRequests: false,
  standardHeaders: true,
  legacyHeaders: false,
};

export default defaultRateLimitConfig;
