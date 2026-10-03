import { Request, Response } from 'express';
import { Errors } from './TemplateResponses.js';

function IPResolver(req: Request): string {
  return (req.headers['cf-connecting-ip'] as string) || req.ip!;
}

export function keyGenerator(req: Request): string {
  return req.user ? req.user.id : IPResolver(req);
}

export function handler(_: Request, res: Response) {
  res.status(429).json(new Errors.RateLimited());
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
