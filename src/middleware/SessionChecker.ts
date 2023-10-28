import { logger } from '../index.js';
import type { Request, Response, NextFunction } from 'express';
import { Errors } from '../utils/TemplateResponses.js';

export default function SessionChecker(
  req: Request<any, any, any, any>,
  res: Response<any>,
  next: NextFunction,
) {
  if (!req.user) {
    logger.warn(
      `A request to a route that requires a session was made without a session. Route: ${req.path}`,
    );
    return res.status(401).json(new Errors.InvalidSession());
  } else {
    logger.debug(`SessionChecker: ${req.user.username}`);
    next();
  }
}
