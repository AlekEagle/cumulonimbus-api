import { Errors } from '../utils/TemplateResponses.js';
import { RequestHandler } from 'express';
import logger from '../utils/LogMachine.js';

export default function BanHammer(): RequestHandler {
  return (req, res, next) => {
    if (req.user?.bannedAt) {
      logger.warn(
        `Banned user ${req.user.username} (${req.user.id}) attempted to access ${req.originalUrl}`,
      );
      return res.status(403).json(new Errors.Banned());
    }
    next();
  };
}
