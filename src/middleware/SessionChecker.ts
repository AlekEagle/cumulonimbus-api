import { logger } from '../index.js';
import type { RequestHandler } from 'express';
import { Errors } from '../utils/TemplateResponses.js';

export default function SessionChecker(
  staffRequired: boolean = false,
): RequestHandler {
  return (req, res, next) => {
    if (!req.user) {
      logger.warn(
        `A request to a route that requires a session was made without a session. Route: ${req.path}`,
      );
      return res.status(401).json(new Errors.InvalidSession());
    } else {
      if (staffRequired && !req.user.staff) {
        logger.warn(
          `A request to a route that requires staff privileges was made without staff privileges. Route: ${req.path} | User: ${req.user.username} (${req.user.id})`,
        );
        return res.status(403).json(new Errors.InsufficientPermissions());
      } else if (staffRequired && req.user.twoFactorBackupCodes === null) {
        logger.warn(
          `A request to a route that requires staff privileges was made without a second factor enrolled. Route: ${req.path} | User: ${req.user.username} (${req.user.id})`,
        );
        return res.status(401).json(new Errors.EndpointRequiresSecondFactor());
      } else {
        logger.debug(
          `Route: ${req.path} | staff required: ${staffRequired} | User: ${req.user.username} (${req.user.id})`,
        );
        next();
      }
    }
  };
}
