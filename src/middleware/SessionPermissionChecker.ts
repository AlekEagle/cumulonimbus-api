import { logger } from '../index.js';
import { Errors } from '../utils/TemplateResponses.js';

import { RequestHandler } from 'express';

export enum PermissionFlags {
  ALL = 1 << 0,
  UPLOAD_FILE = 1 << 1,
  ACCOUNT_READ = 1 << 2,
  ACCOUNT_MODIFY = 1 << 3,
  SECOND_FACTOR_READ = 1 << 4,
  SESSION_READ = 1 << 5,
  SESSION_MODIFY = 1 << 6,
  FILE_READ = 1 << 7,
  FILE_MODIFY = 1 << 8,
  STAFF_READ_ACCOUNTS = 1 << 9,
  STAFF_MODIFY_ACCOUNTS = 1 << 10,
  STAFF_READ_SECOND_FACTORS = 1 << 11,
  STAFF_MODIFY_SECOND_FACTORS = 1 << 12,
  STAFF_READ_SESSIONS = 1 << 13,
  STAFF_MODIFY_SESSIONS = 1 << 14,
  STAFF_READ_FILES = 1 << 15,
  STAFF_MODIFY_FILES = 1 << 16,
  STAFF_MODIFY_DOMAINS = 1 << 17,
  STAFF_MODIFY_INSTRUCTIONS = 1 << 18,
  STAFF_MODIFY_KILLSWITCHES = 1 << 19,
}

export enum PermissionGroups {
  ACCOUNT = PermissionFlags.ACCOUNT_READ | PermissionFlags.ACCOUNT_MODIFY,
  SESSION = PermissionFlags.SESSION_READ | PermissionFlags.SESSION_MODIFY,
  FILE = PermissionFlags.FILE_READ | PermissionFlags.FILE_MODIFY,
  STAFF = PermissionFlags.STAFF_READ_ACCOUNTS |
    PermissionFlags.STAFF_MODIFY_ACCOUNTS |
    PermissionFlags.STAFF_READ_SECOND_FACTORS |
    PermissionFlags.STAFF_MODIFY_SECOND_FACTORS |
    PermissionFlags.STAFF_READ_SESSIONS |
    PermissionFlags.STAFF_MODIFY_SESSIONS |
    PermissionFlags.STAFF_READ_FILES |
    PermissionFlags.STAFF_MODIFY_FILES |
    PermissionFlags.STAFF_MODIFY_DOMAINS |
    PermissionFlags.STAFF_MODIFY_INSTRUCTIONS |
    PermissionFlags.STAFF_MODIFY_KILLSWITCHES,
  STAFF_ACCOUNTS = PermissionFlags.STAFF_READ_ACCOUNTS |
    PermissionFlags.STAFF_MODIFY_ACCOUNTS,
  STAFF_SECOND_FACTORS = PermissionFlags.STAFF_READ_SECOND_FACTORS |
    PermissionFlags.STAFF_MODIFY_SECOND_FACTORS,
  STAFF_SESSIONS = PermissionFlags.STAFF_READ_SESSIONS |
    PermissionFlags.STAFF_MODIFY_SESSIONS,
  STAFF_FILES = PermissionFlags.STAFF_READ_FILES |
    PermissionFlags.STAFF_MODIFY_FILES,
  STAFF_ONLY = PermissionFlags.STAFF_MODIFY_DOMAINS |
    PermissionFlags.STAFF_MODIFY_INSTRUCTIONS |
    PermissionFlags.STAFF_MODIFY_KILLSWITCHES,
}

export default function SessionPermissionChecker(
  requiredPermissionFlags?: PermissionFlags,
): RequestHandler {
  return async function (req, res, next) {
    if (!req.user || !req.session)
      return res.status(401).json(new Errors.InvalidSession());
    if (req.session.permissionFlags === null) {
      logger.debug(
        `User ${req.user.username}'s (${req.user.id}) session ${req.session.name} (${req.session.id}) is a standard browser session and does not have any permissionFlags. Required permissionFlags: ${requiredPermissionFlags}`,
      );
      next();
    } else if (requiredPermissionFlags === undefined) {
      // If the requiredPermissionFlags are not defined, then the route is assumed to only be available to standard browser sessions.
      if (req.session.permissionFlags === null) {
        next();
      } else {
        logger.warn(
          `User ${req.user.username}'s (${req.user.id}) scoped session ${req.session.name} (${req.session.id}) attempted to access a resource that required a standard browser session. PermissionFlags: ${req.session.permissionFlags}`,
        );
        res.status(403).send(new Errors.InsufficientPermissions());
      }
    } else if (
      req.session.permissionFlags & PermissionFlags.ALL ||
      req.session.permissionFlags & requiredPermissionFlags
    ) {
      next();
    } else {
      logger.warn(
        `User ${req.user.username}'s (${req.user.id}) session ${req.session.name} (${req.session.id}) with permissionFlags ${req.session.permissionFlags} tried to access a resource that required these permissionFlags ${requiredPermissionFlags}`,
      );
      res.status(403).send(new Errors.InsufficientPermissions());
    }
  };
}
