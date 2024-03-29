import { logger } from '../index.js';
import { Errors } from '../utils/TemplateResponses.js';

import { RequestHandler } from 'express';

export enum PermissionFlags {
  ALL = 1 << 0,
  UPLOAD_FILE = 1 << 1,
  ACCOUNT_READ = 1 << 2,
  ACCOUNT_MODIFY = 1 << 3,
  SESSION_READ = 1 << 4,
  SESSION_MODIFY = 1 << 5,
  SESSION_CREATE = 1 << 6,
  FILE_READ = 1 << 7,
  FILE_MODIFY = 1 << 8,
  STAFF_READ = 1 << 9,
  STAFF_MODIFY = 1 << 10,
}

export enum PermissionGroups {
  ACCOUNT = PermissionFlags.ACCOUNT_READ | PermissionFlags.ACCOUNT_MODIFY,
  SESSION = PermissionFlags.SESSION_READ |
    PermissionFlags.SESSION_MODIFY |
    PermissionFlags.SESSION_CREATE,
  FILE = PermissionFlags.FILE_READ | PermissionFlags.FILE_MODIFY,
  STAFF = PermissionFlags.STAFF_READ | PermissionFlags.STAFF_MODIFY,
}

export default function SessionPermissionChecker(
  requiredPermissionFlags: PermissionFlags,
): RequestHandler {
  return async function (req, res, next) {
    if (!req.session.permissionFlags) {
      logger.debug(
        `User ${req.user.username}'s (${req.user.id}) session ${req.session.name} (${req.session.id}) is a standard browser session and does not have any permissionFlags. Required permissionFlags: ${requiredPermissionFlags}`,
      );
      next();
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
