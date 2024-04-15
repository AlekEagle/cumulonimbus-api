import { Request, Response, NextFunction } from 'express';
import { errors } from 'jose';

import { Errors } from '../utils/TemplateResponses.js';
import { logger } from '../index.js';
import { validateToken } from '../utils/Token.js';
import User from '../DB/User.js';
import Session from '../DB/Session.js';

export default async function AuthProvider(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  // Check if the request has a token to be validated
  if (req.headers.authorization) {
    try {
      // Validate and retrieve token
      let token = await validateToken(req.headers.authorization);
      // Check if token is actually valid
      if (token instanceof Error) {
        // If token is invalid, set user and session to null
        logger.debug('Token validation failed, continuing unauthenticated.');
        if (token instanceof errors.JWTExpired) logger.debug('Token expired.');
        else logger.debug('Error: ', token);

        req.user = null;
        req.session = null;
      } else {
        // Find the user that the token belongs to
        const user = await User.findByPk(token.payload.sub);
        // Check if user exists
        if (!user) {
          // If user does not exist, set user and session to null
          logger.debug('Request contained valid token for non-existent user.');
          req.user = null;
          req.session = null;
        } else {
          // Cool, the user exists, let's see if that session has been revoked.
          const session = await Session.findOne({
            where: {
              user: user.id,
              id: token.payload.iat.toString(),
            },
          });

          // If the session doesn't exist in the database, it's been revoked.
          if (!session) {
            logger.debug(
              `Request contained valid token for user ${user.username} (${user.id}), but has since been revoked.`,
            );
            req.user = null;
            req.session = null;
          } else {
            // If the session exists, then the user is authenticated.
            logger.debug(
              `Request contained valid token for user ${user.username} (${user.id}).`,
            );
            // Since the user is authenticated and the session is valid, we'll update the session's last used time.
            await session.update({ usedAt: new Date() });
            req.user = user;
            req.session = session;
          }
        }
      }
    } catch (error) {
      // If an error occurs, log it and return a 500 Internal Server Error
      logger.error(error);
      res.status(500).json(new Errors.Internal());
      return;
    }
  }
  next();
}
