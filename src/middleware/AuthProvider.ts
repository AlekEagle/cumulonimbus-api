import { Request, Response, NextFunction } from "express";
import { Sequelize } from "sequelize";

import { Errors } from "../utils/TemplateResponses.js";
import { logger } from "../index.js";
import { TokenStructure, validateToken } from "../utils/Token.js";
import User from "../DB/User.js";
import staleSessionPruner from "../utils/StaleSessionPruner.js";

export default async function AuthProvider(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  // Check if the request has a token to be validated
  if (req.headers.authorization) {
    logger.debug("Authorization header found, validating token...");
    try {
      // Validate and retrieve token
      let token = await validateToken(req.headers.authorization);
      // Check if token is actually valid
      if (token instanceof Error) {
        // If token is invalid, set user and session to null
        logger.debug("Token validation failed, continuing unauthenticated.");
        logger.debug("Error: ", token);
        req.user = null;
        req.session = null;
      } else {
        logger.debug("Token validation succeeded, fetching associated user...");
        let user = await User.findOne({
          where: Sequelize.where(Sequelize.col("id"), token.payload.sub),
        });
        // Check if user exists
        if (!user) {
          // If user does not exist, set user and session to null
          logger.debug("User not found, continuing unauthenticated.");
          req.user = null;
          req.session = null;
        } else {
          // Check if the user is banned
          logger.debug("User found, checking if user is banned...");
          if (user.bannedAt) {
            // If user is banned, return a 403 Forbidden error
            logger.warn(
              `User ${user.username} (${user.id}) attempted to access the API but is banned.`
            );
            res.status(403).json(new Errors.Banned());
            return;
          } else {
            // Check if this session has been revoked
            logger.debug(
              "User is not banned, checking if session is revoked..."
            );
            if (
              user.sessions.some(
                (s) => s.iat === (token as TokenStructure).payload.iat
              )
            ) {
              // If session is not revoked, prune expired sessions and set user and session
              logger.debug(
                "Session is not revoked, pruning expired sessions..."
              );
              await staleSessionPruner(user);
              logger.debug("Pruning complete, continuing authenticated.");
              req.user = user;
              req.session = token;
            } else {
              // If session is revoked, set user and session to null
              logger.debug("Session is revoked, continuing unauthenticated.");
              req.user = null;
              req.session = null;
            }
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
