import SecondFactor from '../DB/SecondFactor.js';
import { Errors } from '../utils/TemplateResponses.js';
import {
  generateSecondFactorIntermediateToken,
  validateToken,
} from '../utils/Token.js';
import { logger } from '../index.js';
import {
  verifyTOTP,
  verifyBackupCode,
  generateSecondFactorChallenge,
  verifySecondFactor,
  SecondFactorChallengeResponse,
} from '../utils/SecondFactor.js';

import { RequestHandler } from 'express';
import Bcrypt from 'bcrypt';
import { errors as JoseErrors } from 'jose';

// A middleware that will reverify the user's identity using their password or second factors.
// This can be used in place of SessionChecker.
// This MUST be used in an endpoint that does not use the GET method, as it requires a body.
export default function ReverifyIdentity(
  staffRequired: boolean = false,
): RequestHandler {
  return async (req, res, next) => {
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
      } else
        logger.debug(`Route: ${req.path} | staff required: ${staffRequired}`);
    }

    const secondFactors = await SecondFactor.findAll({
        where: {
          user: req.user.id,
        },
      }),
      availableFactors = secondFactors
        .map((factor) => factor.type)
        .filter((t, i, a) => a.indexOf(t) === i);

    // If they aren't responding to a challenge, check if they provided the correct password.
    if (!req.body['2fa'].token) {
      if (!req.body.password)
        // If they didn't provide a password, we will send an error response.
        return res.status(400).json(new Errors.MissingFields(['password']));
      // If they did provide a password, we will check if it is correct.
      else if (!(await Bcrypt.compare(req.body.password, req.user.password)))
        return res.status(401).json(new Errors.InvalidPassword());
    }

    // If they have second factors, we will also use them to reverify their identity.
    if (availableFactors.length !== 0) {
      // They are not responding to a challenge, so we will send them one.
      if (!req.body['2fa'].token) {
        return res
          .status(401)
          .json(await generateSecondFactorChallenge(req.user));
      } else {
        try {
          if (await verifySecondFactor(req.body['2fa'], req.user)) {
            logger.debug(
              `User ${req.user.username} (${req.user.id}) successfully reverified their identity using their second factor.`,
            );
            return next();
          }
        } catch (e) {
          // All errors thrown by verifySecondFactor should be forwarded to the user.
          if (e instanceof Errors.MissingFields) return res.status(400).json(e);
          else if (e instanceof Errors.Invalid2FAResponse)
            return res.status(401).json(e);
          else if (e instanceof Errors.Internal) return res.status(500).json(e);
          else if (e instanceof Errors.NotImplemented)
            return res.status(501).json(e);
          else {
            logger.error(
              `An unexpected error occurred while reverifying the user's identity using their second factor. User: ${req.user.username} (${req.user.id}) | Error: ${e}`,
            );
            return res.status(500).json(new Errors.Internal());
          }
        }
      }
    }
    // The user does not have any second factors, but their password is correct. There is no point in issuing a challenge that they would not be able to complete.
    else {
      logger.debug(
        `User ${req.user.username} (${req.user.id}) successfully reverified their identity using their password.`,
      );
      return next();
    }
  };
}
