import SecondFactor from '../DB/SecondFactor.js';
import { Errors } from '../utils/TemplateResponses.js';
import { logger } from '../index.js';
import {
  generateSecondFactorChallenge,
  verifySecondFactor,
} from '../utils/SecondFactor.js';

import { RequestHandler } from 'express';
import Bcrypt from 'bcrypt';

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
        logger.debug(
          `Route: ${req.path} | staff required: ${staffRequired} | User: ${req.user.username} (${req.user.id})`,
        );
    }

    // If the session the user is using is a scoped session, we will skip the reverify process.
    if (req.session.permissionFlags !== null) return next();

    // Check if the user provided a body. If they didn't, we will send an error response.
    if (!req.body)
      return res.status(400).json(new Errors.MissingFields(['password']));

    const secondFactors = await SecondFactor.findAll({
        where: {
          user: req.user.id,
        },
      }),
      availableFactors = secondFactors
        .map((factor) => factor.type)
        .filter((t, i, a) => a.indexOf(t) === i);

    // If they aren't responding to a challenge, check if they provided the correct password.
    if (!req.body['2fa'] || !req.body['2fa'].token) {
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
      try {
        if (!req.body['2fa'] || !req.body['2fa'].token) {
          return res
            .status(401)
            .json(await generateSecondFactorChallenge(req.user));
        } else {
          if (await verifySecondFactor(req.body['2fa'], req.user, res)) {
            logger.debug(
              `User ${req.user.username} (${req.user.id}) successfully reverified their identity using their second factor.`,
            );
            return next();
          }
        }
      } catch (e) {
        logger.error(e);
        return res.status(500).json(new Errors.Internal());
      }
    }
    // The user does not have any second factors, but their password is correct. There is no point in issuing a challenge that they would not be able to complete.
    else {
      // If the endpoint requires staff privileges, but they don't have any second factors, we will send an error response.
      if (staffRequired) {
        logger.warn(
          `User ${req.user.username} (${req.user.id}) attempted to access a staff-only endpoint without any second factors. Route: ${req.path}`,
        );
        return res.status(401).json(new Errors.EndpointRequires2FA());
      }
      logger.debug(
        `User ${req.user.username} (${req.user.id}) successfully reverified their identity using their password.`,
      );
      return next();
    }
    // We somehow reached this point, not sure its even possible, but we will include this snippet just in case.
    logger.warn(
      `We somehow exited the primary logic of ReverifyIdentity. Route: ${req.path} | User: ${req.user.username} (${req.user.id})`,
    );
    return res.status(500).json(new Errors.Internal());
  };
}
