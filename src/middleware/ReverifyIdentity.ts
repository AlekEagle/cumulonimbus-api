import SecondFactor from '../DB/SecondFactor.js';
import { Errors } from '../utils/TemplateResponses.js';
import {
  generateSecondFactorIntermediateToken,
  validateToken,
} from '../utils/Token.js';
import { logger } from '../index.js';
import { verifyTOTP } from '../utils/SecondFactor.js';

import { RequestHandler } from 'express';
import Bcrypt from 'bcrypt';
import { errors as JoseErrors } from 'jose';

export default function ReverifyIdentity(): RequestHandler {
  return async (req, res, next) => {
    if (!req.user) {
      res.status(401).send(new Errors.InvalidSession());
      return;
    }

    const secondFactors = await SecondFactor.findAll({
        where: {
          user: req.user.id,
        },
      }),
      availableFactors = secondFactors
        .map((factor) => factor.type)
        .filter((t, i, a) => a.indexOf(t) === i);

    // If they have second factors, we will also use them to reverify their identity.
    if (availableFactors.length !== 0) {
      // Check if they have already been challenged.
      if (!req.body.token) {
        // This will interrupt the request and send a second factor challenge.
        const token = await generateSecondFactorIntermediateToken(req.user.id);

        if (availableFactors.includes('webauthn'))
          logger.warn(
            'User has a WebAuthn second factor, but challenging it is not yet implemented!',
          );

        return res.status(401).send({
          token: token.token,
          exp: token.data.payload.exp,
          types: availableFactors,
        } as Cumulonimbus.Structures.SecondFactorChallenge);
      } else {
        // Validate the token.
        const result = await validateToken(req.body.token);

        if (result instanceof Error) {
          if (result instanceof JoseErrors.JWTExpired)
            return res.status(401).send(new Errors.Invalid2FAResponse());
        } else if (result.payload.sub !== req.user.id) {
          return res.status(401).send(new Errors.Invalid2FAResponse());
        }

        // Check if the challenge matches what we expect.
        else
          switch (req.body.type) {
            case 'totp':
              // Go through each TOTP second factor and check if the code is valid.
              let valid = false;
              for (let factor of secondFactors.filter(
                (factor) => factor.type === 'totp',
              )) {
                if (await verifyTOTP(req.body.code, factor.secret)) {
                  valid = true;
                  break;
                }
              }
              if (!valid)
                return res.status(401).send(new Errors.Invalid2FAResponse());
              else
                logger.debug(
                  `User ${req.user.username} (${req.user.id}) reverified their identity with a TOTP second factor.`,
                );
              break;
            case 'webauthn':
              logger.warn(
                'User has a WebAuthn second factor, but validating it is not yet implemented!',
              );
              return res.status(501).send(new Errors.NotImplemented());
          }
      }
    }
    // If they don't have second factors, we will use their password to reverify their identity.
    else if (!(await Bcrypt.compare(req.body.password, req.user.password)))
      return res.status(401).send(new Errors.InvalidPassword());

    next();
  };
}
