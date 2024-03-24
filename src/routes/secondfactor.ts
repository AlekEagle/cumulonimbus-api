import { app, logger } from '../index.js';
import { Errors } from '../utils/TemplateResponses.js';
import KillSwitch from '../middleware/KillSwitch.js';
import SessionChecker from '../middleware/SessionChecker.js';
import BodyValidator from '../middleware/BodyValidator.js';
import { KillSwitches } from '../utils/GlobalKillSwitches.js';
import {
  generateTOTPSecret,
  verifyTOTP,
  generateBackupCodes,
} from '../utils/SecondFactor.js';
import {
  generateTOTPGenerationConfirmationToken,
  validateToken,
} from '../utils/Token.js';
import {
  SECOND_FACTOR_ALGORITHM,
  SECOND_FACTOR_TOTP_DIGITS,
  SECOND_FACTOR_TOTP_STEP,
} from '../utils/Constants.js';
import SecondFactor from '../DB/SecondFactor.js';

import { Request, Response } from 'express';
import Bcrypt from 'bcrypt';
import { errors as JoseErrors } from 'jose';

logger.debug('Loading: Second Factor routes...');

app.put(
  // PUT /api/users/me/2fa
  '/api/users/me/2fa',
  SessionChecker(),
  BodyValidator({
    type: 'string',
    password: 'string',
  }),
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  async (
    req: Request<null, null, { type: 'totp' | 'webauthn'; password: string }>,
    res: Response<
      | Cumulonimbus.Structures.TwoFactorRegistration
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    // Check if the user's password is correct.
    if (!(await Bcrypt.compare(req.body.password, req.user.password)))
      return res.status(401).send(new Errors.InvalidPassword());
    // Handle the type of 2FA the user wants to add.
    switch (req.body.type) {
      case 'totp':
        const secret = await generateTOTPSecret(),
          confirmationToken = await generateTOTPGenerationConfirmationToken(
            req.user.id,
            secret,
          );

        logger.debug(
          `User ${req.user.username} (${req.user.id}) requested to add a new TOTP second factor.`,
        );

        return res.status(200).send({
          token: confirmationToken.token,
          exp: confirmationToken.data.payload.exp,
          type: 'totp',
          data: {
            secret: secret,
            algorithm: SECOND_FACTOR_ALGORITHM,
            digits: SECOND_FACTOR_TOTP_DIGITS,
            period: SECOND_FACTOR_TOTP_STEP,
          },
        });
      case 'webauthn':
        return res.status(501).send(new Errors.NotImplemented());
      default:
        return res.status(400).send(new Errors.Invalid2FAMethod());
    }
  },
);

app.put(
  // PUT /api/users/me/2fa/finish
  '/api/users/me/2fa/finish',
  SessionChecker(),
  BodyValidator({
    token: 'string',
    type: 'string',
    name: 'string',
    data: 'any',
  }),
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  async (
    req: Request<
      null,
      null,
      {
        token: string;
        type: 'totp' | 'webauthn';
        name: string;
        data:
          | {
              code: string;
            }
          | never;
      }
    >,
    res: Response<
      | Cumulonimbus.Structures.TwoFactorRegisterSuccess
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    // Check if the provided TwoFactorRegistration token is valid.
    const result = await validateToken(req.body.token);
    if (result instanceof Error) {
      if (result instanceof JoseErrors.JWTExpired)
        return res.status(400).send(new Errors.Invalid2FARegistration());
    }
    // Check if the token is for the user.
    else if (result.payload.sub !== req.user.id)
      return res.status(400).send(new Errors.Invalid2FARegistration());
    else
      switch (req.body.type) {
        case 'totp':
          // Check if the provided code is valid.
          if (!verifyTOTP(req.body.data.code, result.payload.secret))
            return res.status(400).send(new Errors.Invalid2FAResponse());

          // Save the new TOTP second factor.
          await SecondFactor.create({
            id: result.payload.iat.toString(),
            user: req.user.id,
            type: 'totp',
            name: req.body.name,
            secret: result.payload.secret,
          });

          // If the user has no 2FA backup codes, generate them.
          if (
            !req.user.twoFactorBackupCodes ||
            req.user.twoFactorBackupCodes.length === 0
          ) {
            const { codes, hashed } = await generateBackupCodes();
            await req.user.update({
              twoFactorBackupCodes: hashed,
            });

            logger.debug(
              `User ${req.user.username} (${req.user.id}) added a new TOTP second factor and generated backup codes.`,
            );

            return res.status(201).send({
              id: result.payload.iat.toString(),
              name: req.body.name,
              type: 'totp',
              backupCodes: codes,
            });
          } else {
            logger.debug(
              `User ${req.user.username} (${req.user.id}) added a new TOTP second factor.`,
            );
            return res.status(201).send({
              id: result.payload.iat.toString(),
              name: req.body.name,
              type: 'totp',
            });
          }
        case 'webauthn':
          return res.status(501).send(new Errors.NotImplemented());
        default:
          return res.status(400).send(new Errors.Invalid2FAMethod());
      }
  },
);
