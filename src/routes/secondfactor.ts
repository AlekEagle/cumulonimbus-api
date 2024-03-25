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
import ReverifyIdentity from '../middleware/ReverifyIdentity.js';

import { Request, Response } from 'express';
import Bcrypt from 'bcrypt';
import { errors as JoseErrors } from 'jose';

logger.debug('Loading: Second Factor routes...');

app.put(
  // PUT /api/users/me/2fa/totp
  '/api/users/me/2fa/totp',
  SessionChecker(),
  BodyValidator({
    password: 'string',
  }),
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  async (
    req: Request<null, null, { password: string }>,
    res: Response<
      | Cumulonimbus.Structures.SecondFactorTOTPRegistration
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    // Verify the user's password
    if (!(await Bcrypt.compare(req.body.password, req.user.password)))
      return res.status(401).json(new Errors.InvalidPassword());

    // Generate a TOTP secret
    const secret = await generateTOTPSecret(),
      // Generate a TOTP registration token
      { token, data } = await generateTOTPGenerationConfirmationToken(
        req.user.id,
        secret,
      );

    return res.status(200).json({
      token,
      exp: data.payload.exp,
      type: 'totp',
      data: {
        secret,
        digits: SECOND_FACTOR_TOTP_DIGITS,
        algorithm: SECOND_FACTOR_ALGORITHM,
        period: SECOND_FACTOR_TOTP_STEP,
      },
    });
  },
);

app.put(
  // PUT /api/users/me/2fa/totp/confirm
  '/api/users/me/2fa/totp/confirm',
  SessionChecker(),
  BodyValidator({
    token: 'string',
    name: 'string',
    code: 'string',
  }),
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  async (
    req: Request<null, null, { token: string; name: string; code: string }>,
    res: Response<
      | Cumulonimbus.Structures.SecondFactorRegisterSuccess
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    // Validate the token
    const result = await validateToken(req.body.token);
    if (result instanceof Error) {
      if (result instanceof JoseErrors.JWTExpired)
        return res.status(401).json(new Errors.Invalid2FAResponse());
    } else {
      // Verify the TOTP code
      if (!(await verifyTOTP(req.body.code, result.payload.secret)))
        return res.status(401).json(new Errors.Invalid2FAResponse());

      // Store the TOTP secret in the database
      await SecondFactor.create({
        id: result.payload.iat.toString(),
        name: req.body.name,
        user: result.payload.sub,
        type: 'totp',
        secret: result.payload.secret,
      });

      let backupCodes;

      if (!req.user.twoFactorBackupCodes) {
        // Generate backup codes
        const { codes, hashed } = await generateBackupCodes();
        backupCodes = codes;
        await req.user.update({
          twoFactorBackupCodes: hashed,
        });
      }

      return res.status(201).json({
        id: result.payload.iat.toString(),
        type: 'totp',
        name: req.body.name,
        backupCodes,
      });
    }
  },
);

app.put(
  // PUT /api/users/me/2fa/test
  '/api/users/me/2fa/test',
  ReverifyIdentity(),
  async (
    req: Request,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    return res.status(200).json({
      code: '2FA_TEST_SUCCESS',
      message: 'Successfully authenticated with 2FA!',
    });
  },
);
