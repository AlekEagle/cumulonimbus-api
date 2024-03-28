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
  generateWebAuthnRegistrationObject,
  verifyWebAuthnRegistration,
} from '../utils/SecondFactor.js';
import {
  extractToken,
  generateTOTPGenerationConfirmationToken,
  generateWebAuthnGenerationConfirmationToken,
  validateToken,
} from '../utils/Token.js';
import {
  SECOND_FACTOR_TOTP_ALGORITHM,
  SECOND_FACTOR_TOTP_DIGITS,
  SECOND_FACTOR_TOTP_STEP,
} from '../utils/Constants.js';
import SecondFactor from '../DB/SecondFactor.js';
import ReverifyIdentity from '../middleware/ReverifyIdentity.js';

import { Request, Response } from 'express';
import { errors as JoseErrors } from 'jose';

logger.debug('Loading: Second Factor routes...');

app.put(
  // PUT /api/users/me/2fa/totp
  '/api/users/me/2fa/totp',
  ReverifyIdentity(),
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  async (
    req,
    res: Response<
      | Cumulonimbus.Structures.SecondFactorTOTPRegistration
      | Cumulonimbus.Structures.Error
    >,
  ) => {
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
      secret,
      digits: SECOND_FACTOR_TOTP_DIGITS,
      algorithm: SECOND_FACTOR_TOTP_ALGORITHM,
      period: SECOND_FACTOR_TOTP_STEP,
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
  // PUT /api/users/me/2fa/webauthn
  '/api/users/me/2fa/webauthn',
  ReverifyIdentity(),
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  async (
    req,
    res: Response<
      | Cumulonimbus.Structures.SecondFactorWebAuthnRegistration
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    // Generate a WebAuthn registration challenge
    const challenge = await generateWebAuthnRegistrationObject(req.user),
      // Generate a WebAuthn registration token
      { token, data } = await generateWebAuthnGenerationConfirmationToken(
        req.user.id,
        challenge.challenge,
      );

    return res.status(200).json({
      token,
      exp: data.payload.exp,
      type: 'webauthn',
      ...challenge,
    });
  },
);

app.put(
  // PUT /api/users/me/2fa/webauthn/confirm
  '/api/users/me/2fa/webauthn/confirm',
  SessionChecker(),
  BodyValidator({
    token: 'string',
    name: 'string',
    response: 'any',
  }),
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  async (
    req: Request<null, null, { token: string; name: string; response: any }>,
    res: Response<
      | Cumulonimbus.Structures.SecondFactorRegisterSuccess
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    // Verify the registration response
    const result = await verifyWebAuthnRegistration(req, res, req.user);

    if (result === null) {
      // The response was invalid and an error was already sent. We're done here.
      return;
    } else {
      const { payload } = extractToken(req.body.token);
      await SecondFactor.create({
        id: payload.iat.toString(),
        name: req.body.name,
        user: payload.sub,
        type: 'webauthn',
        keyId: Buffer.from(result.registrationInfo.credentialID)
          .toString('base64url')
          .replace(/=/g, ''), // Obliterate the base64 padding from existence
        publicKey: Buffer.from(result.registrationInfo.credentialPublicKey),
        counter: result.registrationInfo.counter,
        deviceType: result.registrationInfo.credentialDeviceType,
        transports: req.body.response.response.transports,
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
        id: payload.iat.toString(),
        type: 'webauthn',
        name: req.body.name,
        backupCodes,
      });
    }
  },
);

// Regenerating backup codes will require identity re-verification.
app.put(
  // PUT /api/users/me/2fa/backup
  '/api/users/me/2fa/backup',
  ReverifyIdentity(),
  async (
    req: Request,
    res: Response<
      | Cumulonimbus.Structures.SecondFactorBackupRegisterSuccess
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    // Generate backup codes
    const { codes, hashed } = await generateBackupCodes();
    await req.user.update({
      twoFactorBackupCodes: hashed,
    });

    return res.status(201).json({
      codes,
    });
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
