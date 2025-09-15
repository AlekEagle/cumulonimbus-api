import { app, logger, ratelimitStore } from '../index.js';
import { Errors, Success } from '../utils/TemplateResponses.js';
import KillSwitch from '../middleware/KillSwitch.js';
import SessionChecker from '../middleware/SessionChecker.js';
import BodyValidator, {
  ExtendedValidBodyTypes,
} from '../middleware/BodyValidator.js';
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
import Ratelimit from '../middleware/Ratelimit.js';
import LimitOffset from '../middleware/LimitOffset.js';
import KVExtractor from '../utils/KVExtractor.js';
import User from '../DB/User.js';
import SessionPermissionChecker, {
  PermissionFlags,
} from '../middleware/SessionPermissionChecker.js';

import { Request, Response } from 'express';
import { errors as JoseErrors } from 'jose';
import ms from 'ms';

logger.debug('Loading: Second Factor routes...');

app.post(
  // POST /api/users/me/2fa/totp
  '/api/users/me/2fa/totp',
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  ReverifyIdentity(),
  SessionPermissionChecker(), // Require a standard browser session
  Ratelimit({
    max: 3,
    window: ms('1d'),
    storage: ratelimitStore,
  }),
  async (
    req,
    res: Response<
      | Cumulonimbus.Structures.SecondFactorTOTPRegistration
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
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

app.post(
  // POST /api/users/me/2fa/totp/confirm
  '/api/users/me/2fa/totp/confirm',
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  SessionChecker(),
  SessionPermissionChecker(), // Require a standard browser session
  BodyValidator({
    token: 'string',
    name: 'string',
    code: 'string',
  }),
  async (
    req: Request<null, null, { token: string; name: string; code: string }>,
    res: Response<
      | Cumulonimbus.Structures.SecondFactorRegisterSuccess
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Validate the token
    const result = await validateToken(req.body.token);
    if (result instanceof Error) {
      if (result instanceof JoseErrors.JWTExpired)
        return res.status(401).json(new Errors.InvalidSecondFactorResponse());
    } else {
      // Verify the TOTP code
      if (!(await verifyTOTP(req.body.code, result.payload.secret)))
        return res.status(401).json(new Errors.InvalidSecondFactorResponse());

      // Store the TOTP secret in the database
      await SecondFactor.create({
        id: result.payload.iat.toString(),
        name: req.body.name,
        user: result.payload.sub,
        type: 'totp',
        secret: result.payload.secret,
      });

      let codes;

      if (!req.user.twoFactorBackupCodes) {
        // Generate backup codes
        const { codes: unhashedCodes, hashed } = await generateBackupCodes();
        codes = unhashedCodes;
        await req.user.update({
          twoFactorBackupCodes: hashed,
        });
      }

      return res.status(201).json({
        id: result.payload.iat.toString(),
        type: 'totp',
        name: req.body.name,
        codes,
      });
    }
  },
);

app.post(
  // POST /api/users/me/2fa/webauthn
  '/api/users/me/2fa/webauthn',
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  ReverifyIdentity(),
  SessionPermissionChecker(), // Require a standard browser session
  Ratelimit({
    max: 3,
    window: ms('1d'),
    storage: ratelimitStore,
  }),
  async (
    req,
    res: Response<
      | Cumulonimbus.Structures.SecondFactorWebAuthnRegistration
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
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

app.post(
  // POST /api/users/me/2fa/webauthn/confirm
  '/api/users/me/2fa/webauthn/confirm',
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  SessionChecker(),
  SessionPermissionChecker(), // Require a standard browser session
  BodyValidator({
    token: 'string',
    name: 'string',
    response: 'any',
  }),
  async (
    req: Request<{}, {}, { token: string; name: string; response: any }>,
    res: Response<
      | Cumulonimbus.Structures.SecondFactorRegisterSuccess
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
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
        keyId: result.registrationInfo!.credential.id.replace(/=/g, ''), // Obliterate the base64 padding from existence
        publicKey: Buffer.from(result.registrationInfo!.credential.publicKey),
        counter: result.registrationInfo!.credential.counter,
        deviceType: result.registrationInfo!.credentialDeviceType,
        transports: req.body.response.response.transports,
      });

      let codes;

      if (!req.user.twoFactorBackupCodes) {
        // Generate backup codes
        const { codes: unhashedCodes, hashed } = await generateBackupCodes();
        codes = unhashedCodes;
        await req.user.update({
          twoFactorBackupCodes: hashed,
        });
      }

      return res.status(201).json({
        id: payload.iat.toString(),
        type: 'webauthn',
        name: req.body.name,
        codes,
      });
    }
  },
);

app.post(
  // POST /api/users/me/2fa/backup
  '/api/users/me/2fa/backup',
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  ReverifyIdentity(),
  SessionPermissionChecker(), // Require a standard browser session
  Ratelimit({
    max: 1,
    window: ms('1d'),
    storage: ratelimitStore,
  }),
  async (
    req: Request,
    res: Response<
      | Cumulonimbus.Structures.SecondFactorBackupRegisterSuccess
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Generate backup codes
    const { codes, hashed } = await generateBackupCodes();
    await req.user.update({
      twoFactorBackupCodes: hashed,
      twoFactorBackupCodeUsedAt: null,
    });

    return res.status(201).json({
      codes,
    });
  },
);

app.get(
  // GET /api/users/me/2fa
  '/api/users/me/2fa',
  SessionChecker(),
  SessionPermissionChecker(PermissionFlags.SECOND_FACTOR_READ),
  LimitOffset(0, 50),
  Ratelimit({
    storage: ratelimitStore,
  }),
  async (
    req: Request,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.SecondFactor>
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    try {
      // Get the user's second factors
      const factors = await SecondFactor.findAndCountAll({
        where: {
          user: req.user.id,
        },
        order: [['createdAt', 'DESC']],
        limit: req.limit,
        offset: req.offset,
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) fetched their second factors. (offset: ${req.offset}, limit: ${req.limit})`,
      );

      // Return the second factors
      return res.status(200).json({
        count: factors.count,
        items: factors.rows.map((factor) =>
          KVExtractor(factor.toJSON(), ['id', 'name']),
        ),
      });
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/users/:id/2fa
  '/api/users/:id/2fa',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_READ_SECOND_FACTORS),
  LimitOffset(0, 50),
  async (
    req: Request<{ id: string }>,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.SecondFactor>
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    try {
      const user = await User.findByPk(req.params.id);
      if (!user) return res.status(404).json(new Errors.InvalidUser());

      // Get the user's second factors
      const factors = await SecondFactor.findAndCountAll({
        where: {
          user: req.params.id,
        },
        order: [['createdAt', 'DESC']],
        limit: req.limit,
        offset: req.offset,
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) fetched user ${user.username} (${user.id})'s second factors. (offset: ${req.offset}, limit: ${req.limit})`,
      );

      // Return the second factors
      return res.status(200).json({
        count: factors.count,
        items: factors.rows.map((factor) =>
          KVExtractor(factor.toJSON(), ['id', 'name']),
        ),
      });
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/users/me/2fa/:id
  '/api/users/me/2fa/:id',
  SessionChecker(),
  SessionPermissionChecker(PermissionFlags.SECOND_FACTOR_READ),
  Ratelimit({
    storage: ratelimitStore,
  }),
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.SecondFactor | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Find the second factor
    const factor = await SecondFactor.findByPk(req.params.id);
    if (!factor) return res.status(404).json(new Errors.InvalidSecondFactor());

    logger.debug(
      `User ${req.user.username} (${req.user.id}) fetched their second factor ${factor.name} (${factor.id}).`,
    );

    return res
      .status(200)
      .json(
        KVExtractor(factor.toJSON(), [
          'id',
          'type',
          'name',
          'usedAt',
          'createdAt',
          'updatedAt',
        ]),
      );
  },
);

app.get(
  // GET /api/users/:uid/2fa/:id
  '/api/users/:uid/2fa/:id',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_READ_SECOND_FACTORS),
  async (
    req: Request<{ uid: string; id: string }>,
    res: Response<
      Cumulonimbus.Structures.SecondFactor | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Find the user
    const user = await User.findByPk(req.params.uid);
    if (!user) return res.status(404).json(new Errors.InvalidUser());

    // Find the second factor
    const factor = await SecondFactor.findByPk(req.params.id);
    if (!factor) return res.status(404).json(new Errors.InvalidSecondFactor());

    logger.debug(
      `User ${req.user.username} (${req.user.id}) fetched user ${user.username} (${user.id})'s second factor ${factor.name} (${factor.id}).`,
    );

    return res
      .status(200)
      .json(
        KVExtractor(factor.toJSON(), [
          'id',
          'type',
          'name',
          'usedAt',
          'createdAt',
          'updatedAt',
        ]),
      );
  },
);

app.delete(
  // DELETE /api/users/me/2fa/:id
  '/api/users/me/2fa/:id',
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  ReverifyIdentity(),
  SessionPermissionChecker(), // Require a standard browser session
  Ratelimit({
    max: 10,
    window: ms('1d'),
    storage: ratelimitStore,
  }),
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Find the second factor
    const factor = await SecondFactor.findByPk(req.params.id);
    if (!factor) return res.status(404).json(new Errors.InvalidSecondFactor());

    // Delete the second factor
    await factor.destroy();

    // Check if the user has any second factors left
    const remainingFactors = await SecondFactor.count({
      where: {
        user: req.user.id,
      },
    });

    if (remainingFactors === 0) {
      // If the user has no second factors left, delete their backup codes and reset the backup codes used at date
      await req.user.update({
        twoFactorBackupCodes: null,
        twoFactorBackupCodeUsedAt: null,
      });
    }

    logger.debug(
      `User ${req.user.username} (${req.user.id}) deleted their second factor ${factor.name} (${factor.id}). Remaining factors: ${remainingFactors}.`,
    );

    return res.status(200).json(new Success.DeleteSecondFactor());
  },
);

app.delete(
  // DELETE /api/users/:uid/2fa/:id
  '/api/users/:uid/2fa/:id',
  ReverifyIdentity(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_SECOND_FACTORS),
  async (
    req: Request<{ uid: string; id: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Find the user
    const user = await User.findByPk(req.params.uid);
    if (!user) return res.status(404).json(new Errors.InvalidUser());

    // Find the second factor
    const factor = await SecondFactor.findByPk(req.params.id);
    if (!factor) return res.status(404).json(new Errors.InvalidSecondFactor());

    // Delete the second factor
    await factor.destroy();

    // Check if the user has any second factors left
    const remainingFactors = await SecondFactor.count({
      where: {
        user: req.params.uid,
      },
    });

    if (remainingFactors === 0) {
      // If the user has no second factors left, delete their backup codes and reset the backup codes used at date
      await user.update({
        twoFactorBackupCodes: null,
        twoFactorBackupCodeUsedAt: null,
      });
    }

    logger.debug(
      `User ${req.user.username} (${req.user.id}) deleted user ${user.username} (${user.id})'s second factor ${factor.name} (${factor.id}). Remaining factors: ${remainingFactors}.`,
    );

    return res.status(200).json(new Success.DeleteSecondFactor());
  },
);

app.delete(
  // DELETE /api/users/me/2fa
  '/api/users/me/2fa',
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  ReverifyIdentity(),
  SessionPermissionChecker(), // Require a standard browser session
  BodyValidator({
    ids: new ExtendedValidBodyTypes().array('string'),
  }),
  Ratelimit({
    max: 5,
    window: ms('1d'),
    storage: ratelimitStore,
  }),
  async (
    req: Request<null, null, { ids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Find the second factors
    const factors = await SecondFactor.findAll({
      where: {
        user: req.user.id,
        id: req.body.ids,
      },
    });

    // Delete the second factors
    await Promise.all(factors.map((factor) => factor.destroy()));

    // Check if the user has any second factors left
    const remainingFactors = await SecondFactor.count({
      where: {
        user: req.user.id,
      },
    });

    if (remainingFactors === 0) {
      // If the user has no second factors left, delete their backup codes and reset the backup codes used at date
      await req.user.update({
        twoFactorBackupCodes: null,
        twoFactorBackupCodeUsedAt: null,
      });
    }

    logger.debug(
      `User ${req.user.username} (${req.user.id}) deleted ${factors.length} second factor(s). Remaining factors: ${remainingFactors}.`,
    );

    return res
      .status(200)
      .json(new Success.DeleteSecondFactors(factors.length));
  },
);

app.delete(
  // DELETE /api/users/:uid/2fa
  '/api/users/:uid/2fa',
  ReverifyIdentity(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_SECOND_FACTORS),
  BodyValidator({
    ids: new ExtendedValidBodyTypes().array('string'),
  }),
  async (
    req: Request<{ uid: string }, null, { ids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Find the user
    const user = await User.findByPk(req.params.uid);
    if (!user) return res.status(404).json(new Errors.InvalidUser());

    // Find the second factors
    const factors = await SecondFactor.findAll({
      where: {
        user: req.params.uid,
        id: req.body.ids,
      },
    });

    // Delete the second factors
    await Promise.all(factors.map((factor) => factor.destroy()));

    // Check if the user has any second factors left
    const remainingFactors = await SecondFactor.count({
      where: {
        user: req.params.uid,
      },
    });

    if (remainingFactors === 0) {
      // If the user has no second factors left, delete their backup codes and reset the backup codes used at date
      await user.update({
        twoFactorBackupCodes: null,
        twoFactorBackupCodeUsedAt: null,
      });
    }

    logger.debug(
      `User ${req.user.username} (${req.user.id}) deleted user ${user.username} (${user.id})'s ${factors.length} second factor(s). Remaining factors: ${remainingFactors}.`,
    );

    return res
      .status(200)
      .json(new Success.DeleteSecondFactors(factors.length));
  },
);

app.delete(
  // DELETE /api/users/me/2fa/all
  '/api/users/me/2fa/all',
  KillSwitch(KillSwitches.ACCOUNT_MODIFY),
  ReverifyIdentity(),
  SessionPermissionChecker(), // Require a standard browser session
  Ratelimit({
    max: 5,
    window: ms('1d'),
    storage: ratelimitStore,
  }),
  async (
    req: Request,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Find the second factors
    const factors = await SecondFactor.findAll({
      where: {
        user: req.user.id,
      },
    });

    // Delete the second factors
    await Promise.all(factors.map((factor) => factor.destroy()));

    // Delete the user's backup codes and reset the backup codes used at date
    await req.user.update({
      twoFactorBackupCodes: null,
      twoFactorBackupCodeUsedAt: null,
    });

    logger.debug(
      `User ${req.user.username} (${req.user.id}) deleted all of their second factors.`,
    );

    return res
      .status(200)
      .json(new Success.DeleteSecondFactors(factors.length));
  },
);

app.delete(
  // DELETE /api/users/:uid/2fa/all
  '/api/users/:uid/2fa/all',
  ReverifyIdentity(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_SECOND_FACTORS),
  async (
    req: Request<{ uid: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Find the user
    const user = await User.findByPk(req.params.uid);
    if (!user) return res.status(404).json(new Errors.InvalidUser());

    // Find the second factors
    const factors = await SecondFactor.findAll({
      where: {
        user: req.params.uid,
      },
    });

    // Delete the second factors
    await Promise.all(factors.map((factor) => factor.destroy()));

    // Delete the user's backup codes and reset the backup codes used at date
    await user.update({
      twoFactorBackupCodes: null,
      twoFactorBackupCodeUsedAt: null,
    });

    logger.debug(
      `User ${req.user.username} (${req.user.id}) deleted all of user ${user.username} (${user.id})'s second factors.`,
    );

    return res
      .status(200)
      .json(new Success.DeleteSecondFactors(factors.length));
  },
);
