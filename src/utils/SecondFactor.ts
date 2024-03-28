import {
  SECOND_FACTOR_TOTP_ALGORITHM,
  SECOND_FACTOR_BACKUP_CODE_ALGORITHM,
  SECOND_FACTOR_BACKUP_CODE_LENGTH,
  SECOND_FACTOR_INTERMEDIATE_TOKEN_EXPIRY,
  SECOND_FACTOR_TOTP_DIGITS,
  SECOND_FACTOR_TOTP_STEP,
} from './Constants.js';
import User from '../DB/User.js';
import SecondFactor from '../DB/SecondFactor.js';
import { Errors } from './TemplateResponses.js';
import { logger } from '../index.js';
import {
  generateSecondFactorIntermediateToken,
  validateToken,
} from './Token.js';

import { HashAlgorithms } from '@otplib/core';
import { authenticator } from '@otplib/preset-default-async';
import { randomBytes, createHash } from 'crypto';
import { errors as JoseErrors } from 'jose';
import { Request, Response } from 'express';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  VerifiedRegistrationResponse,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { AuthenticationResponseJSON } from '@simplewebauthn/types';
import ms from 'ms';

authenticator.options = {
  window: [2, 1],
  step: SECOND_FACTOR_TOTP_STEP,
  digits: SECOND_FACTOR_TOTP_DIGITS,
  algorithm: HashAlgorithms[SECOND_FACTOR_TOTP_ALGORITHM],
};

export interface BaseSecondFactorChallengeResponse {
  token: string;
  type: string;
}

export interface TOTPSecondFactorChallengeResponse
  extends BaseSecondFactorChallengeResponse {
  type: 'totp';
  code: string;
}

export interface BackupCodeSecondFactorChallengeResponse
  extends BaseSecondFactorChallengeResponse {
  type: 'backup';
  code: string;
}

export interface WebAuthnSecondFactorChallengeResponse
  extends BaseSecondFactorChallengeResponse {
  type: 'webauthn';
  response: AuthenticationResponseJSON;
}

export type SecondFactorChallengeResponse =
  | TOTPSecondFactorChallengeResponse
  | BackupCodeSecondFactorChallengeResponse
  | WebAuthnSecondFactorChallengeResponse;

export async function generateTOTPSecret(): Promise<string> {
  return await authenticator.generateSecret();
}

export async function generateTOTP(secret: string): Promise<string> {
  return await authenticator.generate(secret);
}

export async function checkTOTPDelta(
  token: string,
  secret: string,
): Promise<number | null> {
  const delta = await authenticator.checkDelta(token, secret);
  return delta;
}

export async function verifyTOTP(
  token: string,
  secret: string,
): Promise<boolean> {
  return (await checkTOTPDelta(token, secret)) !== null;
}

function generateBackupCode(): Promise<{
  code: string;
  hashed: string;
}> {
  return new Promise((resolve, reject) => {
    randomBytes(SECOND_FACTOR_BACKUP_CODE_LENGTH, (err, buf) => {
      if (err) return reject(err);
      const code = buf.toString('hex');
      const hashed = createHash(SECOND_FACTOR_BACKUP_CODE_ALGORITHM)
        .update(code)
        .digest('hex');
      resolve({ code, hashed });
    });
  });
}

export async function generateBackupCodes(): Promise<{
  codes: string[];
  hashed: string[];
}> {
  const codes = [];
  const hashed = [];
  for (let i = 0; i < 10; i++) {
    const { code, hashed: h } = await generateBackupCode();
    codes.push(code);
    hashed.push(h);
  }
  return { codes, hashed };
}

export function verifyBackupCode(code: string, hashed: string): boolean {
  return (
    createHash(SECOND_FACTOR_BACKUP_CODE_ALGORITHM)
      .update(code)
      .digest('hex') === hashed
  );
}

export async function generateWebAuthnRegistrationObject(user: User) {
  const existingWebAuthnCredentials = await SecondFactor.findAll({
    where: {
      user: user.id,
      type: 'webauthn',
    },
  });
  return await generateRegistrationOptions({
    rpName: 'Cumulonimbus',
    rpID: process.env.WEBAUTHN_RPID,
    userID: user.id,
    userName: user.username,
    timeout: ms(SECOND_FACTOR_INTERMEDIATE_TOKEN_EXPIRY),
    attestationType: 'none',
    excludeCredentials: existingWebAuthnCredentials.map((cred) => ({
      id: Buffer.from(cred.keyId, 'base64url'),
      type: 'public-key',
      transports: cred.transports,
    })),
    authenticatorSelection: {
      userVerification: 'preferred',
    },
  });
}

export async function generateWebAuthnChallenge(user: User) {
  return await generateAuthenticationOptions({
    rpID: process.env.WEBAUTHN_RPID,
    timeout: ms(SECOND_FACTOR_INTERMEDIATE_TOKEN_EXPIRY),
    allowCredentials: (
      await SecondFactor.findAll({
        where: {
          user: user.id,
          type: 'webauthn',
        },
      })
    ).map((cred) => ({
      id: Buffer.from(cred.keyId, 'base64'),
      type: 'public-key',
      transports: cred.transports,
    })),
    userVerification: 'preferred',
  });
}

export async function generateSecondFactorChallenge(
  user: User,
): Promise<Errors.Challenge2FARequired> {
  const secondFactors = await SecondFactor.findAll({
    where: { user: user.id },
  });

  if (secondFactors.length === 0) {
    throw new Error('User does not have any second factors!');
  }

  const availableFactors = secondFactors
    .map((factor) => factor.type)
    .filter((t, i, a) => a.indexOf(t) === i);

  let challenge;

  if (availableFactors.includes('webauthn'))
    challenge = await generateWebAuthnChallenge(user);

  const token = await generateSecondFactorIntermediateToken(
    user.id,
    challenge?.challenge,
  );

  return {
    code: 'CHALLENGE_2FA_REQUIRED_ERROR',
    message: 'Challenge 2FA Required',
    token: token.token,
    exp: token.data.payload.exp,
    types: [...availableFactors, 'backup'],
    challenge,
  };
}

export async function verifyWebAuthnRegistration(
  req: Request,
  res: Response,
  user: User,
): Promise<VerifiedRegistrationResponse | null> {
  const result = await validateToken(req.body.token);

  if (result instanceof Error) {
    if (result instanceof JoseErrors.JWTExpired) {
      logger.debug(
        `User ${user.username} (${user.id}) attempted to use an expired 2FA WebAuthn registration token.`,
      );
      res.status(401).json(new Errors.Invalid2FAResponse());
      return null;
    }
  } else if (!result.payload.challenge) {
    logger.warn(
      `User ${user.username} (${user.id}) attempted to use a non-2FA WebAuthn registration token (no challenge).`,
    );
    res.status(401).json(new Errors.Invalid2FAResponse());
    return null;
  } else if (result.payload.sub !== user.id) {
    logger.warn(
      `User ${user.username} (${user.id}) attempted to use a 2FA WebAuthn registration token that does not belong to them.`,
    );
    res.status(401).json(new Errors.Invalid2FAResponse());
    return null;
  } else {
    const verification = await verifyRegistrationResponse({
      response: req.body.response,
      expectedChallenge: result.payload.challenge,
      expectedOrigin: process.env.FRONTEND_BASE_URL,
      expectedRPID: process.env.WEBAUTHN_RPID,
      requireUserVerification: false,
    });

    if (verification.verified) {
      return verification;
    } else {
      logger.debug(
        `User ${user.username} (${user.id}) attempted to register a WebAuthn credential, but it was not able to be verified.`,
      );
      res.status(401).json(new Errors.Invalid2FAResponse());
      return null;
    }
  }
}

export async function verifyWebAuthnAuthentication(
  response: AuthenticationResponseJSON,
  token: string,
  res: Response,
  user: User,
): Promise<boolean> {
  const result = await validateToken(token);

  if (result instanceof Error) {
    if (result instanceof JoseErrors.JWTExpired) {
      logger.debug(
        `User ${user.username} (${user.id}) attempted to use an expired 2FA intermediate token.`,
      );
      res.status(401).json(new Errors.Invalid2FAResponse());
      return false;
    }
  } else if (result.payload.sub !== user.id) {
    logger.warn(
      `User ${user.username} (${user.id}) attempted to use a 2FA intermediate token that does not belong to them.`,
    );
    res.status(401).json(new Errors.Invalid2FAResponse());
    return false;
  } else {
    try {
      // Find the WebAuthn credential that was used
      const credential = await SecondFactor.findOne({
        where: {
          user: user.id,
          type: 'webauthn',
          keyId: response.id,
        },
      });

      // Check if the credential exists
      if (!credential) {
        logger.warn(
          `User ${user.username} (${user.id}) attempted to authenticate with a WebAuthn credential that does not exist.`,
        );
        res.status(401).json(new Errors.Invalid2FAResponse());
        return false;
      }

      const verification = await verifyAuthenticationResponse({
        authenticator: {
          counter: credential.counter,
          credentialID: Buffer.from(credential.keyId, 'base64url'),
          credentialPublicKey: credential.publicKey,
          transports: credential.transports,
        },
        response,
        expectedChallenge: result.payload.challenge,
        expectedOrigin: process.env.FRONTEND_BASE_URL,
        expectedRPID: process.env.WEBAUTHN_RPID,
        requireUserVerification: false,
      });

      if (verification.verified) {
        return true;
      } else {
        logger.debug(
          `User ${user.username} (${user.id}) attempted to authenticate with a WebAuthn credential, but it was not able to be verified.`,
        );
        res.status(401).json(new Errors.Invalid2FAResponse());
        return false;
      }
    } catch (e) {
      logger.error(
        `User ${user.username} (${user.id}) attempted to authenticate with a WebAuthn credential, but an error occurred: ${e}`,
      );
      res.status(500).json(new Errors.Internal());
      return false;
    }
  }
}

// This will handle all second factor challenge verification logic
export async function verifySecondFactor(
  challenge: SecondFactorChallengeResponse,
  user: User,
  res: Response,
): Promise<boolean> {
  // Validate the token.
  const result = await validateToken(challenge.token);

  if (result instanceof Error) {
    if (result instanceof JoseErrors.JWTExpired) {
      logger.debug(
        `User ${user.username} (${user.id}) attempted to use an expired 2FA intermediate token.`,
      );
      res.status(401).json(new Errors.Invalid2FAResponse());
      return false;
    }
  } else if (result.payload.sub !== user.id) {
    logger.warn(
      `User ${user.username} (${user.id}) attempted to use a 2FA intermediate token that does not belong to them.`,
    );
    res.status(401).json(new Errors.Invalid2FAResponse());
    return false;
  } else
    switch (challenge.type) {
      case 'backup':
        // Check if required fields are present
        if (!challenge.code) {
          logger.debug(
            `User ${user.username} (${user.id}) attempted to use a backup code without providing a code.`,
          );
          res.status(400).json(new Errors.MissingFields(['code']));
          return false;
        }
        // Check if the user has backup codes
        if (!user.twoFactorBackupCodes) {
          logger.error(
            `User ${user.username} (${user.id}) was challenged for a second factor and attempted to use a backup code, but they do not have any backup codes! This should not happen!`,
          );
          res.status(500).json(new Errors.Internal());
          return false;
        }
        // Check if the backup code is valid
        if (
          !user.twoFactorBackupCodes.some((hash) =>
            verifyBackupCode(challenge.code, hash),
          )
        ) {
          logger.debug(
            `User ${user.username} (${user.id}) attempted to use an invalid backup code.`,
          );
          res.status(401).json(new Errors.Invalid2FAResponse());
          return false;
        } else {
          // Find the backup code that was used and remove it
          await user.update({
            twoFactorBackupCodes: user.twoFactorBackupCodes.filter(
              (hash) => !verifyBackupCode(challenge.code, hash),
            ),
          });
          return true;
        }
      case 'totp':
        // Check if required fields are present
        if (!challenge.code) {
          logger.debug(
            `User ${user.username} (${user.id}) attempted to use a TOTP code without providing a code.`,
          );
          res.status(400).json(new Errors.MissingFields(['code']));
          return false;
        }
        // Go through each TOTP second factor and check if the code is valid
        const secondFactors = await SecondFactor.findAll({
          where: {
            user: user.id,
            type: 'totp',
          },
        });
        // If the user has no TOTP second factors, we will send an error response.
        if (secondFactors.length === 0) {
          logger.error(
            `User ${user.username} (${user.id}) was challenged for a second factor and attempted to use a TOTP code, but they do not have any TOTP second factors.`,
          );
          res.status(400).json(new Errors.Invalid2FAMethod());
          return false;
        }
        if (
          (
            await Promise.all(
              secondFactors.map(
                async (factor) =>
                  await verifyTOTP(challenge.code, factor.secret),
              ),
            )
          ).some((result) => result)
        ) {
          logger.debug(
            `User ${user.username} (${user.id}) successfully used a TOTP code.`,
          );
          return true;
        } else {
          logger.debug(
            `User ${user.username} (${user.id}) attempted to use an invalid TOTP code.`,
          );
          res.status(401).json(new Errors.Invalid2FAResponse());
          return false;
        }
      case 'webauthn':
        // Check if required fields are present
        if (!challenge.response) {
          logger.debug(
            `User ${user.username} (${user.id}) attempted to use a WebAuthn response without providing a response.`,
          );
          res.status(400).json(new Errors.MissingFields(['response']));
          return false;
        }

        // Check if the challenge is in the token
        if (!result.payload.challenge) {
          logger.error(
            `User ${user.username} (${user.id}) attempted to use a WebAuthn response without a challenge in the token.`,
          );
          res.status(400).json(new Errors.Invalid2FAResponse());
          return false;
        }

        // Verify the WebAuthn response
        if (
          await verifyWebAuthnAuthentication(
            challenge.response,
            challenge.token,
            res,
            user,
          )
        ) {
          logger.debug(
            `User ${user.username} (${user.id}) successfully used a WebAuthn credential.`,
          );
          return true;
        } else {
          logger.debug(
            `User ${user.username} (${user.id}) attempted to use an invalid WebAuthn response.`,
          );
          return false;
        }
      default:
        logger.error(
          `User ${user.username} (${
            user.id
          }) attempted to use an invalid second factor type. Challenge response body: ${JSON.stringify(
            challenge,
          )}`,
        );
        res.status(400).json(new Errors.Invalid2FAMethod());
        return false;
    }
}
