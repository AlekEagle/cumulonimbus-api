import {
  SECOND_FACTOR_ALGORITHM,
  SECOND_FACTOR_BACKUP_CODE_ALGORITHM,
  SECOND_FACTOR_BACKUP_CODE_LENGTH,
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

authenticator.options = {
  window: [2, 1],
  step: SECOND_FACTOR_TOTP_STEP,
  digits: SECOND_FACTOR_TOTP_DIGITS,
  algorithm: HashAlgorithms[SECOND_FACTOR_ALGORITHM],
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

export async function generateSecondFactorChallenge(
  user: User,
): Promise<Cumulonimbus.Structures.SecondFactorChallenge> {
  const secondFactors = await SecondFactor.findAll({
    where: { user: user.id },
  });

  if (secondFactors.length === 0) {
    throw new Error('User does not have any second factors!');
  }

  const availableFactors = secondFactors
    .map((factor) => factor.type)
    .filter((t, i, a) => a.indexOf(t) === i);

  const token = await generateSecondFactorIntermediateToken(user.id);

  return {
    token: token.token,
    exp: token.data.payload.exp,
    types: availableFactors,
  };
}

// This will handle all second factor challenge verification logic
// Errors thrown by this function should be forwarded to the user
export async function verifySecondFactor(
  challenge: SecondFactorChallengeResponse,
  user: User,
): Promise<boolean> {
  // Validate the token.
  const result = await validateToken(challenge.token);

  if (result instanceof Error) {
    if (result instanceof JoseErrors.JWTExpired) {
      logger.debug(
        `User ${user.username} (${user.id}) attempted to use an expired 2FA intermediate token.`,
      );
      throw new Errors.Invalid2FAResponse();
    }
  } else if (result.payload.sub !== user.id) {
    logger.warn(
      `User ${user.username} (${user.id}) attempted to use a 2FA intermediate token that does not belong to them.`,
    );
    throw new Errors.Invalid2FAResponse();
  }
  switch (challenge.type) {
    case 'backup':
      // Check if required fields are present
      if (!challenge.code) throw new Errors.MissingFields(['code']);
      // Check if the user has backup codes
      if (!user.twoFactorBackupCodes) {
        logger.error(
          `User ${user.username} (${user.id}) was challenged for a second factor and attempted to use a backup code, but they do not have any backup codes! This should not happen!`,
        );
        throw new Errors.Internal();
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
        throw new Errors.Invalid2FAResponse();
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
      if (!challenge.code) throw new Errors.MissingFields(['code']);
      // Go through each TOTP second factor and check if the code is valid
      const secondFactors = await SecondFactor.findAll({
        where: {
          user: user.id,
          type: 'totp',
        },
      });
      if (
        (
          await Promise.all(
            secondFactors.map(
              async (factor) => await verifyTOTP(challenge.code, factor.secret),
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
        throw new Errors.Invalid2FAResponse();
      }
    case 'webauthn':
      logger.warn(
        'User has a WebAuthn second factor, but validating it is not yet implemented!',
      );
      throw new Errors.NotImplemented();
    default:
      throw new Errors.Invalid2FAResponse();
  }
}
