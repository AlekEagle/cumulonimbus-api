import {
  SECOND_FACTOR_ALGORITHM,
  SECOND_FACTOR_BACKUP_CODE_LENGTH,
  SECOND_FACTOR_TOTP_DIGITS,
  SECOND_FACTOR_TOTP_STEP,
} from './Constants.js';

import { HashAlgorithms } from '@otplib/core';
import { authenticator } from '@otplib/preset-default-async';
import { randomBytes, createHash } from 'crypto';

authenticator.options = {
  window: [2, 1],
  step: SECOND_FACTOR_TOTP_STEP,
  digits: SECOND_FACTOR_TOTP_DIGITS,
  algorithm: HashAlgorithms[SECOND_FACTOR_ALGORITHM],
};

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
      const hashed = createHash('sha256').update(code).digest('hex');
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

export async function verifyBackupCode(
  code: string,
  hashed: string,
): Promise<boolean> {
  return createHash('SHA512').update(code).digest('hex') === hashed;
}
