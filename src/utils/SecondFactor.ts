import { SECOND_FACTOR_BACKUP_CODE_LENGTH } from './Constants.js';

import {
  TOTPAsync,
  HashAlgorithms,
  AuthenticatorAsync,
  AuthenticatorAsyncOptions,
  KeyDecoder,
  KeyEncoder,
} from '@otplib/core-async';
import {
  createDigest,
  createRandomBytes,
} from '@otplib/plugin-crypto-async-ronomon';
import { keyDecoder, keyEncoder } from '@otplib/plugin-thirty-two';
import { randomBytes, createHash } from 'crypto';

const authenticator = new AuthenticatorAsync<AuthenticatorAsyncOptions>({
  createDigest,
  createRandomBytes,
  keyDecoder: keyDecoder as unknown as KeyDecoder<Promise<string>>,
  keyEncoder: keyEncoder as unknown as KeyEncoder<Promise<string>>,
  step: 30,
  digits: 6,
});

const totp = new TOTPAsync({
  step: 30,
  digits: 6,
  window: [2, 1],
  createDigest,
  algorithm: HashAlgorithms.SHA512,
});

export async function generateTOTPSecret(): Promise<string> {
  return await authenticator.generateSecret();
}

export async function generateTOTP(secret: string): Promise<string> {
  return await totp.generate(secret);
}

export async function verifyTOTP(
  token: string,
  secret: string,
): Promise<number> {
  return await totp.checkDelta(token, secret);
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
