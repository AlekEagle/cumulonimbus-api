// All of the cool JWT stuffs
import { importX509, importPKCS8, KeyLike, SignJWT, jwtVerify } from 'jose';
// We need this to read the JWT public and private keypair
import { readFile } from 'node:fs/promises';
// We need this to generate secure random numbers
import { randomInt } from 'node:crypto';
// Those Constants that are constant that we need
import {
  TOKEN_ALGORITHM,
  LONG_LIVED_TOKEN_EXPIRY,
  SHORT_LIVED_TOKEN_EXPIRY,
  TOKEN_TYPE,
  EMAIL_VERIFICATION_TOKEN_LENGTH,
} from './Constants.js';
import { Request } from 'express';

// This is the structure of the token
export declare interface TokenStructure {
  header: {
    alg: typeof TOKEN_ALGORITHM;
    typ: 'JWT';
  };
  payload: {
    sub: string;
    iat: number;
    exp: number;
  };
}

// After we import the keys, store them to reduce disk activity
let pubKey: KeyLike, privKey: KeyLike;

// Import the certificates from disk
export async function importCertificates() {
  // Do not re-import certificates if we already have them
  if (pubKey && privKey) return;
  pubKey = await importX509(await readFile('./certs/jwt.crt', 'utf8'), 'ES256');

  privKey = await importPKCS8(
    await readFile('./certs/jwt.pem', 'utf8'),
    'ES256',
  );
  return;
}

export async function generateToken(
  subject: string,
  longLived: boolean = false,
): Promise<{ token: string; data: TokenStructure }> {
  // Import certificates if they aren't already imported.
  await importCertificates();
  let token: string, data: TokenStructure;
  token = await new SignJWT({})
    .setProtectedHeader({ alg: TOKEN_ALGORITHM, typ: TOKEN_TYPE })
    .setIssuedAt()
    .setSubject(subject)
    .setExpirationTime(
      longLived ? LONG_LIVED_TOKEN_EXPIRY : SHORT_LIVED_TOKEN_EXPIRY,
    )
    .sign(privKey);
  data = extractToken(token);
  return { token, data };
}

export async function validateToken(
  token: string,
): Promise<TokenStructure | Error> {
  await importCertificates();
  try {
    const { protectedHeader, payload } = await jwtVerify(token, pubKey);
    return { payload: payload as any, header: protectedHeader as any };
  } catch (error) {
    return error;
  }
}

export function extractToken(token: string): TokenStructure {
  let t = token
    .split('.')
    .filter((a, i) => i !== 2)
    .map((p) => JSON.parse(Buffer.from(p, 'base64').toString('utf8')));
  return { header: t[0], payload: t[1] };
}

// A function that constructs a pretty user readable name for a session
// The name is based on the device that the user is using.
// Example: "Chrome on Windows 10 Desktop"
export function nameSession(req: Request): string {
  // If req.useragent.os and req.useragent.device are empty objects, fallback to the user agent string
  if (
    Object.keys(req.useragent.os).length === 0 &&
    req.useragent.device === undefined
  )
    return req.headers['user-agent'];
  let name = '';
  // If only req.useragent.client is empty, call it an "Unknown Browser"
  if (Object.keys(req.useragent.client).length === 0) name += 'Unknown Browser';
  else {
    // Use the name of the browser
    name += req.useragent.client.name;
    // If the browser version is available, use the major version
    if (req.useragent.client.version !== '')
      name += ' v' + req.useragent.client.version.split('.')[0];
  }

  name += ' on ';

  // If only req.useragent.os is empty, call it "an Unknown OS"
  if (Object.keys(req.useragent.os).length === 0) name += 'an Unknown OS';
  else {
    // Use the name of the OS
    name += req.useragent.os.name;
    // If the OS version is available, use the major version
    if (req.useragent.os.version !== '')
      name += ' v' + req.useragent.os.version.split('.')[0];
  }

  return name;
}

export function generateVerifyEmailToken() {
  return Buffer.from(
    new Array(EMAIL_VERIFICATION_TOKEN_LENGTH)
      .fill(0)
      .map((_) => randomInt(0, 255)),
  ).toString('base64');
}
