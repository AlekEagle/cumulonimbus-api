// All of the cool JWT stuffs
import { importX509, importPKCS8, KeyLike, SignJWT, jwtVerify } from 'jose';
// We need this to read the JWT public and private keypair
import { readFile } from 'node:fs/promises';
// Those Constants that are constant that we need
import {
  TOKEN_ALGORITHM,
  LONG_LIVED_SESSION_EXPIRY,
  SHORT_LIVED_SESSION_EXPIRY,
  TOKEN_TYPE,
  EMAIL_VERIFICATION_TOKEN_EXPIRY,
  SECOND_FACTOR_INTERMEDIATE_TOKEN_EXPIRY,
} from './Constants.js';
import { Request } from 'express';

// This is the structure of the token
export declare interface TokenStructure<T = Record<string, string>> {
  header: {
    alg: typeof TOKEN_ALGORITHM;
    typ: 'JWT';
  };
  payload: {
    sub: string;
    iat: number;
    exp: number;
    iss: string;
  } & T;
}

export declare interface TokenGenerationResult<T = Record<string, string>> {
  token: string;
  data: TokenStructure<T>;
}

// After we import the keys, store them to reduce disk activity
let pubKey: KeyLike, privKey: KeyLike;

function generateBaseToken(data: Record<string, string> = {}): SignJWT {
  return new SignJWT(data)
    .setProtectedHeader({ alg: TOKEN_ALGORITHM, typ: TOKEN_TYPE })
    .setIssuedAt()
    .setIssuer(process.env.WEBAUTHN_RPID);
}

async function completeToken<T = Record<string, string>>(
  token: SignJWT,
): Promise<TokenGenerationResult<T>> {
  const signedToken = await token.sign(privKey);
  return { token: signedToken, data: extractToken(signedToken) };
}

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

// Generate a session token for the provided user.
export async function generateSessionToken(
  subject: string,
  longLived: boolean = false,
): Promise<TokenGenerationResult> {
  // Import certificates if they aren't already imported.
  await importCertificates();
  // Generate the token.
  let token = generateBaseToken()
    .setSubject(subject)
    .setExpirationTime(
      longLived ? LONG_LIVED_SESSION_EXPIRY : SHORT_LIVED_SESSION_EXPIRY,
    );
  return await completeToken(token);
}

// Generate an email verification token for the provided email.
export async function generateEmailVerificationToken(
  email: string,
): Promise<TokenGenerationResult> {
  // Import certificates if they aren't already imported.
  await importCertificates();
  // Generate the token.
  let token = generateBaseToken()
    .setSubject(email)
    .setExpirationTime(EMAIL_VERIFICATION_TOKEN_EXPIRY);

  return await completeToken(token);
}

// Generate a TOTP generation confirmation token for the provided user and TOTP secret.
export async function generateTOTPGenerationConfirmationToken(
  subject: string,
  secret: string,
): Promise<TokenGenerationResult<{ secret: string }>> {
  // Import certificates if they aren't already imported.
  await importCertificates();
  // Generate the token.
  let token = generateBaseToken({ secret })
    .setSubject(subject)
    .setExpirationTime(SECOND_FACTOR_INTERMEDIATE_TOKEN_EXPIRY);
  return await completeToken(token);
}

// Generate a WebAuthn generation confirmation token for the provided user and WebAuthn registration challenge.
export async function generateWebAuthnGenerationConfirmationToken(
  subject: string,
  challenge: string,
): Promise<TokenGenerationResult<{ challenge: string }>> {
  // Import certificates if they aren't already imported.
  await importCertificates();
  // Generate the token.
  let token = generateBaseToken({ challenge })
    .setSubject(subject)
    .setExpirationTime(SECOND_FACTOR_INTERMEDIATE_TOKEN_EXPIRY);
  return await completeToken(token);
}

// Generate a 2FA intermediate token for the provided user.
// We put the challenge in the token so that we can verify it later
// if they decide to use WebAuthn.
export async function generateSecondFactorIntermediateToken(
  subject: string,
  challenge?: string, // Optional challenge for WebAuthn
): Promise<TokenGenerationResult> {
  // Import certificates if they aren't already imported.
  await importCertificates();
  // Generate the token.
  let token = generateBaseToken(challenge ? { challenge } : {})
    .setSubject(subject)
    .setExpirationTime(SECOND_FACTOR_INTERMEDIATE_TOKEN_EXPIRY);
  return await completeToken(token);
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

export function extractToken<T = Record<string, string>>(
  token: string,
): TokenStructure<T> {
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
    return req.headers['user-agent']!;
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
