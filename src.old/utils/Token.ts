import { importX509, importPKCS8, KeyLike, SignJWT, jwtVerify } from 'jose';
import { readFile } from 'node:fs/promises';

export declare interface TokenStructure {
  header: {
    alg: string;
    typ: string;
  };
  payload: {
    sub: string;
    name: string;
    iat: number;
    exp: number;
  };
}

export let pubKey: KeyLike, privKey: KeyLike;
let imported = false;

export async function importCerts() {
  if (imported) return;
  pubKey = await importX509(await readFile('./certs/jwt.crt', 'utf8'), 'ES256');

  privKey = await importPKCS8(
    await readFile('./certs/jwt.pem', 'utf8'),
    'ES256'
  );
  imported = true;
}

export async function generateToken(
  user: string,
  name: string,
  expires: boolean = true
): Promise<{ token: string; data: TokenStructure }> {
  await importCerts();
  let tokenStr = await new SignJWT({ name, sub: user })
      .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
      .setIssuedAt()
      .setExpirationTime(expires ? '24h' : '10y')
      .sign(privKey),
    tokenData = extractToken(tokenStr);

  return { token: tokenStr, data: tokenData };
}

export async function validateToken(
  token: string
): Promise<TokenStructure | Error> {
  await importCerts();
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
    .map(p => JSON.parse(Buffer.from(p, 'base64').toString('utf8')));
  return { header: t[0], payload: t[1] };
}
