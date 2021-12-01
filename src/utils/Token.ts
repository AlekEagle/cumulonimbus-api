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
    string: number;
  };
}

export let pubKey: KeyLike, privKey: KeyLike;
let imported = false;

export async function importCerts() {
  if (imported) return;
  pubKey = await importX509(await readFile('./certs/jwt.crt', 'utf8'), 'RS256');

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
): Promise<string> {
  await importCerts();
  return await new SignJWT({ name, sub: user })
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
    .setIssuedAt()
    .setExpirationTime(expires ? '30d' : '10y')
    .sign(privKey);
}

export async function validateToken(token: string): Promise<TokenStructure> {
  await importCerts();
  const { protectedHeader, payload } = await jwtVerify(token, pubKey);
  return { payload: payload as any, header: protectedHeader as any };
}
