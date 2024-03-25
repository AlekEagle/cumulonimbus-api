// All of those constants that are used throughout everywhere.
import { readFileSync } from 'fs';

// ========= GENERAL CONSTANTS =========
export const API_VERSION = JSON.parse(
  readFileSync('./package.json', 'utf-8'),
).version;

// ========= SERVER RELATED CONSTANTS =========
export const PORT: number =
  8000 + (!process.env.INSTANCE ? 0 : Number(process.env.INSTANCE));

// ========= USER RELATED CONSTANTS =========
export const USERNAME_REGEX = /^[a-z0-9_\-\.]{1,64}$/i;
export const EMAIL_REGEX =
  /(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/i;
export const INSTRUCTION_REGEX = /^[a-z0-9_\-\.]{1,64}$/;
export const PASSWORD_HASH_ROUNDS = 15;
export const OMITTED_USER_FIELDS = [
  'password',
  'sessions',
  'verificationRequestedAt',
];

// ========= FILE RELATED CONSTANTS =========
export const FILENAME_LENGTH = 10;

// File extensions that the FileType library struggles with.
// If we encounter one of these, we'll just use the file extension
// from the original file name instead of whatever FileType gives us.
export const TROUBLESOME_FILE_EXTENSIONS = [
  'tar.gz',
  'tar.xz',
  'tar.bz2',
  'tar.lz',
  'tar.lzma',
  'tar.lzo',
  'tar.z',
  'tar.Z',
  'tar.sz',
  'apk',
  'jar',
];

// ========= TOKEN RELATED CONSTANTS =========
export const SHORT_LIVED_TOKEN_EXPIRY = '24h';
export const LONG_LIVED_TOKEN_EXPIRY = '10y';
export const TOKEN_ALGORITHM = 'ES256';
export const TOKEN_TYPE = 'JWT';

// ========= EMAIL RELATED CONSTANTS =========
export const EMAIL_VERIFICATION_TOKEN_EXPIRY = '1h';

// ========= 2FA RELATED CONSTANTS =========
export const SECOND_FACTOR_ALGORITHM = 'SHA1';
export const SECOND_FACTOR_TOTP_DIGITS = 6;
export const SECOND_FACTOR_TOTP_STEP = 30;
export const SECOND_FACTOR_INTERMEDIATE_TOKEN_EXPIRY = '5m';
export const SECOND_FACTOR_BACKUP_CODE_LENGTH = 10;
