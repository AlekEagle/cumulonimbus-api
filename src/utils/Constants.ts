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
export const PASSWORD_HASH_ROUNDS = 15;
export const OMITTED_USER_FIELDS = [
  'password',
  'sessions',
  'twoFactorBackupCodes',
];

// ========= FILE RELATED CONSTANTS =========
export const FILENAME_LENGTH = 10;

export const MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024; // 100 MB

// The compression-following pass only needs the container headers (the ustar
// magic sits at offset 257 of the decompressed stream), so scan at most 1 MB.
export const MAX_LIBMAGIC_SCAN_BYTES = 1024 * 1024; // 1 MB

// A list of possible nested container file extensions that require further inspection.
export const NESTED_CONTAINERS = new Set([
  'xz',
  'zst',
  'bz2',
  'lz4',
  'lz',
  'lzma',
]);

// libmagic description prefixes for the containers above. Unmapped containers
// fall back to the bare extension.
export const LIBMAGIC_CONTAINERS: [RegExp, string][] = [
  [/^gzip compressed data/i, 'gz'],
  [/^XZ compressed data/i, 'xz'],
  [/^bzip2 compressed data/i, 'bz2'],
  [/^Zstandard compressed data/i, 'zst'],
  [/^LZMA compressed data/i, 'lzma'],
];

// ========= TOKEN RELATED CONSTANTS =========
export const TOKEN_ALGORITHM = 'ES256';
export const TOKEN_TYPE = 'JWT';

// ========= EMAIL RELATED CONSTANTS =========
export const EMAIL_VERIFICATION_TOKEN_EXPIRY = '1h';

// ========= 2FA RELATED CONSTANTS =========
export const SECOND_FACTOR_TOTP_ALGORITHM = 'SHA1';
export const SECOND_FACTOR_TOTP_DIGITS = 6;
export const SECOND_FACTOR_TOTP_STEP = 30;
export const SECOND_FACTOR_INTERMEDIATE_TOKEN_EXPIRY = '5m';
export const SECOND_FACTOR_BACKUP_CODE_LENGTH = 10;
export const SECOND_FACTOR_BACKUP_CODE_ALGORITHM = 'SHA512';

// ========= SESSION RELATED CONSTANTS =========
export const SHORT_LIVED_SESSION_EXPIRY = '24h';
export const LONG_LIVED_SESSION_EXPIRY = '10y';
