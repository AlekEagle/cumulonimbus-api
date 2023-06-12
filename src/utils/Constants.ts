// All of those constants that are used throughout everywhere.
import { readFileSync } from "fs";

// ========= GENERAL CONSTANTS =========
export const API_VERSION = JSON.parse(
  readFileSync("./package.json", "utf-8")
).version;

// ========= SERVER RELATED CONSTANTS =========
export const PORT: number =
  8000 + (!process.env.INSTANCE ? 0 : Number(process.env.INSTANCE));

// ========= USER RELATED CONSTANTS =========
export const USERNAME_REGEX = /^[a-z0-9_\-\.]{1,60}$/i;
export const EMAIL_REGEX =
  /(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/i;

// ========= FILE RELATED CONSTANTS =========
export const FILENAME_LENGTH = 10;

// ========= TOKEN RELATED CONSTANTS =========
export const SHORT_LIVED_TOKEN_EXPIRY = "24h";
export const LONG_LIVED_TOKEN_EXPIRY = "10y";
export const TOKEN_ALGORITHM = "ES256";
export const TOKEN_TYPE = "JWT";
