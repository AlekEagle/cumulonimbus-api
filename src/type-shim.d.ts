// Woah! type definitions for global modules!
import { DetectResult } from 'node-device-detector';
import User from './DB/User.ts';
import { TokenStructure } from './utils/Token.ts';
import type { SecondFactorType } from './DB/SecondFactor.ts';

export {};
declare global {
  // Environment variables
  namespace NodeJS {
    interface ProcessEnv {
      ENV: 'development' | 'production';
      DATABASE_HOST: string;
      DATABASE_PORT: string;
      DATABASE_USER: string;
      DATABASE_PASS: string;
      DATABASE: string;
      INSTANCE: string;
      BASE_UPLOAD_PATH: string;
      BASE_THUMBNAIL_PATH: string;
      DEFAULT_DOMAIN: string;
      FRONTEND_BASE_URL: string;
      THUMBNAIL_BASE_URL: string;
      SMTP_HOST: string;
      SMTP_PORT: string;
      SMTP_USER: string;
      SMTP_PASS: string;
    }
  }

  // Express
  namespace Express {
    interface Request {
      useragent: DetectResult;
      user?: User;
      session?: TokenStructure;
      limit?: number;
      offset?: number;
    }
  }

  // Cumulonimbus
  namespace Cumulonimbus {
    export namespace Structures {
      export interface User {
        id: string;
        username: string;
        email: string;
        staff: boolean;
        domain: string;
        subdomain: string | null;
        emailVerificationToken: string | null;
        verificationRequestedAt: Date | null;
        verifiedAt: Date | null;
        bannedAt: string | null;
        createdAt: string;
        updatedAt: string;
      }

      export interface Session {
        id: number;
        exp: number;
        name: string;
      }

      export interface List<T> {
        count: number;
        items: T[];
      }

      export interface Success {
        code: string;
        message: string;
      }

      export interface Instruction {
        id: string;
        name: string;
        description: string;
        steps: string[];
        filename: string;
        content: string;
        createdAt: string;
        updatedAt: string;
      }

      export interface Domain {
        id: string;
        subdomains: boolean;
        createdAt: string;
        updatedAt: string;
      }

      export interface Error {
        code: string;
        message: string;
      }

      export interface SuccessfulAuth {
        token: string;
        exp: number;
      }

      export interface SecondFactorChallenge {
        token: string;
        exp: number;
        types: SecondFactorType[];
        challenge?: string; // This will only be present if 'webauthn' is in the types array
      }

      export interface SecondFactorBaseRegistration {
        token: string;
        exp: number;
        type: SecondFactorType;
      }

      export interface SecondFactorTOTPRegistration
        extends SecondFactorBaseRegistration {
        type: 'totp';
        data: {
          secret: string;
          algorithm: string;
          digits: number;
          period: number;
        };
      }

      // TODO: Populate this with the correct fields
      export interface SecondFactorWebAuthnRegistration
        extends SecondFactorBaseRegistration {
        type: 'webauthn';
      }

      export type SecondFactorRegistration =
        | SecondFactorTOTPRegistration
        | SecondFactorWebAuthnRegistration;

      export interface File {
        id: string;
        userID: string;
        size: number;
        createdAt: string;
        updatedAt: string;
      }

      export interface SuccessfulUpload {
        url: string;
        thumbnail: string;
        manage: string;
      }

      export interface KillSwitch {
        id: number;
        name: string;
        state: boolean;
      }

      export interface TwoFactorRegisterSuccess {
        id: string;
        name: string;
        type: 'totp' | 'webauthn';
        backupCodes?: string[];
      }
    }
  }
}
