// Woah! type definitions for global modules!
import User from './DB/User.ts';
import Session from './DB/Session.ts';
import type { SecondFactorType } from './DB/SecondFactor.ts';
import type {
  RatelimitSubject,
  RatelimitData,
} from './utils/RatelimitStorage.ts';

import { DetectResult } from 'node-device-detector';
import { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/types';
import { Send } from 'express';

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
      WEBAUTHN_RPID: string;
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
      user: User | null;
      session: Session | null;
      limit?: number;
      offset?: number;
    }

    interface Response {
      _originalSend?: Send;
      ratelimit?: {
        headersSet: boolean;
        skipped: boolean;
        requestTime: number;
        subject: RatelimitSubject;
        data: RatelimitData;
      };
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
        verifiedAt: string | null;
        bannedAt: string | null;
        twoFactorBackupCodeUsedAt: string | null;
        createdAt: string;
        updatedAt: string;
      }

      export interface Session {
        id: string;
        exp: number;
        name: string;
        permissionFlags: number | null;
        usedAt: string | null;
        createdAt: string;
        updatedAt: string;
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

      export interface SecondFactor {
        id: string;
        name: string;
        type: SecondFactorType;
        usedAt: string | null;
        createdAt: string;
        updatedAt: string;
      }

      export interface SecondFactorChallenge {
        token: string;
        exp: number;
        types: (SecondFactorType | 'backup')[];
      }

      export interface SecondFactorBaseRegistration {
        token: string;
        exp: number;
        type: SecondFactorType;
      }

      export interface SecondFactorTOTPRegistration
        extends SecondFactorBaseRegistration {
        type: 'totp';
        secret: string;
        algorithm: string;
        digits: number;
        period: number;
      }
      export interface SecondFactorWebAuthnRegistration
        extends SecondFactorBaseRegistration,
          PublicKeyCredentialCreationOptionsJSON {
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

      export interface SecondFactorRegisterSuccess {
        id: string;
        name: string;
        type: SecondFactorType;
        codes?: string[];
      }

      export interface SecondFactorBackupRegisterSuccess {
        codes: string[];
      }

      export interface ScopedSessionCreate extends Session {
        token: string;
      }

      export interface LogLevel {
        name: string;
      }
    }

    namespace Utilities {
      export type ValueDeterminingMiddleware<T> = (
        request: Express.Request,
        response: Express.Response,
      ) => T | Promise<T>;
    }
  }
}
