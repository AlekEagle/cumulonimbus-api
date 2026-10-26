// Woah! type definitions for global modules!
import User from './DB/User.ts';
import Session from './DB/Session.ts';
import type { SecondFactorType } from './DB/SecondFactor.ts';
import type {
  RatelimitSubject,
  RatelimitData,
} from './utils/Ratelimit/Storage/index.ts';
import _Structures from 'cumulonimbus-types';

import { DetectResult } from 'node-device-detector';
import { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/server';
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
      SMTP_FROM: string;
      SMTP_SECURE: string;
      REDIS_HOST: string;
      REDIS_PORT: string;
      REDIS_USER: string;
      REDIS_PASS: string;
      HOST?: string;
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
    export import Structures = _Structures;

    namespace Utilities {
      export type ValueDeterminingMiddleware<T> = (
        request: Express.Request,
        response: Express.Response,
      ) => T | Promise<T>;
    }
  }
}
