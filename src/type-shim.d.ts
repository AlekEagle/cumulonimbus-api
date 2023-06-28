// Woah! type definitions for global modules!
import { DetectResult } from "node-device-detector";
import User from "./DB/User.ts";
import { TokenStructure } from "./utils/Token.ts";

export {};
declare global {
  // Environment variables
  namespace NodeJS {
    interface ProcessEnv {
      ENV: "development" | "production";
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
    }
  }

  // Express
  namespace Express {
    interface Request {
      useragent: DetectResult;
      user?: User;
      session?: TokenStructure;
    }
  }

  // Cumulonimbus
  namespace Cumulonimbus {
    export namespace Structures {
      export interface User {
        id: string;
        username: string;
        email: string;
        verified: boolean;
        staff: boolean;
        domain: string;
        subdomain: string | null;
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
    }
  }
}
