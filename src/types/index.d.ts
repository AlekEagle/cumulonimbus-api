import Express from 'express';
import UA from 'ua-parser-js';
import User from '../utils/DB/User';

declare namespace NodeJS {
  export interface ProcessEnv {
    SERVERIP: string;
    SERVERUSERNAME: string;
    SERVERPASSWORD: string;
    SERVERDB: string;
    instance: string;
  }
}

declare namespace Cumulonimbus {
  export type Methods =
    | 'get'
    | 'post'
    | 'patch'
    | 'options'
    | 'put'
    | 'delete'
    | 'head'
    | 'all';

  export interface Request<BodyStruct = {}> extends Express.Request {
    ua: UA.IResult;
    user?: User;
    body: BodyStruct;
  }

  export interface UserStructure {
    id: string;
    username: string;
    displayName: string;
    email: string;
    staff: string;
    domain: string;
    subdomain: string;
    bannedAt: string;
    createdAt: string;
    updatedAt: string;
  }

  export interface TokenStructure {
    iat: number;
  }

  export interface SuccessfulAuthStructure {
    token: string;
    exp: number;
  }

  export interface FileStructure {
    filename: string;
    createdAt: Date;
    updatedAt: Date;
    userId: string;
    size: number;
  }

  export interface FileListStructure {
    count: number;
    files: FileStructure[];
  }

  export interface APIEndpoint {
    method: Methods;
    path: string;
    preHandlers?: Express.RequestHandler | Express.RequestHandler[];
    handler: (
      request: Request,
      response: Express.Response,
      next: Express.NextFunction
    ) => void | Promise<void>;
  }

  export type APIEndpointModule = APIEndpoint[];
}
