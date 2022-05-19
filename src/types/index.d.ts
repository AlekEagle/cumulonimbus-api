import Express from 'express';
import UA from 'ua-parser-js';
import User from '../utils/DB/User';
import { TokenStructure } from '../utils/Token';

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

  export interface Request<
    BodyStruct = null,
    ParamStruct = null,
    QueryStruct = null
  > extends Express.Request<ParamStruct, null, BodyStruct, QueryStruct> {
    ua: UA.IResult;
    user?: User;
    session?: TokenStructure;
  }

  export interface Response<ResBody = null>
    extends Express.Response<ResBody | Structures.Error> {}

  export namespace Structures {
    export interface User {
      id: string;
      username: string;
      displayName: string;
      email: string;
      staff?: string;
      domain: string;
      subdomain?: string;
      bannedAt?: string;
      createdAt: string;
      updatedAt: string;
    }

    export interface Session {
      iat: number;
      exp: number;
      sub: string;
      name: string;
    }

    export interface List<T> {
      count: number;
      items: T[];
    }

    export interface Success {
      code: string;
      message?: string;
    }

    export interface DeleteBulk {
      count: number;
      type: 'user' | 'session' | 'file' | 'domain' | 'instruction';
    }

    export interface Instruction {
      name: string;
      steps: string[];
      filename: string;
      fileContent: string;
      description: string;
      displayName: string;
      createdAt: string;
      updatedAt: string;
    }

    export interface Domain {
      domain: string;
      allowsSubdomains: boolean;
      createdAt: string;
      updatedAt: string;
    }

    export interface DomainSlim {
      domain: string;
      allowsSubdomains: boolean;
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
      filename: string;
      createdAt: string;
      updatedAt: string;
      userID: string;
      size: number;
    }

    export interface SuccessfulUpload {
      url: string;
      thumbnail: string;
      manage: string;
    }
  }

  export interface APIEndpoint {
    method: Methods;
    path: string;
    preHandlers?: Express.RequestHandler | Express.RequestHandler[];
    handler: (
      request: Request,
      response: Response,
      next: Express.NextFunction
    ) => void | Promise<void>;
  }

  export type APIEndpointModule = APIEndpoint[];
}
