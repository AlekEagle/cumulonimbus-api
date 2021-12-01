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
  export interface Request extends Express.Request {
    ua: UA.IResult;
    user?: User;
  }
}
