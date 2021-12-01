import Logger, { Level } from './utils/Logger';
import configureEnv from './utils/Env';
import Express, { json, urlencoded, NextFunction } from 'express';
import ExpressRateLimit from 'express-rate-limit';
import ms from 'ms';
import compression, { filter as _filter } from 'compression';
import UAParser from 'ua-parser-js';
import { Cumulonimbus } from './types';

configureEnv();

global.console = new Logger(
  process.env.DEBUG ? Level.DEBUG : Level.INFO
) as any;

const port: number =
  8000 + (!process.env.instance ? 0 : Number(process.env.instance));
const app = Express();

function shouldCompress(req: Express.Request, res: Express.Response): boolean {
  if (req.headers['x-no-compression']) {
    return false;
  }

  return _filter(req, res);
}

app.use(
  compression({ filter: shouldCompress }),
  async (
    req: Cumulonimbus.Request,
    res: Express.Response,
    next: NextFunction
  ) => {
    if (req.headers.authorization) {
      console.log('no');
    }
    req.ua = new UAParser(req.headers['user-agent']).getResult();
    next();
  },
  json(),
  urlencoded({ extended: true })
);
