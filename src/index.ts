import Logger, { Level } from "./utils/Logger";
import configureEnv from "./utils/Env";
import Express, { json, urlencoded, NextFunction } from "express";
import ExpressRateLimit from "express-rate-limit";
import ms from "ms";
import compression, { filter as _filter } from "compression";
import DeviceDetector from "node-device-detector";
import ClientHints from "node-device-detector/client-hints";
import { Cumulonimbus } from "./types";
import { TokenStructure, validateToken } from "./utils/Token";
import User from "./utils/DB/User";
import Endpoints from "./api";
import { ResponseConstructors } from "./utils/RequestUtils";
import QueryStringParser from "./utils/QueryStringParser";
import { readFileSync } from "node:fs";
import { Sequelize } from "sequelize";

const packageJSON = JSON.parse(readFileSync("./package.json", "utf-8"));

configureEnv();

// Usernames can only contain alphanumeric characters, underscores, dashes, periods and must not exceed 60 characters.
export const usernameRegex = /^[a-z0-9_\-\.]{1,60}$/i;

global.console = new Logger(
  process.env.DEBUG ? Level.DEBUG : Level.INFO
) as any;

const port: number =
  8000 + (!process.env.instance ? 0 : Number(process.env.instance));
const app = Express();

const detector = new DeviceDetector({
    clientIndexes: true,
    deviceIndexes: true,
  }),
  clientHints = new ClientHints();

function shouldCompress(req: Express.Request, res: Express.Response): boolean {
  if (req.headers["x-no-compression"]) {
    return false;
  }

  return _filter(req, res);
}

async function pruneExpiredSessions(user: User): Promise<void> {
  const staleSessionTime = Math.floor(Date.now() / 1000);
  if (user.sessions.some((s) => s.exp < staleSessionTime)) {
    await user.update({
      sessions: user.sessions.filter((s) => s.exp > staleSessionTime),
    });
  }
  return;
}

setInterval(async () => {
  let users = await User.findAll();
  users.forEach(pruneExpiredSessions);
}, ms("1h"));

app.use(
  (req, res, next) => {
    // If process.env.DEBUG is true, set CORS headers and handle OPTIONS requests
    if (process.env.DEBUG) {
      res.header("Access-Control-Allow-Origin", "*");
      res.header(
        "Access-Control-Allow-Headers",
        "Origin, X-Requested-With, Content-Type, Accept, Authorization"
      );
      if (req.method === "OPTIONS") {
        res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
        return res.status(204).send();
      }
    }
    next();
  },
  compression({ filter: shouldCompress }),
  QueryStringParser({
    keyWithNoValueIsBool: true,
    ignoreKeyWithNoValue: false,
  }),
  async (
    req: Cumulonimbus.Request,
    res: Express.Response,
    next: NextFunction
  ) => {
    const clientHintData = clientHints.parse(req.headers);
    req.ua = detector.detect(req.headers["user-agent"], clientHintData);
    if (req.headers.authorization) {
      try {
        let token = await validateToken(req.headers.authorization);
        if (token instanceof Error) {
          req.user = null;
          req.session = null;
        } else {
          let user = await User.findOne({
            where: Sequelize.where(Sequelize.col("id"), token.payload.sub),
          });
          if (!user) {
            req.user = null;
            req.session = null;
          } else {
            if (user.bannedAt) {
              res.status(403).json(new ResponseConstructors.Errors.Banned());
              return;
            } else {
              if (
                user.sessions.some(
                  (s) => s.iat === (token as TokenStructure).payload.iat
                )
              ) {
                await pruneExpiredSessions(user);
                req.user = user;
                req.session = token;
              } else {
                req.user = null;
                req.session = null;
              }
            }
          }
        }
      } catch (error) {
        console.error(error);
        res.status(500).json(new ResponseConstructors.Errors.Internal());
        return;
      }
    }
    next();
  },
  json(),
  urlencoded({ extended: true }),
  ExpressRateLimit({
    windowMs: ms("5mins"),
    max: 200,
    keyGenerator: (req: Cumulonimbus.Request, res: Express.Response) => {
      return req.user
        ? req.user.id
        : (Array.isArray(req.headers["x-forwarded-for"])
            ? req.headers["x-forwarded-for"][0]
            : req.headers["x-forwarded-for"]) || req.ip;
    },
    handler(
      req: Express.Request,
      res: Express.Response,
      next: Express.NextFunction
    ) {
      res.status(429).send(new ResponseConstructors.Errors.RateLimited());
    },
    skipFailedRequests: true,
    standardHeaders: true,
    legacyHeaders: true,
  })
);

app.all("/api/", (req: Cumulonimbus.Request, res: Express.Response) => {
  res.json({ hello: "world", version: packageJSON.version });
});

Endpoints.forEach((endpointModule) => {
  endpointModule.forEach(async (endpoint) => {
    let path = `/api${endpoint.path}`;
    console.log(
      "Initializing endpoint: %s",
      endpoint.method.toUpperCase(),
      path
    );
    if (endpoint.preHandlers === null || endpoint.preHandlers === undefined)
      app[endpoint.method](
        path,
        async (req: Cumulonimbus.Request, res: Cumulonimbus.Response, next) => {
          try {
            await endpoint.handler(req, res, next);
          } catch (error) {
            console.error(error);
            res.status(500).json(new ResponseConstructors.Errors.Internal());
          }
        }
      );
    else {
      if (Array.isArray(endpoint.preHandlers))
        app[endpoint.method](
          path,
          ...endpoint.preHandlers,
          async (
            req: Cumulonimbus.Request,
            res: Cumulonimbus.Response,
            next
          ) => {
            try {
              await endpoint.handler(req, res, next);
            } catch (error) {
              console.error(error);
              res.status(500).json(new ResponseConstructors.Errors.Internal());
            }
          }
        );
      else
        app[endpoint.method](
          path,
          endpoint.preHandlers,
          async (
            req: Cumulonimbus.Request,
            res: Cumulonimbus.Response,
            next
          ) => {
            try {
              await endpoint.handler(req, res, next);
            } catch (error) {
              console.error(error);
              res.status(500).json(new ResponseConstructors.Errors.Internal());
            }
          }
        );
    }
  });
});

app.all("/api/*", (req, res) => {
  res.status(404).json(new ResponseConstructors.Errors.InvalidEndpoint());
});

app.listen(port, () => {
  console.log("Listening on port %s", port);
});
