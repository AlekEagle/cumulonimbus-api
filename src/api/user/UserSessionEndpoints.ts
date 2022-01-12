import { Cumulonimbus } from '../../types';
import { Op } from 'sequelize/dist';
import Multer from 'multer';
import { generateToken } from '../../utils/Token';
import Bcrypt from 'bcrypt';
import User from '../../utils/DB/User';
import Express from 'express';
import ExpressRateLimits from 'express-rate-limit';
import ms from 'ms';
import {
  browserName,
  getInvalidFields,
  FieldTypeOptions,
  ResponseConstructors
} from '../../utils/RequestUtils';

const UserSessionEndpoints: Cumulonimbus.APIEndpointModule = [
  {
    method: 'post',
    path: '/user/session',
    preHandlers: [
      Multer().none(),
      ExpressRateLimits({
        windowMs: ms('1min'),
        max: 1,
        keyGenerator: (req: Cumulonimbus.Request, res: Express.Response) => {
          return req.user
            ? req.user.id
            : (Array.isArray(req.headers['x-forwarded-for'])
                ? req.headers['x-forwarded-for'][0]
                : req.headers['x-forwarded-for']) || req.ip;
        },
        handler(
          req: Express.Request,
          res: Express.Response,
          next: Express.NextFunction
        ) {
          res.status(429).send(new ResponseConstructors.Errors.RateLimited());
        },
        skipFailedRequests: true
      })
    ],
    async handler(
      req: Cumulonimbus.Request<{
        user: string;
        pass: string;
        rememberMe: boolean;
      }>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.SuccessfulAuth>
    ) {
      try {
        let invalidFields = getInvalidFields(req.body, {
          user: 'string',
          pass: 'string',
          rememberMe: new FieldTypeOptions('boolean', true)
        });
        if (invalidFields.length > 0) {
          res
            .status(400)
            .json(new ResponseConstructors.Errors.MissingFields(invalidFields));
        } else {
          try {
            let u = await User.findOne({
              where: {
                [Op.or]: {
                  email: req.body.user,
                  username: req.body.user.toLowerCase()
                }
              }
            });
            if (!u)
              res
                .status(404)
                .json(new ResponseConstructors.Errors.InvalidUser());
            else {
              if (u.bannedAt !== null)
                res.status(403).json(new ResponseConstructors.Errors.Banned());
              else {
                try {
                  let match = await Bcrypt.compare(req.body.pass, u.password);
                  if (!match)
                    res
                      .status(401)
                      .json(new ResponseConstructors.Errors.InvalidPassword());
                  else {
                    try {
                      let tName =
                        typeof req.headers['x-token-name'] === 'string' &&
                        req.headers['x-token-name'] !== ''
                          ? req.headers['x-token-name']
                          : browserName(req.ua);
                      let token = await generateToken(
                        u.id,
                        tName,
                        !req.body.rememberMe
                      );
                      let nS = [
                        ...u.sessions,
                        {
                          iat: token.data.payload.iat,
                          exp: token.data.payload.exp,
                          name: token.data.payload.name
                        }
                      ];
                      await u.update({ sessions: nS });
                      res.status(201).json({
                        token: token.token,
                        exp: token.data.payload.exp
                      } as Cumulonimbus.Structures.SuccessfulAuth);
                    } catch (error) {
                      throw error;
                    }
                  }
                } catch (error) {
                  throw error;
                }
              }
            }
          } catch (error) {
            throw error;
          }
        }
      } catch (error) {
        throw error;
      }
    }
  },
  {
    method: 'get',
    path: '/user/session',
    async handler(
      req,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.Session>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        let curSession: Cumulonimbus.Structures.Session = {
          iat: req.session.payload.iat,
          exp: req.session.payload.exp,
          name: req.session.payload.name,
          sub: req.user.id
        };
        res.status(200).json(curSession);
      }
    }
  },
  {
    method: 'get',
    path: '/user/session/:id',
    async handler(
      req: Cumulonimbus.Request<null, { id: string }>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.Session>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        let session = req.user.sessions.find(
          s => s.iat.toString() === req.params.id
        );
        if (session === undefined)
          res
            .status(404)
            .json(new ResponseConstructors.Errors.InvalidSession());
        else res.status(200).json({ ...session, sub: req.user.id });
      }
    }
  },
  {
    method: 'get',
    path: '/user/sessions',
    async handler(
      req: Cumulonimbus.Request<null, null, { limit: number; offset: number }>,
      res: Cumulonimbus.Response<
        Cumulonimbus.Structures.List<Cumulonimbus.Structures.Session>
      >
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        if (req.query.limit > 50) req.query.limit = 50;
        let u = req.user.toJSON(),
          sessions = u.sessions
            .map((s: Cumulonimbus.Structures.Session) => {
              return { ...s, sub: req.user.id };
            })
            .slice(req.query.offset, req.query.limit + req.query.offset);
        res.status(200).json({
          count: u.sessions.length,
          items: sessions
        } as Cumulonimbus.Structures.List<Cumulonimbus.Structures.Session>);
      }
    }
  },
  {
    method: 'delete',
    path: '/user/session/:id([0-9]+)',
    async handler(
      req: Cumulonimbus.Request<{}, { id: string }>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.Success>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        if (
          req.user.sessions.findIndex(a => a.iat === Number(req.params.id)) ===
          -1
        )
          res
            .status(404)
            .json(new ResponseConstructors.Errors.InvalidSession());
        else {
          try {
            let uSessions = req.user.sessions.filter(
              s => s.iat !== Number(req.params.id)
            );
            await req.user.update({ sessions: uSessions });
            res
              .status(200)
              .json(
                new ResponseConstructors.Success.Generic('Session Deleted')
              );
          } catch (error) {
            throw error;
          }
        }
      }
    }
  },
  {
    method: 'delete',
    path: '/user/sessions',
    preHandlers: Multer().none(),
    async handler(
      req: Cumulonimbus.Request<{ sessions: string[] }>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.DeleteBulk>
    ) {
      try {
        if (!req.user)
          res
            .status(401)
            .json(new ResponseConstructors.Errors.InvalidSession());
        else {
          let invalidFields = getInvalidFields(req.body, {
            sessions: new FieldTypeOptions('array', false, 'string')
          });

          if (invalidFields.length > 0)
            res
              .status(400)
              .json(
                new ResponseConstructors.Errors.MissingFields(invalidFields)
              );
          else {
            try {
              let count = req.user.sessions.filter(s =>
                  req.body.sessions.includes(s.iat.toString())
                ).length,
                sessions = req.user.sessions.filter(
                  s => !req.body.sessions.includes(s.iat.toString())
                );
              await req.user.update({ sessions });
              res.status(200).json({
                count,
                type: 'session'
              });
            } catch (error) {
              throw error;
            }
          }
        }
      } catch (error) {
        throw error;
      }
    }
  },
  {
    method: 'delete',
    path: '/user/sessions/all',
    async handler(
      req: Cumulonimbus.Request<null, null, { allButSelf: boolean }>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.DeleteBulk>
    ) {
      try {
        if (!req.user)
          res
            .status(401)
            .json(new ResponseConstructors.Errors.InvalidSession());
        else {
          try {
            let count = req.query.allButSelf
                ? req.user.sessions.filter(
                    s => s.iat !== req.session.payload.iat
                  ).length
                : req.user.sessions.length,
              sessions = req.query.allButSelf
                ? req.user.sessions.filter(
                    s => s.iat === req.session.payload.iat
                  )
                : [];
            await req.user.update({ sessions });
            res.status(200).json({
              count,
              type: 'session'
            });
          } catch (error) {
            throw error;
          }
        }
      } catch (error) {
        throw error;
      }
    }
  }
];

export default UserSessionEndpoints;
