import { Cumulonimbus } from '../../types';
import Multer from 'multer';
import User from '../../utils/DB/User';
import { ResponseConstructors } from '../../utils/RequestUtils';

const AdminSessionEndpoints: Cumulonimbus.APIEndpointModule = [
  {
    method: 'get',
    path: '/user/:id([0-9]+)/sessions',
    async handler(
      req: Cumulonimbus.Request<
        null,
        { id: string },
        { limit: number; offset: number }
      >,
      res: Cumulonimbus.Response<
        Cumulonimbus.Structures.List<Cumulonimbus.Structures.Session>
      >
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        if (
          req.user.staff === undefined ||
          req.user.staff === null ||
          req.user.staff === ''
        )
          res.status(403).json(new ResponseConstructors.Errors.Permissions());
        else {
          try {
            if (req.query.limit > 50) req.query.limit = 50;
            let u = await User.findOne({
              where: {
                id: req.params.id
              }
            });

            if (!u)
              res
                .status(404)
                .json(new ResponseConstructors.Errors.InvalidUser());
            else {
              let ujson = u.toJSON(),
                sessions = ujson.sessions
                  .map((s: Cumulonimbus.Structures.Session) => {
                    return { ...s, sub: u.id };
                  })
                  .reverse()
                  .slice(req.query.offset, req.query.limit + req.query.offset);
              res
                .status(200)
                .json({ count: ujson.sessions.length, items: sessions });
            }
          } catch (error) {
            throw error;
          }
        }
      }
    }
  },
  {
    method: 'get',
    path: '/user/:id([0-9]+)/session/:sid',
    async handler(
      req: Cumulonimbus.Request<null, { id: string; sid: string }, null>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.Session>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        if (
          req.user.staff === undefined ||
          req.user.staff === null ||
          req.user.staff === ''
        )
          res.status(403).json(new ResponseConstructors.Errors.Permissions());
        else {
          try {
            let u = await User.findOne({
              where: {
                id: req.params.id
              }
            });

            if (!u)
              res
                .status(404)
                .json(new ResponseConstructors.Errors.InvalidUser());
            else {
              if (
                u.sessions.findIndex(s => s.iat === Number(req.params.sid)) ===
                -1
              )
                res
                  .status(404)
                  .json(new ResponseConstructors.Errors.InvalidSession());
              else {
                let session = {
                  ...u.sessions[
                    u.sessions.findIndex(s => s.iat === Number(req.params.sid))
                  ],
                  sub: u.id
                };
                res.status(200).json(session);
              }
            }
          } catch (error) {
            throw error;
          }
        }
      }
    }
  },
  {
    method: 'delete',
    path: '/user/:id([0-9]+)/session/:sid',
    async handler(
      req: Cumulonimbus.Request<null, { id: string; sid: string }, null>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.Session>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        if (
          req.user.staff === undefined ||
          req.user.staff === null ||
          req.user.staff === ''
        )
          res.status(403).json(new ResponseConstructors.Errors.Permissions());
        else {
          try {
            let u = await User.findOne({
              where: {
                id: req.params.id
              }
            });

            if (!u)
              res
                .status(404)
                .json(new ResponseConstructors.Errors.InvalidUser());
            else {
              if (
                u.sessions.findIndex(s => s.iat === Number(req.params.sid)) ===
                -1
              )
                res
                  .status(404)
                  .json(new ResponseConstructors.Errors.InvalidSession());
              else {
                let session = {
                  ...u.sessions[
                    u.sessions.findIndex(s => s.iat === Number(req.params.sid))
                  ],
                  sub: u.id
                };
                await u.update({
                  sessions: u.sessions.filter(
                    s => s.iat !== Number(req.params.sid)
                  )
                });
                res.status(200).json(session);
              }
            }
          } catch (error) {
            throw error;
          }
        }
      }
    }
  },
  {
    method: 'delete',
    path: '/user/:id([0-9]+)/sessions',
    preHandlers: Multer().none(),
    async handler(
      req: Cumulonimbus.Request<{ sessions: string[] }, { id: string }, null>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.DeleteBulk>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        if (
          req.user.staff === undefined ||
          req.user.staff === null ||
          req.user.staff === ''
        )
          res.status(403).json(new ResponseConstructors.Errors.Permissions());
        else {
          try {
            let u = await User.findOne({
              where: {
                id: req.params.id
              }
            });

            if (!u)
              res
                .status(404)
                .json(new ResponseConstructors.Errors.InvalidUser());
            else {
              let count = u.sessions.filter(s =>
                  req.body.sessions.includes(s.iat.toString())
                ).length,
                sessions = u.sessions.filter(
                  s => !req.body.sessions.includes(s.iat.toString())
                );

              await u.update({
                sessions
              });
              res.status(200).json({ count, type: 'session' });
            }
          } catch (error) {
            throw error;
          }
        }
      }
    }
  },
  {
    method: 'delete',
    path: '/user/:id([0-9]+)/sessions/all',
    async handler(
      req: Cumulonimbus.Request<null, { id: string }, null>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.DeleteBulk>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        if (
          req.user.staff === undefined ||
          req.user.staff === null ||
          req.user.staff === ''
        )
          res.status(403).json(new ResponseConstructors.Errors.Permissions());
        else {
          try {
            let u = await User.findOne({
              where: {
                id: req.params.id
              }
            });

            if (!u)
              res
                .status(404)
                .json(new ResponseConstructors.Errors.InvalidUser());
            else {
              let count = u.sessions.length;
              await u.update({
                sessions: []
              });
              res.status(200).json({ count, type: 'session' });
            }
          } catch (error) {
            throw error;
          }
        }
      }
    }
  }
];

export default AdminSessionEndpoints;
