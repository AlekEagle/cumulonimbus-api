import { ResponseStructures } from '../utils/ResponseStructures';
import { Cumulonimbus } from '../types';
import { Op } from 'sequelize/dist';
import Multer from 'multer';
import { extractToken, generateToken } from '../utils/Token';
import Bcrypt from 'bcrypt';
import User from '../utils/DB/User';
import {
  browserName,
  getInvalidFields,
  FieldTypeOptions
} from '../utils/RequestUtils';

const SessionEndpoints: Cumulonimbus.APIEndpointModule = [
  {
    method: 'post',
    path: '/session',
    preHandlers: Multer().none(),
    async handler(
      req: Cumulonimbus.Request<{
        user: string;
        pass: string;
        rememberMe: boolean;
      }>,
      res
    ) {
      let invalidFields = getInvalidFields(req.body, {
        user: 'string',
        pass: 'string',
        rememberMe: new FieldTypeOptions('boolean', true)
      });
      if (invalidFields.length > 0) {
        res
          .status(400)
          .json(new ResponseStructures.MissingFields(invalidFields));
      } else {
        if (req.user)
          res
            .status(400)
            .json(new ResponseStructures.GenericError('Already Authenticated'));
        else {
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
              .json(new ResponseStructures.GenericError('User not found'));
          else {
            let match = await Bcrypt.compare(req.body.pass, u.password);
            if (!match)
              res.status(401).json(new ResponseStructures.InvalidPassword());
            else {
              let token = await generateToken(
                u.id,
                browserName(req.ua),
                !req.body.rememberMe
              );
              let tokenData = extractToken(token);
              let nS = [
                ...u.sessions,
                {
                  iat: tokenData.payload.iat,
                  exp: tokenData.payload.exp,
                  name: tokenData.payload.name
                }
              ];
              await u.update({ sessions: nS });
              res.status(201).json({
                token,
                exp: tokenData.payload.exp
              } as Cumulonimbus.SuccessfulAuthStructure);
            }
          }
        }
      }
    }
  },
  {
    method: 'get',
    path: '/sessions',
    async handler(req, res) {
      if (!req.user)
        res.status(401).json(new ResponseStructures.NotAuthenticated());
      else {
        let u = req.user.toJSON();
        res.status(200).json(u.sessions as Cumulonimbus.TokenStructure[]);
      }
    }
  },
  {
    method: 'delete',
    path: '/session/:id([0-9]+?)',
    async handler(req, res) {
      if (!req.user)
        res.status(401).json(new ResponseStructures.NotAuthenticated());
      else {
        if (
          req.user.sessions.findIndex(a => a.iat === Number(req.params.id)) ===
          -1
        )
          res
            .status(404)
            .json(
              new ResponseStructures.GenericError('Session does not exist')
            );
        else {
          let uSessions = req.user.sessions.filter(
            s => s.iat !== Number(req.params.id)
          );
          await req.user.update({ sessions: uSessions });
          res.status(204).end();
        }
      }
    }
  }
];

export default SessionEndpoints;
