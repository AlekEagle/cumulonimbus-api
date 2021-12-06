import { ResponseStructures } from '../utils/ResponseStructures';
import { Cumulonimbus } from '../types';
import { Op } from 'sequelize/dist';
import multer from 'multer';
import Bcrypt from 'bcrypt';
import User from '../utils/DB/User';
import {
  browserName,
  getInvalidFields,
  FieldTypeOptions
} from '../utils/RequestUtils';
import { extractToken, generateToken } from '../utils/Token';
import { randomInt } from 'crypto';
import { unlink } from 'fs/promises';
import Upload from '../utils/DB/Upload';

const UserEndpoints: Cumulonimbus.APIEndpointModule = [
  {
    method: 'get',
    path: '/user',
    async handler(req, res) {
      if (!req.user)
        res.status(401).json(new ResponseStructures.NotAuthenticated());
      else {
        let u = req.user.toJSON();
        delete u.password;
        delete u.sessions;
        res.status(200).json(u as Cumulonimbus.UserStructure);
      }
    }
  },
  {
    method: 'patch',
    path: '/user',
    preHandlers: multer().none(),
    async handler(
      req: Cumulonimbus.Request<{
        username: string;
        email: string;
        newPassword: string;
        password: string;
      }>,
      res
    ) {
      if (!req.user)
        res.status(401).json(new ResponseStructures.NotAuthenticated());
      let invalidFields = getInvalidFields(req.body, {
        username: new FieldTypeOptions('string', true),
        email: new FieldTypeOptions('string', true),
        newPassword: new FieldTypeOptions('string', true),
        password: 'string'
      });

      if (invalidFields.length > 0)
        res
          .status(400)
          .json(new ResponseStructures.MissingFields(invalidFields));
      else if (
        req.body.username === undefined &&
        req.body.email === undefined &&
        req.body.newPassword === undefined
      )
        res
          .status(400)
          .json(
            new ResponseStructures.MissingFields([
              'username',
              'email',
              'password'
            ])
          );
      else {
        let match = await Bcrypt.compare(req.body.password, req.user.password);
        if (!match)
          res.status(401).json(new ResponseStructures.InvalidPassword());
        else {
          let newFields: { [key: string]: string } = {};
          if (req.body.newPassword)
            newFields['password'] = await Bcrypt.hash(
              req.body.newPassword,
              randomInt(0, 15)
            );
          if (req.body.username) {
            newFields['username'] = req.body.username;
            newFields['displayName'] = req.body.username.toLowerCase();
          }
          if (req.body.email) newFields['email'] = req.body.email;

          await req.user.update(newFields);
          res.status(204).end();
        }
      }
    }
  },
  {
    method: 'delete',
    path: '/user',
    async handler(
      req: Cumulonimbus.Request<{ username: string; password: string }>,
      res
    ) {
      if (!req.user)
        res.status(401).json(new ResponseStructures.NotAuthenticated());
      let invalidFields = getInvalidFields(req.body, {
        username: 'string',
        password: 'string'
      });
      if (invalidFields.length > 0)
        res
          .status(400)
          .json(new ResponseStructures.MissingFields(invalidFields));

      let match = await Bcrypt.compare(req.body.password, req.user.password);
      if (!match)
        res.status(401).json(new ResponseStructures.InvalidPassword());
      if (req.body.username !== req.user.username)
        res
          .status(403)
          .json(new ResponseStructures.GenericError('Invalid Username'));
      let files = await Upload.findAll({
        where: {
          userID: req.user.id
        }
      });
      files.forEach(async u => {
        await unlink(`./uploads/${u.filename}`);
        await u.destroy();
      });
      res.status(204).end();
    }
  },
  {
    method: 'post',
    path: '/user',
    preHandlers: multer().none(),
    async handler(
      req: Cumulonimbus.Request<{
        username: string;
        email: string;
        password: string;
        repeatPassword: string;
        rememberMe: boolean;
      }>,
      res
    ) {
      let invalidFields = getInvalidFields(req.body, {
        username: 'string',
        email: 'string',
        password: 'string',
        repeatPassword: 'string',
        rememberMe: new FieldTypeOptions('boolean', true)
      });
      if (invalidFields.length > 0)
        res
          .status(400)
          .json(new ResponseStructures.MissingFields(invalidFields));

      let u = await User.findOne({
        where: {
          [Op.or]: {
            email: req.body.email,
            username: req.body.username.toLowerCase()
          }
        }
      });
      if (u)
        res
          .status(409)
          .json(new ResponseStructures.GenericError('User Already Exists'));
      else {
        if (req.body.password !== req.body.repeatPassword)
          res
            .status(400)
            .json(
              new ResponseStructures.GenericError('Passwords do not match')
            );
        else {
          let userID = Date.now().toString(),
            newHash = await Bcrypt.hash(req.body.password, randomInt(0, 15)),
            token = await generateToken(
              userID,
              browserName(req.ua),
              !req.body.rememberMe
            ),
            tokenData = extractToken(token);
          await User.create({
            username: req.body.username.toLowerCase(),
            displayName: req.body.username,
            email: req.body.email,
            domain: 'alekeagle.me',
            subdomain: '',
            password: newHash,
            staff: null,
            id: userID,
            sessions: [
              {
                iat: tokenData.payload.iat,
                exp: tokenData.payload.exp,
                name: tokenData.payload.name
              }
            ]
          });
          res.status(201).json({
            token,
            exp: tokenData.payload.exp
          } as Cumulonimbus.SuccessfulAuthStructure);
        }
      }
    }
  }
];

export default UserEndpoints;
