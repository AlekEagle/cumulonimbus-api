import { Cumulonimbus } from '../../types';
import Multer from 'multer';
import Bcrypt from 'bcrypt';
import User from '../../utils/DB/User';
import {
  FieldTypeOptions,
  getInvalidFields,
  ResponseConstructors,
  validateSubdomain
} from '../../utils/RequestUtils';
import { randomInt } from 'node:crypto';
import File from '../../utils/DB/File';
import { unlink } from 'node:fs/promises';
import { Op } from 'sequelize/dist';
import Domain from '../../utils/DB/Domain';

const AdminAccountEndpoints: Cumulonimbus.APIEndpointModule = [
  {
    method: 'get',
    path: '/users',
    async handler(
      req: Cumulonimbus.Request<
        null,
        null,
        {
          limit: number;
          offset: number;
        }
      >,
      res: Cumulonimbus.Response<
        Cumulonimbus.Structures.List<Cumulonimbus.Structures.User>
      >
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        if (!req.user.staff)
          res.status(403).json(new ResponseConstructors.Errors.Permissions());
        else {
          try {
            if (req.query.limit > 50) req.query.limit = 50;

            let { count, rows } = await User.findAndCountAll({
                limit: req.query.limit,
                offset: req.query.offset,
                order: [['createdAt', 'DESC']]
              }),
              strippedUsers = rows.map(u => {
                let a = u.toJSON();
                delete a.password;
                delete a.sessions;
                return a;
              });

            res.status(200).json({ count, items: strippedUsers });
          } catch (error) {
            throw error;
          }
        }
      }
    }
  },
  {
    method: 'get',
    path: '/user/:id([0-9]+)',
    async handler(
      req: Cumulonimbus.Request<null, { id: string }, null>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.User>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        if (!req.user.staff)
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
              let strippedUser = u.toJSON();
              delete strippedUser.password;
              delete strippedUser.sessions;
              res.status(200).json(strippedUser);
            }
          } catch (error) {
            throw error;
          }
        }
      }
    }
  },
  {
    method: 'patch',
    path: '/user/:id([0-9]+)',
    preHandlers: Multer().none(),
    async handler(
      req: Cumulonimbus.Request<
        { username: string; password: string; email: string; staff: boolean },
        { id: string },
        null
      >,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.User>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        if (!req.user.staff)
          res.status(403).json(new ResponseConstructors.Errors.Permissions());
        else {
          try {
            if (
              req.body.email === undefined &&
              req.body.password === undefined &&
              req.body.username === undefined &&
              req.body.staff === undefined
            )
              res
                .status(400)
                .json(
                  new ResponseConstructors.Errors.MissingFields([
                    'username',
                    'password',
                    'email',
                    'staff'
                  ])
                );
            else {
              let existingUserConstraints: any = {
                where: {
                  [Op.or]: []
                }
              };
              if (req.body.username !== undefined)
                existingUserConstraints.where[Op.or].username =
                  req.body.username;
              if (req.body.email !== undefined)
                existingUserConstraints.where[Op.or].email = req.body.email;
              let existingUser = await User.findOne(existingUserConstraints);
              if (existingUser) {
                if (existingUser.id !== req.params.id) {
                  res
                    .status(409)
                    .json(new ResponseConstructors.Errors.UserExists());
                  return;
                }
              }
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
                let updatedFields: { [key: string]: string | boolean } = {};
                if (req.body.password)
                  updatedFields['password'] = await Bcrypt.hash(
                    req.body.password,
                    randomInt(0, 15)
                  );

                if (req.body.email) updatedFields['email'] = req.body.email;
                if (req.body.username) {
                  updatedFields['username'] = req.body.username;
                }
                if (req.body.staff !== undefined)
                  updatedFields['staff'] = req.body.staff;

                let updatedU = await u.update(updatedFields),
                  strippedUser = updatedU.toJSON();
                delete strippedUser.password;
                delete strippedUser.sessions;
                res.status(200).json(strippedUser);
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
    method: 'patch',
    path: '/user/:id([0-9]+)/domain',
    preHandlers: Multer().none(),
    async handler(
      req: Cumulonimbus.Request<
        { domain: string; subdomain?: string },
        { id: string }
      >,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.User>
    ) {
      try {
        if (!req.user)
          res
            .status(401)
            .json(new ResponseConstructors.Errors.InvalidSession());
        else {
          let invalidFields = getInvalidFields(req.body, {
            domain: 'string',
            subdomain: new FieldTypeOptions('string', true)
          });
          if (invalidFields.length > 0)
            res
              .status(400)
              .json(
                new ResponseConstructors.Errors.MissingFields(invalidFields)
              );
          else {
            try {
              let domain = await Domain.findOne({
                  where: {
                    domain: req.body.domain
                  }
                }),
                user = await User.findOne({
                  where: {
                    id: req.params.id
                  }
                });
              if (!domain)
                res
                  .status(404)
                  .json(new ResponseConstructors.Errors.InvalidDomain());
              else if (!user) {
                res
                  .status(404)
                  .json(new ResponseConstructors.Errors.InvalidUser());
              } else {
                if (!req.body.subdomain) {
                  await user.update({
                    domain: domain.domain,
                    subdomain: null
                  });

                  let u = user.toJSON();
                  delete u.password;
                  delete u.sessions;
                  res.status(200).json(u as Cumulonimbus.Structures.User);
                } else {
                  if (!domain.allowsSubdomains)
                    res
                      .status(400)
                      .json(
                        new ResponseConstructors.Errors.SubdomainNotSupported()
                      );
                  else {
                    let safeSubdomain = validateSubdomain(req.body.subdomain);
                    if (safeSubdomain.length > 63)
                      res
                        .status(400)
                        .json(
                          new ResponseConstructors.Errors.InvalidSubdomain(
                            safeSubdomain
                          )
                        );
                    else {
                      await user.update({
                        domain: domain.domain,
                        subdomain: safeSubdomain
                      });

                      let u = user.toJSON();
                      delete u.password;
                      delete u.sessions;
                      res.status(200).json(u as Cumulonimbus.Structures.User);
                    }
                  }
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
  },
  {
    method: 'patch',
    path: '/user/:id([0-9]+)/ban',
    async handler(
      req: Cumulonimbus.Request<null, { id: string }, null>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.User>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        if (!req.user.staff)
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
              if (u.bannedAt !== null) await u.update({ bannedAt: null });
              else await u.update({ bannedAt: new Date(Date.now()) });

              let strippedUser = u.toJSON();
              delete strippedUser.password;
              delete strippedUser.sessions;
              res.status(200).json(strippedUser);
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
    path: '/user/:id([0-9]+)',
    async handler(
      req: Cumulonimbus.Request<null, { id: string }, null>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.User>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        if (!req.user.staff)
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
              let uls = await File.findAll({
                where: {
                  userID: u.id
                }
              });

              for (let ul of uls) {
                try {
                  await unlink(`/var/www-uploads/${ul.filename}`);
                  await ul.destroy();
                } catch (error) {
                  throw error;
                }
              }
              let userStripped = u.toJSON();
              delete userStripped.password;
              delete userStripped.sessions;
              await u.destroy();
              res.status(200).json(userStripped);
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
    path: '/users',
    async handler(
      req: Cumulonimbus.Request<{ users: string[] }, null, null>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.DeleteBulk>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        if (!req.user.staff)
          res.status(403).json(new ResponseConstructors.Errors.Permissions());
        else {
          if (
            !req.body.users ||
            req.body.users.length < 1 ||
            req.body.users.length > 100
          )
            res
              .status(400)
              .json(new ResponseConstructors.Errors.MissingFields(['users']));
          else {
            try {
              let { count, rows: users } = await User.findAndCountAll({
                where: {
                  id: {
                    [Op.in]: req.body.users
                  }
                }
              });
              for (let user of users) {
                let userFiles = await File.findAll({
                  where: {
                    userID: user.id
                  }
                });

                for (let file of userFiles) {
                  await unlink(`/var/www-uploads/${file.filename}`);
                  await file.destroy();
                }

                await user.destroy();
              }

              res.status(200).json({ count, type: 'user' });
            } catch (error) {
              throw error;
            }
          }
        }
      }
    }
  }
];

export default AdminAccountEndpoints;
