import { Cumulonimbus } from '../../types';
import { Op } from 'sequelize/dist';
import User from '../../utils/DB/User';
import { ResponseConstructors } from '../../utils/RequestUtils';
import File from '../../utils/DB/File';
import { unlink } from 'node:fs/promises';

const AdminFileEndpoints: Cumulonimbus.APIEndpointModule = [
  {
    method: 'get',
    path: '/files',
    async handler(
      req: Cumulonimbus.Request<null, null, { offset: number; limit: number }>,
      res: Cumulonimbus.Response<
        Cumulonimbus.Structures.List<Cumulonimbus.Structures.File>
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
            let { count, rows: files } = await File.findAndCountAll({
              limit: req.query.limit,
              offset: req.query.offset,
              order: [['createdAt', 'DESC']]
            });
            let items = files.map(file => file.toJSON());

            res.status(200).json({ count, items });
          } catch (error) {
            throw error;
          }
        }
      }
    }
  },
  {
    method: 'get',
    path: '/user/:id([0-9]+)/files',
    async handler(
      req: Cumulonimbus.Request<
        null,
        { id: string },
        { offset: number; limit: number }
      >,
      res: Cumulonimbus.Response<
        Cumulonimbus.Structures.List<Cumulonimbus.Structures.File>
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
              if (req.query.limit > 50) req.query.limit = 50;
              let { count, rows: files } = await File.findAndCountAll({
                limit: req.query.limit,
                offset: req.query.offset,
                order: [['createdAt', 'DESC']],
                where: {
                  userID: u.id
                }
              });
              let items = files.map(file => file.toJSON());

              res.status(200).json({ count, items });
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
    path: '/file/:id',
    async handler(
      req: Cumulonimbus.Request<null, { id: string }, null>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.File>
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
            let file = await File.findOne({
              where: {
                filename: req.params.id
              }
            });

            if (!file)
              res
                .status(404)
                .json(new ResponseConstructors.Errors.InvalidFile());
            else {
              res.status(200).json(file.toJSON());
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
    path: '/file/:id',
    async handler(
      req: Cumulonimbus.Request<null, { uid: string; id: string }, null>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.File>
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
            let file = await File.findOne({
              where: {
                filename: req.params.id
              }
            });

            if (!file)
              res
                .status(404)
                .json(new ResponseConstructors.Errors.InvalidFile());
            else {
              await unlink(`/var/www-uploads/${file.filename}`);
              await file.destroy();

              res.status(200).json(file.toJSON());
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
    path: '/files',
    async handler(
      req: Cumulonimbus.Request<{ files: string[] }, { id: string }, null>,
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
            let { count, rows: files } = await File.findAndCountAll({
              where: {
                filename: {
                  [Op.in]: req.body.files
                }
              }
            });

            for (let file of files) {
              await unlink(`/var/www-uploads/${file.filename}`);
              await file.destroy();
            }

            res.status(200).json({ count, type: 'file' });
          } catch (error) {
            throw error;
          }
        }
      }
    }
  }
];

export default AdminFileEndpoints;
