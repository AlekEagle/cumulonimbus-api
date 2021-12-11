import {
  FieldTypeOptions,
  getInvalidFields,
  ResponseConstructors
} from '../../utils/RequestUtils';
import { Cumulonimbus } from '../../types';
import { Op } from 'sequelize/dist';
import { unlink } from 'fs/promises';
import File from '../../utils/DB/File';
import Multer from 'multer';

const UserFileEndpoints: Cumulonimbus.APIEndpointModule = [
  {
    method: 'get',
    path: '/user/files',
    async handler(
      req: Cumulonimbus.Request<null, null, { limit: number; offset: number }>,
      res: Cumulonimbus.Response<
        Cumulonimbus.Structures.List<Cumulonimbus.Structures.File>
      >
    ) {
      try {
        if (req.query.limit > 50) req.query.limit = 50;

        if (!req.user)
          res
            .status(401)
            .json(new ResponseConstructors.Errors.InvalidSession());
        else {
          let uls = await File.findAndCountAll({
            limit: req.query.limit,
            offset: req.query.offset,
            order: [['createdAt', 'DESC']],
            where: {
              userId: req.user.id
            }
          });

          let files = uls.rows.map(u =>
            u.toJSON()
          ) as Cumulonimbus.Structures.File[];

          res.status(200).json({
            count: uls.count,
            items: files
          } as Cumulonimbus.Structures.List<Cumulonimbus.Structures.File>);
        }
      } catch (error) {
        throw error;
      }
    }
  },
  {
    method: 'get',
    path: '/user/file/:id',
    async handler(
      req: Cumulonimbus.Request<null, { id: string }, null>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.File>
    ) {
      try {
        if (!req.user)
          res
            .status(401)
            .json(new ResponseConstructors.Errors.InvalidSession());
        else {
          let ul = await File.findOne({
            where: {
              filename: req.params.id,
              userId: req.user.id
            }
          });

          if (!ul)
            res.status(404).json(new ResponseConstructors.Errors.InvalidFile());
          else
            res.status(200).json(ul.toJSON() as Cumulonimbus.Structures.File);
        }
      } catch (error) {
        throw error;
      }
    }
  },
  {
    method: 'delete',
    path: '/user/file/:id',
    async handler(
      req: Cumulonimbus.Request<null, { id: string }, null>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.Success>
    ) {
      try {
        if (!req.user)
          res
            .status(401)
            .json(new ResponseConstructors.Errors.InvalidSession());
        else {
          let ul = await File.findOne({
            where: {
              filename: req.params.id,
              userId: req.user.id
            }
          });

          if (!ul)
            res.status(404).json(new ResponseConstructors.Errors.InvalidFile());
          else {
            try {
              await unlink(`./uploads/${ul.filename}`);
              await ul.destroy();
              res
                .status(200)
                .json(new ResponseConstructors.Success.Generic('File Deleted'));
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
    path: '/user/files',
    preHandlers: Multer().none(),
    async handler(
      req: Cumulonimbus.Request<{ files: string[] }>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.DeleteBulk>
    ) {
      try {
        if (!req.user)
          res
            .status(401)
            .json(new ResponseConstructors.Errors.InvalidSession());
        else {
          if (
            !req.body.files ||
            req.body.files.length < 0 ||
            req.body.files.length > 100
          )
            res
              .status(400)
              .json(new ResponseConstructors.Errors.MissingFields(['files']));
          else {
            let uls = await File.findAndCountAll({
              where: {
                filename: {
                  [Op.in]: req.body.files
                }
              }
            });

            if (uls.count < 1) res.status(200).json({ count: 0, type: 'file' });
            else {
              for (let ul of uls.rows) {
                try {
                  await unlink(`./uploads/${ul.filename}`);
                  await ul.destroy();
                } catch (error) {
                  throw error;
                }
              }
              res.status(200).json({ count: uls.count, type: 'file' });
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
    path: '/user/files/all',
    async handler(
      req,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.DeleteBulk>
    ) {
      try {
        if (!req.user)
          res
            .status(401)
            .json(new ResponseConstructors.Errors.InvalidSession());
        else {
          try {
            let uls = await File.findAndCountAll({
              where: {
                userId: req.user.id
              }
            });

            for (let ul of uls.rows) {
              try {
                await unlink(`./uploads/${ul.filename}`);
                await ul.destroy();
              } catch (error) {
                throw error;
              }
            }

            res.status(200).json({ count: uls.count, type: 'file' });
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

export default UserFileEndpoints;
