import {
  FieldTypeOptions,
  getInvalidFields,
  ResponseConstructors
} from '../../utils/RequestUtils';
import { Cumulonimbus } from '../../types';
import { Op } from 'sequelize/dist';
import { unlink } from 'fs/promises';
import Upload from '../../utils/DB/Upload';
import Multer from 'multer';

const UserFileEndpoints: Cumulonimbus.APIEndpointModule = [
  {
    method: 'get',
    path: '/files',
    async handler(
      req: Cumulonimbus.Request<null, null, { limit: string; offset: string }>,
      res: Cumulonimbus.Response<
        Cumulonimbus.Structures.List<Cumulonimbus.Structures.File>
      >
    ) {
      try {
        let query = { limit: '50', offset: '0', ...req.query };

        if (!req.user)
          res
            .status(401)
            .json(new ResponseConstructors.Errors.InvalidSession());
        else {
          if (Number(query.limit) > 100) query.limit = '100';

          let uls = await Upload.findAndCountAll({
            order: [['createdAt', 'DESC']],
            where: {
              userId: req.user.id
            }
          });

          let files = uls.rows
            .slice(Number(query.offset), Number(query.limit))
            .map(u => u.toJSON()) as Cumulonimbus.Structures.File[];

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
    path: '/file/:id',
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
          let ul = await Upload.findOne({
            where: {
              filename: req.params.id,
              userId: req.user.id
            }
          });

          if (!ul)
            res.status(404).json(new ResponseConstructors.Errors.FileMissing());
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
    path: '/file/:id',
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
          let ul = await Upload.findOne({
            where: {
              filename: req.params.id,
              userId: req.user.id
            }
          });

          if (!ul)
            res.status(404).json(new ResponseConstructors.Errors.FileMissing());
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
    path: '/files',
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
          let invalidFields = getInvalidFields(req.body, {
            files: new FieldTypeOptions('array', false, 'string')
          });
          if (invalidFields.length > 0)
            res
              .status(400)
              .json(
                new ResponseConstructors.Errors.MissingFields(invalidFields)
              );
          else {
            let uls = await Upload.findAndCountAll({
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
    path: '/files/all',
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
            let uls = await Upload.findAndCountAll({
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
