import { Cumulonimbus } from '../../types';
import Multer from 'multer';
import Instruction from '../../utils/DB/Instruction';
import {
  FieldTypeOptions,
  getInvalidFields,
  ResponseConstructors
} from '../../utils/RequestUtils';
import { Op } from 'sequelize/dist';

const AdminInstructionEndpoints: Cumulonimbus.APIEndpointModule = [
  {
    method: 'post',
    path: '/instruction',
    preHandlers: Multer().none(),
    async handler(
      req: Cumulonimbus.Request<
        {
          steps: string[];
          filename: string;
          fileContent: string;
          description: string;
          displayName: string;
          name: string;
        },
        null,
        null
      >,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.Instruction>
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
          let invalidFields = getInvalidFields(req.body, {
            steps: new FieldTypeOptions('array', false, 'string'),
            filename: new FieldTypeOptions('string', true),
            fileContent: 'string',
            description: 'string',
            displayName: 'string',
            name: 'string'
          });
          if (invalidFields.length > 0)
            res
              .status(400)
              .json(
                new ResponseConstructors.Errors.MissingFields(invalidFields)
              );
          else {
            try {
              let {
                steps,
                filename,
                fileContent,
                description,
                displayName,
                name
              } = req.body;

              let i = await Instruction.findOne({
                where: {
                  name
                }
              });

              if (i)
                res
                  .status(409)
                  .json(new ResponseConstructors.Errors.InstructionExists());
              else {
                let instruction = await Instruction.create({
                  steps,
                  fileContent,
                  filename,
                  description,
                  displayName,
                  name
                });
                res.status(201).json(instruction.toJSON());
              }
            } catch (error) {
              throw error;
            }
          }
        }
      }
    }
  },
  {
    method: 'patch',
    path: '/instruction/:id',
    preHandlers: Multer().none(),
    async handler(
      req: Cumulonimbus.Request<
        {
          steps: string[];
          filename: string | null;
          fileContent: string;
          description: string;
          displayName: string;
        },
        { id: string },
        null
      >,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.Instruction>
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
          if (
            req.body.steps === undefined &&
            req.body.filename === undefined &&
            req.body.filename !== null &&
            req.body.fileContent === undefined &&
            req.body.description === undefined &&
            req.body.displayName === undefined
          )
            res
              .status(400)
              .json(
                new ResponseConstructors.Errors.MissingFields([
                  'steps',
                  'filename',
                  'fileContent',
                  'description',
                  'displayName'
                ])
              );
          else {
            try {
              let instruction = await Instruction.findOne({
                where: {
                  name: req.params.id
                }
              });

              if (!instruction)
                res
                  .status(404)
                  .json(new ResponseConstructors.Errors.InvalidInstruction());
              else {
                let newFields: { [key: string]: any } = {};
                if (req.body.description)
                  newFields['description'] = req.body.description;
                if (req.body.displayName)
                  newFields['displayName'] = req.body.displayName;
                if (req.body.fileContent)
                  newFields['fileContent'] = req.body.fileContent;
                if (req.body.filename)
                  newFields['filename'] = req.body.filename;
                if (req.body.steps) newFields['steps'] = req.body.steps;

                await instruction.update(newFields);

                res.status(200).json(instruction.toJSON());
              }
            } catch (error) {
              throw error;
            }
          }
        }
      }
    }
  },
  {
    method: 'delete',
    path: '/instruction/:id',
    async handler(
      req: Cumulonimbus.Request<null, { id: string }, null>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.Instruction>
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
            let instruction = await Instruction.findOne({
              where: {
                name: req.params.id
              }
            });

            if (!instruction)
              res
                .status(404)
                .json(new ResponseConstructors.Errors.InvalidInstruction());
            else {
              let d = instruction.toJSON();
              await instruction.destroy();
              res.status(200).json(d);
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
    path: '/instructions',
    async handler(
      req: Cumulonimbus.Request<{ instructions: string[] }, null, null>,
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
            if (
              !req.body.instructions ||
              req.body.instructions.length < 1 ||
              req.body.instructions.length > 100
            )
              res
                .status(400)
                .json(
                  new ResponseConstructors.Errors.MissingFields([
                    'instructions'
                  ])
                );
            else {
              let { count, rows: instructions } =
                await Instruction.findAndCountAll({
                  where: {
                    name: {
                      [Op.or]: req.body.instructions
                    }
                  }
                });

              for (let instruction of instructions) {
                await instruction.destroy();
              }
              res.status(200).json({ count, type: 'instruction' });
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
    path: '/instructions/all',
    async handler(
      req: Cumulonimbus.Request<null, null, null>,
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
            let { count, rows: instructions } =
              await Instruction.findAndCountAll({});

            for (let instruction of instructions) {
              await instruction.destroy();
            }
            res.status(200).json({ count, type: 'instruction' });
          } catch (error) {
            throw error;
          }
        }
      }
    }
  }
];

export default AdminInstructionEndpoints;
