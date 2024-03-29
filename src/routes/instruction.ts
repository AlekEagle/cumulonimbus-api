import { logger, app } from '../index.js';
import { Errors, Success } from '../utils/TemplateResponses.js';
import AutoTrim from '../middleware/AutoTrim.js';
import Instruction from '../DB/Instruction.js';
import { INSTRUCTION_REGEX } from '../utils/Constants.js';
import KVExtractor from '../utils/KVExtractor.js';
import SessionChecker from '../middleware/SessionChecker.js';
import BodyValidator, {
  ExtendedValidBodyTypes,
} from '../middleware/BodyValidator.js';
import LimitOffset from '../middleware/LimitOffset.js';
import SessionPermissionChecker, {
  PermissionFlags,
} from '../middleware/SessionPermissionChecker.js';

import { Request, Response } from 'express';
import { Op } from 'sequelize';

logger.debug('Loading: Instruction Routes...');

app.get(
  // GET /api/instructions
  '/api/instructions',
  SessionChecker(),
  LimitOffset(0, 50),
  async (
    req: Request<null, null, null, { limit?: string; offset?: string }>,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.Instruction>
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      // Get the instructions.
      const { count, rows: instructions } = await Instruction.findAndCountAll({
        limit: req.limit,
        offset: req.offset,
        order: [['createdAt', 'DESC']],
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) fetched instructions. (limit: ${req.limit}, offset: ${req.offset})`,
      );

      // Return the instructions.
      return res.status(200).json({
        count,
        items: instructions.map((d) =>
          KVExtractor(d.toJSON(), ['id', 'name', 'description']),
        ),
      });
    } catch (e) {
      logger.error(e);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/instructions/:id
  '/api/instructions/:id',
  SessionChecker(),
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      // Get the instruction.
      const instruction = await Instruction.findByPk(req.params.id);

      // If the instruction doesn't exist, return a InvalidInstruction error.
      if (!instruction)
        return res.status(404).json(new Errors.InvalidInstruction());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) fetched instruction ${instruction.name} (${instruction.id}).`,
      );

      // Return the instruction.
      return res.status(200).json(instruction.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.post(
  // POST /api/instructions
  '/api/instructions',
  AutoTrim(),
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_INSTRUCTIONS),
  BodyValidator({
    id: 'string',
    name: 'string',
    description: 'string',
    filename: new ExtendedValidBodyTypes('string', true),
    content: 'string',
    steps: new ExtendedValidBodyTypes('array', false, 'string'),
  }),
  async (
    req: Request<
      null,
      null,
      {
        id: string;
        name: string;
        description: string;
        filename: string;
        content: string;
        steps: string[];
      }
    >,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      // If the ID is invalid, return an InvalidInstruction error.
      if (!INSTRUCTION_REGEX.test(req.body.id))
        return res.status(400).json(new Errors.InvalidInstruction());

      // Check if the instruction already exists.
      const instruction = await Instruction.findByPk(req.body.id);

      // If the instruction already exists, return an InstructionExists error.
      if (instruction)
        return res.status(409).json(new Errors.InstructionExists());

      // Create the instruction.
      const newInstruction = await Instruction.create({
        id: req.body.id,
        name: req.body.name,
        description: req.body.description,
        filename: req.body.filename,
        content: req.body.content,
        steps: req.body.steps,
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) created instruction ${newInstruction.name} (${newInstruction.id}).`,
      );

      // Return the instruction.
      return res.status(201).json(newInstruction.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/instructions/:id/name
  '/api/instructions/:id/name',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_INSTRUCTIONS),
  AutoTrim(),
  BodyValidator({
    name: 'string',
  }),
  async (
    req: Request<{ id: string }, null, { name: string }>,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      // Get the instruction.
      const instruction = await Instruction.findByPk(req.params.id);

      // If the instruction doesn't exist, return an InvalidInstruction error.
      if (!instruction)
        return res.status(404).json(new Errors.InvalidInstruction());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) updated instruction ${instruction.name} (${instruction.id}). (name: ${req.body.name})`,
      );

      // Update the instruction.
      await instruction.update({ name: req.body.name });

      // Return the instruction.
      return res.status(200).json(instruction.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/instructions/:id/description
  '/api/instructions/:id/description',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_INSTRUCTIONS),
  AutoTrim(),
  BodyValidator({
    description: 'string',
  }),
  async (
    req: Request<{ id: string }, null, { description: string }>,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      // Get the instruction.
      const instruction = await Instruction.findByPk(req.params.id);

      // If the instruction doesn't exist, return an InvalidInstruction error.
      if (!instruction)
        return res.status(404).json(new Errors.InvalidInstruction());

      // Update the instruction.
      await instruction.update({ description: req.body.description });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) updated the description for instruction ${instruction.name} (${instruction.id}).`,
      );

      // Return the instruction.
      return res.status(200).json(instruction.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/instructions/:id/file
  '/api/instructions/:id/file',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_INSTRUCTIONS),
  AutoTrim(),
  BodyValidator({
    filename: new ExtendedValidBodyTypes('string', true),
    content: 'string',
  }),
  async (
    req: Request<{ id: string }, null, { filename?: string; content: string }>,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      // Get the instruction.
      const instruction = await Instruction.findByPk(req.params.id);

      // If the instruction doesn't exist, return an InvalidInstruction error.
      if (!instruction)
        return res.status(404).json(new Errors.InvalidInstruction());

      // Update the instruction.
      await instruction.update({
        filename: req.body.filename ? req.body.filename : null,
        content: req.body.content,
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) updated instruction ${instruction.name} (${instruction.id}) file.`,
      );

      // Return the instruction.
      return res.status(200).json(instruction.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/instructions/:id/steps
  '/api/instructions/:id/steps',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_INSTRUCTIONS),
  AutoTrim(),
  BodyValidator({
    steps: new ExtendedValidBodyTypes('array', false, 'string'),
  }),
  async (
    req: Request<{ id: string }, null, { steps: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      // Get the instruction.
      const instruction = await Instruction.findByPk(req.params.id);

      // If the instruction doesn't exist, return an InvalidInstruction error.
      if (!instruction)
        return res.status(404).json(new Errors.InvalidInstruction());

      // Update the instruction.
      await instruction.update({ steps: req.body.steps });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) updated instruction ${instruction.name} (${instruction.id}) steps.`,
      );

      // Return the instruction.
      return res.status(200).json(instruction.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/instructions/:id
  '/api/instructions/:id',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_INSTRUCTIONS),
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      // Get the instruction.
      const instruction = await Instruction.findByPk(req.params.id);

      // If the instruction doesn't exist, return an InvalidInstruction error.
      if (!instruction)
        return res.status(404).json(new Errors.InvalidInstruction());

      // Delete the instruction.
      await instruction.destroy();

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted instruction ${instruction.name} (${instruction.id}).`,
      );

      // Return a success.
      return res.status(200).json(new Success.DeleteInstruction());
    } catch (e) {
      logger.error(e);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/instructions
  '/api/instructions',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_INSTRUCTIONS),
  BodyValidator({
    ids: new ExtendedValidBodyTypes('array', false, 'string'),
  }),
  async (
    req: Request<null, null, { ids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    // Check if they are trying to delete more than 50 instructions.
    if (req.body.ids.length > 50)
      return res.status(400).json(new Errors.BodyTooLarge());

    try {
      // fetch the instructions.
      const { count, rows: instructions } = await Instruction.findAndCountAll({
        where: {
          id: {
            [Op.in]: req.body.ids,
          },
        },
      });

      // If there are no instructions, return an InvalidInstruction error.
      if (!count) return res.status(404).json(new Errors.InvalidInstruction());

      // Delete the instructions.
      await Promise.all(
        instructions.map((instruction) => instruction.destroy()),
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted ${count} instructions.`,
      );

      // Return a success.
      return res.status(200).json(new Success.DeleteInstruction());
    } catch (e) {
      logger.error(e);
      return res.status(500).json(new Errors.Internal());
    }
  },
);
