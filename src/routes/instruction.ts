import { app } from '../index.js';
import logger from '../utils/LogMachine.js';
import { Errors, Success } from '../utils/TemplateResponses.js';
import AutoTrim from '../middleware/AutoTrim.js';
import Instruction, { InstructionStepActions } from '../DB/Instruction.js';
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
  // MARK: GET /api/instructions
  '/api/instructions',
  SessionChecker(),
  LimitOffset(0, 50),
  async (
    req: Request<{}, null, null, { limit?: string; offset?: string }>,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.Instruction>
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
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
  // MARK: GET /api/instructions/:id
  '/api/instructions/:id',
  SessionChecker(),
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
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
  // MARK: POST /api/instructions
  '/api/instructions',
  AutoTrim(),
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_INSTRUCTIONS),
  BodyValidator({
    name: 'string',
    description: 'string',
    steps: new ExtendedValidBodyTypes().array('record', {
      action: 'string',
      content: 'string',
      file: new ExtendedValidBodyTypes().notRequired().object({
        name: 'string',
        content: 'string',
      }),
      url: new ExtendedValidBodyTypes().notRequired().string(),
    }),
  }),
  async (
    req: Request<
      {},
      null,
      {
        name: string;
        description: string;
        steps: {
          action: InstructionStepActions;
          content: string;
          file?: {
            name: string;
            content: string;
          };
          url?: string;
        }[];
      }
    >,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    try {
      // Generate the instruction ID based off of the name.
      const id = req.body.name
        .toLowerCase() // Lowercase the name.
        .replace(/ /g, '-') // Replace spaces with dashes.
        .replace(/[^a-z0-9_\-\.]/g, ''); // Remove any characters that aren't a-z, 0-9, _, -, or ..

      // If resulting ID is empty, return an InvalidInstruction error.
      if (!id) return res.status(400).json(new Errors.InvalidInstruction());

      // Check if the instruction already exists.
      const instruction = await Instruction.findByPk(id);

      // If the instruction already exists, return an InstructionExists error.
      if (instruction)
        return res.status(409).json(new Errors.InstructionExists());

      // Do some validation or preprocessing on the steps if necessary.

      for (const [index, step] of req.body.steps.entries()) {
        // Is the step's action a valid action?
        if (!Object.values(InstructionStepActions).includes(step.action)) {
          return res.status(400).json(new Errors.InvalidInstruction());
        }
        // If the step's action requires a file, ensure the file is provided.
        if (
          step.action === InstructionStepActions.DOWNLOAD_CONFIG_FILE &&
          !step.file
        ) {
          return res
            .status(400)
            .json(new Errors.MissingFields([`steps[${index}].file`]));
        }
        // If the step's action requires a URL, ensure the URL is provided.
        if (step.action === InstructionStepActions.OPEN_URL && !step.url) {
          return res
            .status(400)
            .json(new Errors.MissingFields([`steps[${index}].url`]));
        }
      }

      // Create the instruction.
      const newInstruction = await Instruction.create({
        id,
        name: req.body.name,
        description: req.body.description,
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
  // MARK: PUT /api/instructions/:id/name
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
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
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
  // MARK: PUT /api/instructions/:id/description
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
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
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
  // MARK: PUT /api/instructions/:id/steps
  '/api/instructions/:id/steps',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_INSTRUCTIONS),
  AutoTrim(),
  BodyValidator({
    steps: new ExtendedValidBodyTypes().array('record', {
      action: 'string',
      content: 'string',
      file: new ExtendedValidBodyTypes().notRequired().object({
        name: 'string',
        content: 'string',
      }),
      url: new ExtendedValidBodyTypes().notRequired().string(),
    }),
  }),
  async (
    req: Request<
      { id: string },
      null,
      {
        steps: {
          action: string;
          content: string;
          file?: { name: string; content: string };
          url?: string;
        }[];
      }
    >,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    try {
      // Get the instruction.
      const instruction = await Instruction.findByPk(req.params.id);

      // If the instruction doesn't exist, return an InvalidInstruction error.
      if (!instruction)
        return res.status(404).json(new Errors.InvalidInstruction());

      // Validate the steps.
      for (const [index, step] of req.body.steps.entries()) {
        if (step.action === InstructionStepActions.OPEN_URL && !step.url) {
          return res
            .status(400)
            .json(new Errors.MissingFields([`steps[${index}].url`]));
        }
        if (
          step.action === InstructionStepActions.DOWNLOAD_CONFIG_FILE &&
          !step.file
        ) {
          return res
            .status(400)
            .json(new Errors.MissingFields([`steps[${index}].file`]));
        }
      }

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
  // MARK: DELETE /api/instructions/:id
  '/api/instructions/:id',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_INSTRUCTIONS),
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
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
  // MARK: DELETE /api/instructions
  '/api/instructions',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_INSTRUCTIONS),
  BodyValidator({
    ids: new ExtendedValidBodyTypes().array('string'),
  }),
  async (
    req: Request<{}, null, { ids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
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
