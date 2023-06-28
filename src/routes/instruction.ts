import { logger, app } from "../index.js";
import { Errors, Success } from "../utils/TemplateResponses.js";
import { getInvalidFields, FieldTypeOptions } from "../utils/FieldValidator.js";
import AutoTrim from "../middleware/AutoTrim.js";
import Instruction from "../DB/Instruction.js";
import { INSTRUCTION_REGEX } from "../utils/Constants.js";
import FieldExtractor from "../utils/FieldExtractor.js";

import { Request, Response } from "express";
import { Op } from "sequelize";

logger.debug("Loading: Instruction Routes...");

app.get(
  // GET /api/instructions
  "/api/instructions",
  async (
    req: Request<null, null, null, { limit: number; offset: number }>,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.Instruction>
      | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // Normalize the limit and offset.
    const limit =
        req.query.limit && req.query.limit >= 0 && req.query.limit <= 50
          ? req.query.limit
          : 50,
      offset = req.query.offset && req.query.offset >= 0 ? req.query.offset : 0;

    try {
      // Get the instructions.
      const { count, rows: instructions } = await Instruction.findAndCountAll({
        limit,
        offset,
        order: [["createdAt", "DESC"]],
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) fetched instructions.)`
      );

      // Return the instructions.
      return res.status(200).send({
        count,
        items: instructions.map((d) =>
          FieldExtractor(d, ["id", "name", "description"])
        ),
      });
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.get(
  // GET /api/instructions/:id
  "/api/instructions/:id",
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    try {
      // Get the instruction.
      const instruction = await Instruction.findByPk(req.params.id);

      // If the instruction doesn't exist, return a InvalidInstruction error.
      if (!instruction)
        return res.status(404).send(new Errors.InvalidInstruction());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) fetched instruction ${instruction.name} (${instruction.id}).`
      );

      // Return the instruction.
      return res.status(200).send(instruction.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.post(
  // POST /api/instructions
  "/api/instructions",
  AutoTrim(),
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
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    // If the user is not staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Validate the fields.
      const invalidFields = getInvalidFields(req.body, {
        id: "string",
        name: "string",
        description: "string",
        filename: new FieldTypeOptions("string", true),
        content: "string",
        steps: new FieldTypeOptions("array", false, "string"),
      });

      // If there are invalid fields, return a MissingFields error.
      if (invalidFields.length)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      // If the ID is invalid, return an InvalidInstruction error.
      if (!INSTRUCTION_REGEX.test(req.body.id))
        return res.status(400).send(new Errors.InvalidInstruction());

      // Check if the instruction already exists.
      const instruction = await Instruction.findByPk(req.body.id);

      // If the instruction already exists, return an InstructionExists error.
      if (instruction)
        return res.status(409).send(new Errors.InstructionExists());

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
        `User ${req.user.username} (${req.user.id}) created instruction ${newInstruction.name} (${newInstruction.id}).`
      );

      // Return the instruction.
      return res.status(201).send(newInstruction.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.put(
  // PUT /api/instructions/:id/name
  "/api/instructions/:id/name",
  AutoTrim(),
  async (
    req: Request<{ id: string }, null, { name: string }>,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    // If the user is not staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Validate the fields.
      const invalidFields = getInvalidFields(req.body, {
        name: "string",
      });

      // If there are invalid fields, return a MissingFields error.
      if (invalidFields.length)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      // Get the instruction.
      const instruction = await Instruction.findByPk(req.params.id);

      // If the instruction doesn't exist, return an InvalidInstruction error.
      if (!instruction)
        return res.status(404).send(new Errors.InvalidInstruction());

      // Update the instruction.
      await instruction.update({ name: req.body.name });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) updated instruction ${instruction.name} (${instruction.id}).`
      );

      // Return the instruction.
      return res.status(200).send(instruction.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.put(
  // PUT /api/instructions/:id/description
  "/api/instructions/:id/description",
  AutoTrim(),
  async (
    req: Request<{ id: string }, null, { description: string }>,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    // If the user is not staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Validate the fields.
      const invalidFields = getInvalidFields(req.body, {
        description: "string",
      });

      // If there are invalid fields, return a MissingFields error.
      if (invalidFields.length)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      // Get the instruction.
      const instruction = await Instruction.findByPk(req.params.id);

      // If the instruction doesn't exist, return an InvalidInstruction error.
      if (!instruction)
        return res.status(404).send(new Errors.InvalidInstruction());

      // Update the instruction.
      await instruction.update({ description: req.body.description });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) updated instruction ${instruction.name} (${instruction.id}) description.`
      );

      // Return the instruction.
      return res.status(200).send(instruction.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.put(
  // PUT /api/instructions/:id/filename
  "/api/instructions/:id/filename",
  AutoTrim(),
  async (
    req: Request<{ id: string }, null, { filename: string }>,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    // If the user is not staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Validate the fields.
      const invalidFields = getInvalidFields(req.body, {
        filename: new FieldTypeOptions("string", true),
      });

      // If there are invalid fields, return a MissingFields error.
      if (invalidFields.length)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      // Get the instruction.
      const instruction = await Instruction.findByPk(req.params.id);

      // If the instruction doesn't exist, return an InvalidInstruction error.
      if (!instruction)
        return res.status(404).send(new Errors.InvalidInstruction());

      // Update the instruction.
      await instruction.update({ filename: req.body.filename });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) updated instruction ${instruction.name} (${instruction.id}) filename.`
      );

      // Return the instruction.
      return res.status(200).send(instruction.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.put(
  // PUT /api/instructions/:id/content
  "/api/instructions/:id/content",
  AutoTrim(),
  async (
    req: Request<{ id: string }, null, { content: string }>,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    // If the user is not staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Validate the fields.
      const invalidFields = getInvalidFields(req.body, {
        content: "string",
      });

      // If there are invalid fields, return a MissingFields error.
      if (invalidFields.length)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      // Get the instruction.
      const instruction = await Instruction.findByPk(req.params.id);

      // If the instruction doesn't exist, return an InvalidInstruction error.
      if (!instruction)
        return res.status(404).send(new Errors.InvalidInstruction());

      // Update the instruction.
      await instruction.update({ content: req.body.content });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) updated instruction ${instruction.name} (${instruction.id}) content.`
      );

      // Return the instruction.
      return res.status(200).send(instruction.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.put(
  // PUT /api/instructions/:id/steps
  "/api/instructions/:id/steps",
  AutoTrim(),
  async (
    req: Request<{ id: string }, null, { steps: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    // If the user is not staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Validate the fields.
      const invalidFields = getInvalidFields(req.body, {
        steps: new FieldTypeOptions("array", false, "string"),
      });

      // If there are invalid fields, return a MissingFields error.
      if (invalidFields.length)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      // Get the instruction.
      const instruction = await Instruction.findByPk(req.params.id);

      // If the instruction doesn't exist, return an InvalidInstruction error.
      if (!instruction)
        return res.status(404).send(new Errors.InvalidInstruction());

      // Update the instruction.
      await instruction.update({ steps: req.body.steps });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) updated instruction ${instruction.name} (${instruction.id}) steps.`
      );

      // Return the instruction.
      return res.status(200).send(instruction.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/instructions/:id
  "/api/instructions/:id",
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    // If the user is not staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Get the instruction.
      const instruction = await Instruction.findByPk(req.params.id);

      // If the instruction doesn't exist, return an InvalidInstruction error.
      if (!instruction)
        return res.status(404).send(new Errors.InvalidInstruction());

      // Delete the instruction.
      await instruction.destroy();

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted instruction ${instruction.name} (${instruction.id}).`
      );

      // Return a success.
      return res.status(200).send(new Success.DeleteInstruction());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/instructions
  "/api/instructions",
  async (
    req: Request<null, null, { ids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no user logged in, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    // If the user is not staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Validate the fields.
      const invalidFields = getInvalidFields(req.body, {
        ids: new FieldTypeOptions("array", false, "string"),
      });

      // If there are invalid fields, return a MissingFields error.
      if (invalidFields.length)
        return res.status(400).send(new Errors.MissingFields(invalidFields));

      // fetch the instructions.
      const { count, rows: instructions } = await Instruction.findAndCountAll({
        where: {
          id: {
            [Op.in]: req.body.ids,
          },
        },
      });

      // If there are no instructions, return an InvalidInstruction error.
      if (!count) return res.status(404).send(new Errors.InvalidInstruction());

      // Delete the instructions.
      await Promise.all(
        instructions.map((instruction) => instruction.destroy())
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted ${count} instructions.`
      );

      // Return a success.
      return res.status(200).send(new Success.DeleteInstruction());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);
