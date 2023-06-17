import { logger, app } from "../../index.js";
import { Errors, Success } from "../../utils/TemplateResponses.js";
import {
  getInvalidFields,
  FieldTypeOptions,
} from "../../utils/FieldValidator.js";
import AutoTrim from "../../middleware/AutoTrim.js";
import Instruction from "../../DB/Instruction.js";
import { INSTRUCTION_REGEX } from "../../utils/Constants.js";

import { Request, Response } from "express";
import { Op } from "sequelize";

logger.debug("Loading privileged/instruction.ts...");

app.post(
  // POST /api/instruction
  "/api/instruction",
  AutoTrim(),
  async (
    req: Request<
      null,
      null,
      {
        steps: string[];
        filename?: string;
        fileContent: string;
        description: string;
        displayName: string;
        name: string;
      }
    >,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff) return res.status(403).send(new Errors.Permissions());

    let invalidFields = getInvalidFields(req.body, {
      steps: new FieldTypeOptions("array", false, "string"),
      filename: new FieldTypeOptions("string", true),
      fileContent: "string",
      description: "string",
      displayName: "string",
      name: "string",
    });

    if (invalidFields.length > 0)
      return res.status(400).send(new Errors.MissingFields(invalidFields));

    if (!req.body.name.match(INSTRUCTION_REGEX))
      return res.status(400).send(new Errors.MissingFields(["name"]));

    try {
      if (await Instruction.findByPk(req.body.name))
        return res.status(409).send(new Errors.InstructionExists());

      let instruction = await Instruction.create({
        steps: req.body.steps,
        fileContent: req.body.fileContent,
        filename: req.body.filename,
        description: req.body.description,
        displayName: req.body.displayName,
        name: req.body.name,
      });

      return res.status(201).send(instruction.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.patch(
  // PATCH /api/instruction/:name/steps
  "/api/instruction/:name/steps",
  AutoTrim(),
  async (
    req: Request<{ name: string }, null, { steps: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff) return res.status(403).send(new Errors.Permissions());

    let invalidFields = getInvalidFields(req.body, {
      steps: new FieldTypeOptions("array", false, "string"),
    });

    if (invalidFields.length > 0)
      return res.status(400).send(new Errors.MissingFields(invalidFields));

    try {
      let instruction = await Instruction.findByPk(req.params.name);
      if (!instruction)
        return res.status(404).send(new Errors.InvalidInstruction());

      await instruction.update({
        steps: req.body.steps,
      });

      return res.status(200).send(instruction.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.patch(
  // PATCH /api/instruction/:name/file
  "/api/instruction/:name/file",
  AutoTrim(),
  async (
    req: Request<
      { name: string },
      null,
      { filename: string | null; fileContent: string }
    >,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff) return res.status(403).send(new Errors.Permissions());

    let invalidFields = getInvalidFields(req.body, {
      filename: new FieldTypeOptions("string", true),
      fileContent: "string",
    });

    if (invalidFields.length > 0)
      return res.status(400).send(new Errors.MissingFields(invalidFields));

    try {
      let instruction = await Instruction.findByPk(req.params.name);
      if (!instruction)
        return res.status(404).send(new Errors.InvalidInstruction());

      await instruction.update({
        filename: req.body.filename,
        fileContent: req.body.fileContent,
      });

      return res.status(200).send(instruction.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.patch(
  // PATCH /api/instruction/:name/description
  "/api/instruction/:name/description",
  AutoTrim(),
  async (
    req: Request<{ name: string }, null, { description: string }>,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff) return res.status(403).send(new Errors.Permissions());

    let invalidFields = getInvalidFields(req.body, {
      description: "string",
    });

    if (invalidFields.length > 0)
      return res.status(400).send(new Errors.MissingFields(invalidFields));

    try {
      let instruction = await Instruction.findByPk(req.params.name);
      if (!instruction)
        return res.status(404).send(new Errors.InvalidInstruction());

      await instruction.update({
        description: req.body.description,
      });

      return res.status(200).send(instruction.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.patch(
  // PATCH /api/instruction/:name/display-name
  "/api/instruction/:name(a-z0-9-)/display-name",
  AutoTrim(),
  async (
    req: Request<{ name: string }, null, { displayName: string }>,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff) return res.status(403).send(new Errors.Permissions());

    let invalidFields = getInvalidFields(req.body, {
      displayName: "string",
    });

    if (invalidFields.length > 0)
      return res.status(400).send(new Errors.MissingFields(invalidFields));

    try {
      let instruction = await Instruction.findByPk(req.params.name);
      if (!instruction)
        return res.status(404).send(new Errors.InvalidInstruction());

      await instruction.update({
        displayName: req.body.displayName,
      });

      return res.status(200).send(instruction.toJSON());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/instruction/:name
  "/api/instruction/:name",
  async (
    req: Request<{ name: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff) return res.status(403).send(new Errors.Permissions());

    try {
      let instruction = await Instruction.findByPk(req.params.name);
      if (!instruction)
        return res.status(404).send(new Errors.InvalidInstruction());

      await instruction.destroy();

      return res.status(200).send(new Success.DeleteInstruction());
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/instructions/
  "/api/instructions",
  async (
    req: Request<null, null, { names: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff) return res.status(403).send(new Errors.Permissions());

    let invalidFields = getInvalidFields(req.body, {
      names: new FieldTypeOptions("array", false, "string"),
    });

    if (invalidFields.length > 0)
      return res.status(400).send(new Errors.MissingFields(invalidFields));

    try {
      let instructions = await Instruction.findAll({
        where: {
          name: {
            [Op.in]: req.body.names,
          },
        },
      });

      await Promise.all(
        instructions.map((instruction) => instruction.destroy())
      );

      return res
        .status(200)
        .send(new Success.DeleteInstructions(instructions.length));
    } catch (e) {
      logger.error(e);
      return res.status(500).send(new Errors.Internal());
    }
  }
);
