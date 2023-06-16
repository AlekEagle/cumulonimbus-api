import { logger, app } from "../../index.js";
import { Errors } from "../../utils/TemplateResponses.js";
import Instruction from "../../DB/Instruction.js";

import { Request, Response } from "express";

logger.debug("Loading unprivileged/instruction.ts...");

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
    try {
      if (!req.user) return res.status(401).send(new Errors.InvalidSession());
      const limit =
          req.query.limit && req.query.limit <= 50 && req.query.limit > 0
            ? req.query.limit
            : 50,
        offset =
          req.query.offset && req.query.offset >= 0 ? req.query.offset : 0;
      let { count, rows: instructions } = await Instruction.findAndCountAll({
        limit,
        offset,
      });

      let items = instructions.map((i) => i.toJSON());
      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested ${items.length} instructions.`
      );
      return res.status(200).send({ count, items });
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.get(
  // GET /api/instructions/:id
  "/api/instruction/:id",
  async (
    req: Request<{ id: string }, null, null>,
    res: Response<
      Cumulonimbus.Structures.Instruction | Cumulonimbus.Structures.Error
    >
  ) => {
    try {
      if (!req.user) return res.status(401).send(new Errors.InvalidSession());
      let instruction = await Instruction.findByPk(req.params.id);

      if (!instruction)
        return res.status(404).send(new Errors.InvalidInstruction());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested instruction ${instruction.name}.`
      );
      return res.status(200).send(instruction.toJSON());
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);
