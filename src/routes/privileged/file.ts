import { logger, app } from "../../index.js";
import { Errors, Success } from "../../utils/TemplateResponses.js";
import {
  getInvalidFields,
  FieldTypeOptions,
} from "../../utils/FieldValidator.js";
import File from "../../DB/File.js";
import User from "../../DB/User.js";
import FieldExtractor from "../../utils/FieldExtractor.js";

import { Request, Response } from "express";
import { unlink } from "node:fs/promises";
import { join } from "node:path";
import { existsSync } from "node:fs";
import { Op } from "sequelize";

logger.debug("Loading privileged/file.ts...");

app.get(
  // GET /api/files
  "/api/files",
  async (
    req: Request<null, null, null, { offset: number; limit: number }>,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.File>
      | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      const limit =
          req.query.limit && req.query.limit <= 50 && req.query.limit > 0
            ? req.query.limit
            : 50,
        offset =
          req.query.offset && req.query.offset >= 0 ? req.query.offset : 0;
      let { count, rows: files } = await File.findAndCountAll({
        limit,
        offset,
        order: [["createdAt", "DESC"]],
      });
      let items = files.map((file) =>
        FieldExtractor(file.toJSON(), ["id", "name"])
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested ${items.length} files.`
      );

      return res.status(200).send({ count, items });
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.get(
  // GET /api/user/:id([0-9]+)/files
  "/api/user/:id([0-9]+)/files",
  async (
    req: Request<{ id: string }, null, null, { offset: number; limit: number }>,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.File>
      | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      const limit =
          req.query.limit && req.query.limit <= 50 && req.query.limit > 0
            ? req.query.limit
            : 50,
        offset =
          req.query.offset && req.query.offset >= 0 ? req.query.offset : 0;

      let user = await User.findByPk(req.params.id);
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      let { count, rows: files } = await File.findAndCountAll({
        limit,
        offset,
        where: {
          userID: user.id,
        },
        order: [["createdAt", "DESC"]],
      });
      let items = files.map((file) =>
        FieldExtractor(file.toJSON(), ["id", "name"])
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested ${items.length} files from user ${user.username} (${user.id}).`
      );

      return res.status(200).send({ count, items });
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.get(
  // GET /api/files/:fid
  "/api/file/:fid",
  async (
    req: Request<{ fid: string }>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      let file = await File.findByPk(req.params.fid);
      if (!file) return res.status(404).send(new Errors.InvalidFile());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested file ${file.id}.`
      );

      return res.status(200).send(file.toJSON());
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/file/:fid
  "/api/file/:fid",
  async (
    req: Request<{ fid: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      let file = await File.findByPk(req.params.fid);
      if (!file) return res.status(404).send(new Errors.InvalidFile());

      await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

      if (existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)))
        await unlink(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`));

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted file ${file.id}.`
      );

      await file.destroy();

      return res.status(200).send(new Success.DeleteFile());
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/files
  "/api/files",
  async (
    req: Request<null, null, { fids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    const invalidFields = getInvalidFields(req.body, {
      fids: new FieldTypeOptions("array", false, "string"),
    });

    if (invalidFields.length > 0)
      return res.status(400).json(new Errors.MissingFields(invalidFields));

    if (req.body.fids.length < 1 || req.body.fids.length > 50)
      return res.status(400).json(new Errors.MissingFields(["fids"]));

    try {
      let { count, rows: files } = await File.findAndCountAll({
        where: {
          id: {
            [Op.in]: req.body.fids,
          },
        },
      });

      await Promise.all(
        files.map(async (file) => {
          await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

          if (
            existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`))
          )
            await unlink(
              join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)
            );

          await file.destroy();
        })
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted ${count} files.`
      );

      return res.status(200).send(new Success.DeleteFiles(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/user/:id([0-9]+)/files/all
  "/api/user/:id([0-9]+)/files/all",
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      let user = await User.findByPk(req.params.id);
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      let { count, rows: files } = await File.findAndCountAll({
        where: {
          userID: user.id,
        },
      });

      await Promise.all(
        files.map(async (file) => {
          await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

          if (
            existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`))
          )
            await unlink(
              join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)
            );

          await file.destroy();
        })
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted all ${count} files from user ${user.username} (${user.id}).`
      );

      return res.status(200).send(new Success.DeleteFiles(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);
