import { logger, app } from "../../index.js";
import { Errors, Success } from "../../utils/TemplateResponses.js";
import File from "../../DB/File.js";
import FieldExtractor from "../../utils/FieldExtractor.js";

import { Op } from "sequelize";
import { unlink } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import Bcrypt from "bcrypt";
import { Request, Response } from "express";

logger.debug("Loading unprivileged/file.ts...");

app.get(
  // GET /api/users/me/files
  "/api/users/me/files",
  async (
    req: Request<null, null, null, { limit: number; offset: number }>,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.File>
      | Cumulonimbus.Structures.Error
    >
  ) => {
    try {
      const limit =
          req.query.limit && req.query.limit <= 50 && req.query.limit > 0
            ? req.query.limit
            : 50,
        offset =
          req.query.offset && req.query.offset >= 0 ? req.query.offset : 0;

      // If there is no session present, return an InvalidSession error.
      if (!req.user) res.status(401).json(new Errors.InvalidSession());
      else {
        // Find all files that belong to the user.
        let { count, rows: files } = await File.findAndCountAll({
          limit,
          offset,
          order: [["createdAt", "DESC"]],
          where: {
            userID: req.user.id,
          },
        });

        // Map the files to JSON and send them to the client.
        let items = files.map((file) =>
          FieldExtractor(file.toJSON(), ["id", "name"])
        );
        logger.debug(
          `User ${req.user.username} (${req.user.id}) requested ${files.length} files.`
        );
        res.status(200).send({
          count,
          items,
        });
      }
    } catch (error) {
      throw error;
    }
  }
);

app.get(
  // GET /api/users/me/files/:id
  "/api/users/me/files/:id",
  async (
    req: Request<{ id: string }, null, null, null>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>
  ) => {
    // If there is no session present, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // Find the file that belongs to the user.
    let file = await File.findOne({
      where: {
        id: req.params.id,
        userID: req.user.id,
      },
    });

    if (!file) return res.status(404).send(new Errors.InvalidFile());
    res.status(200).send(file.toJSON());
  }
);

app.delete(
  // DELETE /api/users/me/files/:id
  "/api/users/me/files/:id",
  async (
    req: Request<{ id: string }, null, null, null>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no session present, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    let file = await File.findOne({
      where: {
        id: req.params.id,
        userID: req.user.id,
      },
    });

    if (!file) return res.status(404).send(new Errors.InvalidFile());
    try {
      // Delete the file from disk.
      await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));
      // Check if the file has a thumbnail, and delete it if it does.
      if (existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)))
        await unlink(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`));
      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted file ${file.id}.`
      );
      // Delete the file from the database.
      await file.destroy();
      // Send a success response.
      res.status(200).send(new Success.DeleteFile());
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/users/me/files
  "/api/users/me/files",
  async (
    req: Request<null, null, { ids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no session present, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // Check if the request body contains the files array.
    if (!req.body.ids || req.body.ids.length < 1 || req.body.ids.length > 50)
      return res.status(400).send(new Errors.MissingFields(["ids"]));

    try {
      // Find all files that have been specified that belong to the user.
      let { count, rows: files } = await File.findAndCountAll({
        where: {
          id: {
            [Op.in]: req.body.ids,
          },
          userID: req.user.id,
        },
      });

      // If there are no files found, return an InvalidFile error.
      if (count < 1) return res.status(404).send(new Errors.InvalidFile());

      // Delete all files from disk.
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
      // Send a success response.
      res.status(200).send(new Success.DeleteFiles(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/users/me/files/all
  "/api/users/me/files/all",
  async (
    req: Request<null, null, { password: string }, null>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no session present, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // Check if the request body contains the password field.
    if (!req.body.password)
      return res.status(400).send(new Errors.MissingFields(["password"]));

    // Check if the password is correct.
    const match = await Bcrypt.compare(req.body.password, req.user.password);
    if (!match) return res.status(401).send(new Errors.InvalidPassword());

    try {
      // Find all files that belong to the user.
      let { count, rows: files } = await File.findAndCountAll({
        where: {
          userID: req.user.id,
        },
      });

      // If there are no files found, return an InvalidFile error.
      if (count < 1) return res.status(404).send(new Errors.InvalidFile());

      // Delete all files from disk.
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
      // Send a success response.
      res.status(200).send(new Success.DeleteFiles(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);
