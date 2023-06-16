import { logger, app } from "../../index.js";
import { Errors, Success } from "../../utils/TemplateResponses.js";
import File from "../../DB/File.js";

import { Op } from "sequelize";
import { unlink } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import Bcrypt from "bcrypt";
import { Request, Response } from "express";

logger.debug("Loading unprivileged/file.ts...");

app.get(
  // GET /api/user/files
  "/api/user/files",
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
        let uls = await File.findAndCountAll({
          limit,
          offset,
          order: [["createdAt", "DESC"]],
          where: {
            userID: req.user.id,
          },
        });

        // Map the files to JSON and send them to the client.
        let files = uls.rows.map((u) =>
          u.toJSON()
        ) as Cumulonimbus.Structures.File[];
        logger.debug(
          `User ${req.user.username} (${req.user.id}) requested ${files.length} files.`
        );
        res.status(200).send({
          count: uls.count,
          items: files,
        });
      }
    } catch (error) {
      throw error;
    }
  }
);

app.get(
  // GET /api/user/file/:id
  "/api/user/file/:id",
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
  // DELETE /api/user/file/:id
  "/api/user/file/:id",
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
      await unlink(join(process.env.BASE_UPLOAD_PATH, file.filename));
      // Check if the file has a thumbnail, and delete it if it does.
      if (
        existsSync(
          join(process.env.BASE_THUMBNAIL_PATH, `${file.filename}.webp`)
        )
      )
        await unlink(
          join(process.env.BASE_THUMBNAIL_PATH, `${file.filename}.webp`)
        );
      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted file ${file.filename}.)`
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
  // DELETE /api/user/files
  "/api/user/files",

  async (
    req: Request<null, null, { files: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no session present, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // Check if the request body contains the files array.
    if (
      !req.body.files ||
      req.body.files.length < 1 ||
      req.body.files.length > 50
    )
      return res.status(400).send(new Errors.MissingFields(["files"]));

    // Find all files that belong to the user.
    let files = await File.findAndCountAll({
      where: {
        id: {
          [Op.in]: req.body.files,
        },
        userID: req.user.id,
      },
    });

    // If there are no files found, return an InvalidFile error.
    if (files.count < 1) return res.status(404).send(new Errors.InvalidFile());

    try {
      // Delete all files from disk.
      await Promise.all(
        files.rows.map(async (file) => {
          await unlink(join(process.env.BASE_UPLOAD_PATH, file.filename));
          if (
            existsSync(
              join(process.env.BASE_THUMBNAIL_PATH, `${file.filename}.webp`)
            )
          )
            await unlink(
              join(process.env.BASE_THUMBNAIL_PATH, `${file.filename}.webp`)
            );
        })
      );
      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted ${files.count} files.)`
      );
      // Delete all files from the database.
      await File.destroy({
        where: {
          id: {
            [Op.in]: req.body.files,
          },
          userID: req.user.id,
        },
      });
      // Send a success response.
      res.status(200).send(new Success.DeleteFiles(files.count));
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/user/files/all
  "/api/user/files/all",
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
      let files = await File.findAndCountAll({
        where: {
          userID: req.user.id,
        },
      });

      // If there are no files found, return an InvalidFile error.
      if (files.count < 1)
        return res.status(404).send(new Errors.InvalidFile());

      // Delete all files from disk.
      await Promise.all(
        files.rows.map(async (file) => {
          await unlink(join(process.env.BASE_UPLOAD_PATH, file.filename));
          if (
            existsSync(
              join(process.env.BASE_THUMBNAIL_PATH, `${file.filename}.webp`)
            )
          )
            await unlink(
              join(process.env.BASE_THUMBNAIL_PATH, `${file.filename}.webp`)
            );
        })
      );
      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted ${files.count} files.)`
      );

      // Delete all files from the database.
      await File.destroy({
        where: {
          userID: req.user.id,
        },
      });
      // Send a success response.
      res.status(200).send(new Success.DeleteFiles(files.count));
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);
