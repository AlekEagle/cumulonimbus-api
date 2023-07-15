import { logger, app } from "../index.js";
import { Errors, Success } from "../utils/TemplateResponses.js";
import File from "../DB/File.js";
import FieldExtractor from "../utils/FieldExtractor.js";
import AutoTrim from "../middleware/AutoTrim.js";
import { getInvalidFields, FieldTypeOptions } from "../utils/FieldValidator.js";
import User from "../DB/User.js";

import { Op } from "sequelize";
import { unlink, rename } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import Bcrypt from "bcrypt";
import { Request, Response } from "express";

logger.debug("Loading: File Routes...");

app.get(
  // GET /api/files
  "/api/files",
  async (
    req: Request<
      null,
      null,
      null,
      { limit: number; offset: number; uid: number | string }
    >,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.File>
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

      // If the user did not provide a user, check if they are staff.
      if (!req.query.uid) {
        if (!req.user.staff)
          return res.status(403).send(new Errors.InsufficientPermissions());
        let { count, rows: files } = await File.findAndCountAll({
          limit,
          offset,
          order: [["createdAt", "DESC"]],
        });
        let items = files.map((file) =>
          FieldExtractor(file.toJSON(), ["id", "name"])
        );

        logger.debug(
          `User ${req.user.username} (${req.user.id}) requested all user files. (limit: ${limit}, offset: ${offset})`
        );

        return res.status(200).send({ count, items });
      }

      // If the user provided a user that isn't their own id or "me", check if they are staff.
      if (req.query.uid !== "me" && req.query.uid !== req.user.id) {
        if (!req.user.staff)
          return res.status(403).send(new Errors.InsufficientPermissions());

        // Check if the user exists.
        let user = await User.findByPk(req.query.uid + "");

        // If the user does not exist, return an InvalidUser error.
        if (!user) return res.status(404).send(new Errors.InvalidUser());

        // Get the user's files.
        let { count, rows: files } = await File.findAndCountAll({
          limit,
          offset,
          order: [["createdAt", "DESC"]],
          where: {
            userID: req.query.uid + "",
          },
        });
        let items = files.map((file) =>
          FieldExtractor(file.toJSON(), ["id", "name"])
        );

        logger.debug(
          `User ${req.user.username} (${req.user.id}) requested files for user ${req.query.uid}. (limit: ${limit}, offset: ${offset})`
        );

        return res.status(200).send({ count, items });
      }

      // If the user provided their own id or "me", return their files.
      let { count, rows: files } = await File.findAndCountAll({
        limit,
        offset,
        order: [["createdAt", "DESC"]],
        where: {
          userID: req.user.id,
        },
      });
      let items = files.map((file) =>
        FieldExtractor(file.toJSON(), ["id", "name"])
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested their files. (limit: ${limit}, offset: ${offset})`
      );

      return res.status(200).send({ count, items });
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.get(
  // GET /api/files/:id
  "/api/files/:id",
  async (
    req: Request<{ id: string }, null, null, null>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>
  ) => {
    // If there is no session present, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    try {
      // Find the file.
      let file = await File.findByPk(req.params.id);

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).send(new Errors.InvalidFile());

      // If the file does not belong to the user, check if they are staff.
      if (file.userID !== req.user.id) {
        // If they are not staff, return an InvalidFile error. (This is to prevent scraping of files by checking if the response is a 404 or 403.)
        if (!req.user.staff)
          return res.status(404).send(new Errors.InvalidFile());
      }

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested file ${file.id}.`
      );

      // Return the file.
      return res.status(200).send(file.toJSON());
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.put(
  // PUT /api/files/:id/name
  "/api/files/:id/name",
  AutoTrim(),
  async (
    req: Request<{ id: string }, null, { name: string }>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>
  ) => {
    // If there is no session present, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // Check if they provided a name and if its a string.
    const invalidFields = getInvalidFields(req.body, {
      name: new FieldTypeOptions("string", true),
    });

    // If there are invalid fields, return an InvalidFields error.
    if (invalidFields.length > 0)
      return res.status(400).send(new Errors.MissingFields(invalidFields));

    try {
      // Find the file
      let file = await File.findByPk(req.params.id);

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).send(new Errors.InvalidFile());

      // If the file does not belong to the user, check if they are staff.
      if (file.userID !== req.user.id) {
        // If they are not staff, return an InvalidFile error. (This is to prevent scraping of files by checking if the response is a 404 or 403.)
        if (!req.user.staff)
          return res.status(404).send(new Errors.InvalidFile());
      }

      logger.debug(
        `User ${req.user.username} (${req.user.id}) updated the name of file ${file.id}.`
      );

      // Update the file's name.
      await file.update({ name: req.body.name === "" ? null : req.body.name });

      // Return the file.
      return res.status(200).send(file.toJSON());
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.put(
  // PUT /api/files/:id/extension
  "/api/files/:id/extension",
  AutoTrim(),
  async (
    req: Request<{ id: string }, null, { extension: string }>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>
  ) => {
    // If there is no session present, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // Check if they provided an extension and if its a string.
    const invalidFields = getInvalidFields(req.body, {
      extension: "string",
    });

    // If there are invalid fields, return an InvalidFields error.
    if (invalidFields.length > 0)
      return res.status(400).send(new Errors.MissingFields(invalidFields));

    // If the extension the user provided has a leading dot, remove it.
    if (req.body.extension.startsWith("."))
      req.body.extension = req.body.extension.slice(1);

    // If the extension the user provided has a trailing dot, remove it.
    if (req.body.extension.endsWith("."))
      req.body.extension = req.body.extension.slice(0, -1);

    try {
      // Find the file.
      let file = await File.findByPk(req.params.id);

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).send(new Errors.InvalidFile());

      // If the file does not belong to the user, check if they are staff.
      if (file.userID !== req.user.id) {
        // If they are not staff, return an InvalidFile error. (This is to prevent scraping of files by checking if the response is a 404 or 403.)
        if (!req.user.staff)
          return res.status(404).send(new Errors.InvalidFile());
      }

      // Check if the file has a thumbnail, and delete it if it does.
      if (existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)))
        await unlink(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`));

      // Update the file's extension.
      await rename(
        join(process.env.BASE_UPLOAD_PATH, file.id),
        join(
          process.env.BASE_UPLOAD_PATH,
          `${file.id.split(".")[0]}.${req.body.extension}`
        )
      );

      logger.warn(
        `User ${req.user.username} (${req.user.id}) updated file ${
          file.id
        }'s extension to ${file.id.split(".")[0]}.${
          req.body.extension
        }, you might need to look into how the server assumes the file's extension.`
      );

      // Since the file's id is the primary key, we need to create a new instance of the file with the new extension and delete the old one.
      let newFile = await File.create({
        id: `${file.id.split(".")[0]}.${req.body.extension}`,
        name: file.name,
        userID: file.userID,
        size: file.size,
        createdAt: file.createdAt,
        updatedAt: new Date(),
      });

      await file.destroy();

      return res.status(200).send(newFile.toJSON());
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);

app.delete(
  // DELETE /api/files/:id
  "/api/files/:id",
  async (
    req: Request<{ id: string }, null, null, null>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no session present, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    try {
      // Find the file.
      let file = await File.findByPk(req.params.id);

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).send(new Errors.InvalidFile());

      // If the file does not belong to the user, check if they are staff.
      if (file.userID !== req.user.id) {
        // If they are not staff, return an InvalidFile error. (This is to prevent scraping of files by checking if the response is a 404 or 403.)
        if (!req.user.staff)
          return res.status(404).send(new Errors.InvalidFile());
      }

      // First, delete the thumbnail if it exists.
      if (existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)))
        await unlink(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`));

      // Delete the file from the disk.
      await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

      // Delete the file from the database.
      await file.destroy();

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted file ${file.id}.`
      );

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
      // Find all files specified in the request body.
      let { count, rows: files } = await File.findAndCountAll({
        where: {
          id: {
            [Op.in]: req.body.ids,
          },
        },
      });

      // If the user is not staff, remove any files that do not belong to them and change the count accordingly.
      if (!req.user.staff) {
        files = files.filter((file) => file.userID === req.user.id);
        count = files.length;
      }

      // If the count is 0, return an InvalidFile error.
      if (count === 0) return res.status(404).send(new Errors.InvalidFile());

      // Delete all files.
      await Promise.all(
        files.map(async (file) => {
          // First, delete the thumbnail if it exists.
          if (
            existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`))
          )
            await unlink(
              join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)
            );

          // Delete the file from the disk.
          await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

          // Delete the file from the database.
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
  // DELETE /api/files/all
  "/api/files/all",
  async (
    req: Request<null, null, { password: string }, { user: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >
  ) => {
    // If there is no session present, return an InvalidSession error.
    if (!req.user) return res.status(401).send(new Errors.InvalidSession());

    // If the query does not contain the user parameter, return a MissingFields error.
    if (!req.query.user)
      return res.status(400).send(new Errors.MissingFields(["user"]));

    // Check if the user is trying delete their own files.
    if (req.query.user === req.user.id || req.query.user === "me") {
      // Check if the request body contains the password field.
      if (!req.body.password)
        return res.status(400).send(new Errors.MissingFields(["password"]));
      try {
        // Check if the password is correct.
        if (!(await Bcrypt.compare(req.body.password, req.user.password)))
          return res.status(401).send(new Errors.InvalidPassword());

        // Fetch all files belonging to the user.
        let { count, rows: files } = await File.findAndCountAll({
          where: {
            userID: req.user.id,
          },
        });

        // Delete all files.
        await Promise.all(
          files.map(async (file) => {
            // First, delete the thumbnail if it exists.
            if (
              existsSync(
                join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)
              )
            )
              await unlink(
                join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)
              );

            // Delete the file from the disk.
            await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

            // Delete the file from the database.
            await file.destroy();
          })
        );

        logger.debug(
          `User ${req.user.username} (${req.user.id}) deleted all of their files.`
        );

        return res.status(200).send(new Success.DeleteFiles(count));
      } catch (error) {
        logger.error(error);
        return res.status(500).send(new Errors.Internal());
      }
    }

    // If the user is not staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).send(new Errors.InsufficientPermissions());

    try {
      // Check if the user exists.
      let user = await User.findByPk(req.query.user);

      // If the user does not exist, return an InvalidUser error.
      if (!user) return res.status(404).send(new Errors.InvalidUser());

      // Fetch all files belonging to the user.
      let { count, rows: files } = await File.findAndCountAll({
        where: {
          userID: user.id,
        },
      });

      // Delete all files.
      await Promise.all(
        files.map(async (file) => {
          // First, delete the thumbnail if it exists.
          if (
            existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`))
          )
            await unlink(
              join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)
            );

          // Delete the file from the disk.
          await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

          // Delete the file from the database.
          await file.destroy();
        })
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted ${count} files belonging to user ${user.username} (${user.id}).`
      );

      return res.status(200).send(new Success.DeleteFiles(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).send(new Errors.Internal());
    }
  }
);
