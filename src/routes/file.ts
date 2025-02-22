import { logger, app, ratelimitStore } from '../index.js';
import { Errors, Success } from '../utils/TemplateResponses.js';
import File from '../DB/File.js';
import KVExtractor from '../utils/KVExtractor.js';
import AutoTrim from '../middleware/AutoTrim.js';
import User from '../DB/User.js';
import SessionChecker from '../middleware/SessionChecker.js';
import BodyValidator, {
  ExtendedValidBodyTypes,
} from '../middleware/BodyValidator.js';
import LimitOffset from '../middleware/LimitOffset.js';
import KillSwitch from '../middleware/KillSwitch.js';
import { KillSwitches } from '../utils/GlobalKillSwitches.js';
import SessionPermissionChecker, {
  PermissionFlags,
} from '../middleware/SessionPermissionChecker.js';
import ReverifyIdentity from '../middleware/ReverifyIdentity.js';
import Ratelimit from '../middleware/Ratelimit.js';

import { Op } from 'sequelize';
import { unlink, rename } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { Request, Response } from 'express';
import ms from 'ms';

logger.debug('Loading: File Routes...');

app.get(
  // GET /api/files
  '/api/files',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_READ_FILES),
  LimitOffset(0, 50),
  async (
    req: Request,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.File>
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());

    try {
      let { count, rows: files } = await File.findAndCountAll({
        limit: req.limit,
        offset: req.offset,
        order: [['createdAt', 'DESC']],
      });

      let items = files.map((file) =>
        KVExtractor(file.toJSON(), ['id', 'name']),
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested all user files. (limit: ${req.limit}, offset: ${req.offset})`,
      );

      return res.status(200).json({ count, items });
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/users/me/files
  '/api/users/me/files',
  SessionChecker(),
  SessionPermissionChecker(PermissionFlags.FILE_READ),
  LimitOffset(0, 50),
  async (
    req: Request,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.File>
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());

    try {
      let { count, rows: files } = await File.findAndCountAll({
        where: {
          userID: req.user.id,
        },
        limit: req.limit,
        offset: req.offset,
        order: [['createdAt', 'DESC']],
      });

      let items = files.map((file) =>
        KVExtractor(file.toJSON(), ['id', 'name']),
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested all of their own files. (limit: ${req.limit}, offset: ${req.offset})`,
      );

      return res.status(200).json({ count, items });
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/users/:id/files
  '/api/users/:id/files',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_READ_FILES),
  LimitOffset(0, 50),
  async (
    req: Request<{ id: string }, null, null, null>,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.File>
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());

    try {
      let user = await User.findByPk(req.params.id);

      if (!user) return res.status(404).json(new Errors.InvalidUser());

      let { count, rows: files } = await File.findAndCountAll({
        where: {
          userID: user.id,
        },
        limit: req.limit,
        offset: req.offset,
        order: [['createdAt', 'DESC']],
      });

      let items = files.map((file) =>
        KVExtractor(file.toJSON(), ['id', 'name']),
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested all files belonging to user ${user.username} (${user.id}). (limit: ${req.limit}, offset: ${req.offset})`,
      );

      return res.status(200).json({ count, items });
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/users/me/files/:id
  '/api/users/me/files/:id',
  SessionChecker(),
  SessionPermissionChecker(PermissionFlags.FILE_READ),
  async (
    req: Request<{ id: string }, null, null, null>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>,
  ) => {
    if (!req.user || !req.session)
      return res.status(401).json(new Errors.InvalidSession());
    try {
      // Find the file.
      let file = await File.findOne({
        where: {
          id: req.params.id,
          userID: req.user.id,
        },
      });

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested file ${file.id}.`,
      );

      // Return the file.
      return res.status(200).json(file.toJSON());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/users/:uid/files/:id
  '/api/users/:uid/files/:id',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_READ_FILES),
  async (
    req: Request<{ uid: string; id: string }, null, null, null>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    try {
      // Find the file.
      let file = await File.findOne({
        where: {
          id: req.params.id,
          userID: req.params.uid,
        },
      });

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested file ${file.id}.`,
      );

      // Return the file.
      return res.status(200).json(file.toJSON());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/files/:id
  '/api/files/:id',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_READ_FILES),
  async (
    req: Request<{ id: string }, null, null, null>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>,
  ) => {
    if (!req.user || !req.session)
      return res.status(401).json(new Errors.InvalidSession());
    try {
      // Find the file.
      let file = await File.findByPk(req.params.id);

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested file ${file.id}.`,
      );

      // Return the file.
      return res.status(200).json(file.toJSON());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/me/files/:id/name
  '/api/users/me/files/:id/name',
  SessionChecker(),
  SessionPermissionChecker(PermissionFlags.FILE_MODIFY),
  AutoTrim(),
  BodyValidator({
    name: 'string',
  }),
  KillSwitch(KillSwitches.FILE_MODIFY),
  Ratelimit({
    max: 5,
    window: ms('6h'),
    ignoreStatusCodes: [500],
    storage: ratelimitStore,
  }),
  async (
    req: Request<{ id: string }, null, { name: string }>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      if (!req.user || !req.session)
        return res.status(401).json(new Errors.InvalidSession());
      // Find the file
      let file = await File.findOne({
        where: {
          id: req.params.id,
          userID: req.user.id,
        },
      });

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) updated the name of file ${file.id}.`,
      );

      // Update the file's name.
      await file.update({ name: req.body.name });

      // Return the file.
      return res.status(200).json(file.toJSON());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/:uid/files/:id/name
  '/api/users/:uid/files/:id/name',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_FILES),
  AutoTrim(),
  BodyValidator({
    name: 'string',
  }),
  async (
    req: Request<{ uid: string; id: string }, null, { name: string }>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      if (!req.user) return res.status(401).json(new Errors.InvalidSession());
      // Find the file
      let file = await File.findOne({
        where: {
          id: req.params.id,
          userID: req.params.uid,
        },
      });

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) updated the name of file ${file.id}.`,
      );

      // Update the file's name.
      await file.update({ name: req.body.name });

      // Return the file.
      return res.status(200).json(file.toJSON());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/me/files/:id/name
  '/api/users/me/files/:id/name',
  SessionChecker(),
  SessionPermissionChecker(PermissionFlags.FILE_MODIFY),
  KillSwitch(KillSwitches.FILE_MODIFY),
  Ratelimit({
    max: 5,
    window: ms('6h'),
    ignoreStatusCodes: [500],
    storage: ratelimitStore,
  }),
  async (
    req: Request<{ id: string }, null, null, null>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>,
  ) => {
    if (!req.user || !req.session)
      return res.status(401).json(new Errors.InvalidSession());
    try {
      // Find the file.
      let file = await File.findOne({
        where: {
          id: req.params.id,
          userID: req.user.id,
        },
      });

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted the name of file ${file.id}.`,
      );

      // Update the file's name.
      await file.update({ name: null });

      // Return the file.
      return res.status(200).json(file.toJSON());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/:uid/files/:id/name
  '/api/users/:uid/files/:id/name',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_FILES),
  async (
    req: Request<{ uid: string; id: string }, null, null, null>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    try {
      // Find the file.
      let file = await File.findOne({
        where: {
          id: req.params.id,
          userID: req.params.uid,
        },
      });

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted the name of file ${file.id}.`,
      );

      // Update the file's name.
      await file.update({ name: null });

      // Return the file.
      return res.status(200).json(file.toJSON());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/me/files/:id/extension
  '/api/users/me/files/:id/extension',
  SessionChecker(),
  AutoTrim(),
  BodyValidator({
    extension: 'string',
  }),
  SessionPermissionChecker(PermissionFlags.FILE_MODIFY),
  KillSwitch(KillSwitches.FILE_MODIFY),
  Ratelimit({
    max: 2,
    window: ms('12h'),
    ignoreStatusCodes: [500],
    storage: ratelimitStore,
  }),
  async (
    req: Request<{ id: string }, null, { extension: string }>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>,
  ) => {
    if (!req.user || !req.session)
      return res.status(401).json(new Errors.InvalidSession());
    // If the extension the user provided has a leading dot, remove it.
    if (req.body.extension.startsWith('.'))
      req.body.extension = req.body.extension.slice(1);

    // If the extension the user provided has a trailing dot, remove it.
    if (req.body.extension.endsWith('.'))
      req.body.extension = req.body.extension.slice(0, -1);

    // Sanitize the extension. (Make sure we don't do a directory traversal attack.)
    req.body.extension = req.body.extension.replace(/\//g, '');

    try {
      // Find the file.
      let file = await File.findOne({
        where: {
          id: req.params.id,
          userID: req.user.id,
        },
      });

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      // Check if the file has a thumbnail, and delete it if it does.
      if (existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)))
        await unlink(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`));

      // Update the file's extension.
      await rename(
        join(process.env.BASE_UPLOAD_PATH, file.id),
        join(
          process.env.BASE_UPLOAD_PATH,
          `${file.id.split('.')[0]}.${req.body.extension}`,
        ),
      );

      logger.warn(
        `User ${req.user.username} (${req.user.id}) updated file ${
          file.id
        }'s extension to ${file.id.split('.')[0]}.${
          req.body.extension
        }, you might need to look into how the server assumes the file's extension.`,
      );

      // Since the file's id is the primary key, we need to create a new instance of the file with the new extension and delete the old one.
      let newFile = await File.create({
        id: `${file.id.split('.')[0]}.${req.body.extension}`,
        name: file.name,
        userID: file.userID,
        size: file.size,
        createdAt: file.createdAt,
        updatedAt: new Date(),
      });

      await file.destroy();

      return res.status(200).json(newFile.toJSON());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/users/:uid/files/:id/extension
  '/api/users/:uid/files/:id/extension',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_FILES),
  AutoTrim(),
  BodyValidator({
    extension: 'string',
  }),
  async (
    req: Request<{ uid: string; id: string }, null, { extension: string }>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // If the extension the user provided has a leading dot, remove it.
    if (req.body.extension.startsWith('.'))
      req.body.extension = req.body.extension.slice(1);

    // If the extension the user provided has a trailing dot, remove it.
    if (req.body.extension.endsWith('.'))
      req.body.extension = req.body.extension.slice(0, -1);

    try {
      // Find the file.
      let file = await File.findOne({
        where: {
          id: req.params.id,
          userID: req.params.uid,
        },
      });

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      // Check if the file has a thumbnail, and delete it if it does.
      if (existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)))
        await unlink(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`));

      // Update the file's extension.
      await rename(
        join(process.env.BASE_UPLOAD_PATH, file.id),
        join(
          process.env.BASE_UPLOAD_PATH,
          `${file.id.split('.')[0]}.${req.body.extension}`,
        ),
      );

      logger.warn(
        `User ${req.user.username} (${req.user.id}) updated file ${
          file.id
        }'s extension to ${file.id.split('.')[0]}.${
          req.body.extension
        }, you might need to look into how the server assumes the file's extension.`,
      );

      // Since the file's id is the primary key, we need to create a new instance of the file with the new extension and delete the old one.
      let newFile = await File.create({
        id: `${file.id.split('.')[0]}.${req.body.extension}`,
        name: file.name,
        userID: file.userID,
        size: file.size,
        createdAt: file.createdAt,
        updatedAt: new Date(),
      });

      await file.destroy();

      return res.status(200).json(newFile.toJSON());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/me/files/all
  '/api/users/me/files/all',
  ReverifyIdentity(),
  SessionPermissionChecker(),
  KillSwitch(KillSwitches.FILE_DELETE),
  Ratelimit({
    max: 1,
    window: ms('3d'),
    ignoreStatusCodes: [500],
    storage: ratelimitStore,
  }),
  async (
    req: Request,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());

    try {
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
            existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`))
          )
            await unlink(
              join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`),
            );

          // Delete the file from the disk.
          await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

          // Delete the file from the database.
          await file.destroy();
        }),
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted all of their own files. Count: ${count}`,
      );

      return res.status(200).json(new Success.DeleteFiles(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/:uid/files/all
  '/api/users/:uid/files/all',
  ReverifyIdentity(true),
  SessionPermissionChecker(),
  async (
    req: Request<{ uid: string }, null, null, null>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());

    try {
      let user = await User.findByPk(req.params.uid);

      if (!user) return res.status(404).json(new Errors.InvalidUser());

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
              join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`),
            );

          // Delete the file from the disk.
          await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

          // Delete the file from the database.
          await file.destroy();
        }),
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted all files belonging to user ${user.username} (${user.id}). Count: ${count}`,
      );

      return res.status(200).json(new Success.DeleteFiles(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/me/files/:id
  '/api/users/me/files/:id',
  SessionChecker(),
  SessionPermissionChecker(PermissionFlags.FILE_MODIFY),
  KillSwitch(KillSwitches.FILE_DELETE),
  async (
    req: Request<{ id: string }, null, null, null>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user || !req.session)
      return res.status(401).json(new Errors.InvalidSession());
    try {
      // Find the file.
      let file = await File.findOne({
        where: {
          id: req.params.id,
          userID: req.user.id,
        },
      });

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      // First, delete the thumbnail if it exists.
      if (existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)))
        await unlink(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`));

      // Delete the file from the disk.
      await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

      // Delete the file from the database.
      await file.destroy();

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted file ${file.id}.`,
      );

      return res.status(200).json(new Success.DeleteFile());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/:uid/files/:id
  '/api/users/:uid/files/:id',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_FILES),
  async (
    req: Request<{ uid: string; id: string }, null, null, null>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    try {
      // Find the file.
      let file = await File.findOne({
        where: {
          id: req.params.id,
          userID: req.params.uid,
        },
      });

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      // First, delete the thumbnail if it exists.
      if (existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`)))
        await unlink(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`));

      // Delete the file from the disk.
      await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

      // Delete the file from the database.
      await file.destroy();

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted (${req.params.uid})'s file ${file.id}.`,
      );

      return res.status(200).json(new Success.DeleteFile());
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/me/files
  '/api/users/me/files',
  SessionChecker(),
  SessionPermissionChecker(PermissionFlags.FILE_MODIFY),
  KillSwitch(KillSwitches.FILE_DELETE),
  BodyValidator({
    ids: new ExtendedValidBodyTypes().array('string'),
  }),
  Ratelimit({
    max: 20,
    window: ms('6h'),
    ignoreStatusCodes: [400, 404, 500],
    storage: ratelimitStore,
  }),
  async (
    req: Request<null, null, { ids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user || !req.session)
      return res.status(401).json(new Errors.InvalidSession());
    // Check if the user is trying to delete more than 50 files.
    if (req.body.ids.length > 50)
      return res.status(400).json(new Errors.BodyTooLarge());

    try {
      // Find all files specified in the request body.
      let { count, rows: files } = await File.findAndCountAll({
        where: {
          id: {
            [Op.in]: req.body.ids,
          },
          userID: req.user.id,
        },
      });

      // If the count is 0, return an InvalidFile error.
      if (count === 0) return res.status(404).json(new Errors.InvalidFile());

      // Delete all files.
      await Promise.all(
        files.map(async (file) => {
          // First, delete the thumbnail if it exists.
          if (
            existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`))
          )
            await unlink(
              join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`),
            );

          // Delete the file from the disk.
          await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

          // Delete the file from the database.
          await file.destroy();
        }),
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted ${count} files.`,
      );

      return res.status(200).json(new Success.DeleteFiles(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/users/:uid/files
  '/api/users/:uid/files',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_FILES),
  BodyValidator({
    ids: new ExtendedValidBodyTypes().array('string'),
  }),
  async (
    req: Request<{ uid: string }, null, { ids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Check if the user is trying to delete more than 50 files.
    if (req.body.ids.length > 50)
      return res.status(400).json(new Errors.BodyTooLarge());

    try {
      // Find all files specified in the request body.
      let { count, rows: files } = await File.findAndCountAll({
        where: {
          id: {
            [Op.in]: req.body.ids,
          },
          userID: req.params.uid,
        },
      });

      // If the count is 0, return an InvalidFile error.
      if (count === 0) return res.status(404).json(new Errors.InvalidFile());

      // Delete all files.
      await Promise.all(
        files.map(async (file) => {
          // First, delete the thumbnail if it exists.
          if (
            existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`))
          )
            await unlink(
              join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`),
            );

          // Delete the file from the disk.
          await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

          // Delete the file from the database.
          await file.destroy();
        }),
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted ${count} files belonging to user ${req.params.uid}.`,
      );

      return res.status(200).json(new Success.DeleteFiles(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/files
  '/api/files',
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_FILES),
  BodyValidator({
    ids: new ExtendedValidBodyTypes().array('string'),
  }),
  async (
    req: Request<null, null, { ids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Check if the user is trying to delete more than 50 files.
    if (req.body.ids.length > 50)
      return res.status(400).json(new Errors.BodyTooLarge());

    try {
      // Find all files specified in the request body.
      let { count, rows: files } = await File.findAndCountAll({
        where: {
          id: {
            [Op.in]: req.body.ids,
          },
        },
      });

      // If the count is 0, return an InvalidFile error.
      if (count === 0) return res.status(404).json(new Errors.InvalidFile());

      // Delete all files.
      await Promise.all(
        files.map(async (file) => {
          // First, delete the thumbnail if it exists.
          if (
            existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`))
          )
            await unlink(
              join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`),
            );

          // Delete the file from the disk.
          await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

          // Delete the file from the database.
          await file.destroy();
        }),
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted ${count} files.`,
      );

      return res.status(200).json(new Success.DeleteFiles(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);
