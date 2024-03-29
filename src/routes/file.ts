import { logger, app } from '../index.js';
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
import { PermissionFlags } from '../middleware/SessionPermissionChecker.js';

import { Op } from 'sequelize';
import { unlink, rename } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import Bcrypt from 'bcrypt';
import { Request, Response } from 'express';

logger.debug('Loading: File Routes...');

app.get(
  // GET /api/files
  '/api/files',
  SessionChecker(),
  LimitOffset(0, 50),
  async (
    req: Request<null, null, null, { uid: string }>,
    res: Response<
      | Cumulonimbus.Structures.List<Cumulonimbus.Structures.File>
      | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      // If the user did not provide a user, check if they are staff.
      if (!req.query.uid) {
        if (
          !req.user.staff ||
          (req.session.permissionFlags !== null &&
            !(req.session.permissionFlags & PermissionFlags.STAFF_READ_FILES))
        )
          return res.status(403).json(new Errors.InsufficientPermissions());
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
      }

      // If the user provided a user that isn't their own id or "me", check if they are staff.
      if (req.query.uid !== 'me') {
        if (
          !req.user.staff ||
          (req.session.permissionFlags !== null &&
            !(req.session.permissionFlags & PermissionFlags.STAFF_READ_FILES))
        )
          return res.status(403).json(new Errors.InsufficientPermissions());

        // Check if the user exists.
        let user = await User.findByPk(req.query.uid + '');

        // If the user does not exist, return an InvalidUser error.
        if (!user) return res.status(404).json(new Errors.InvalidUser());

        // Get the user's files.
        let { count, rows: files } = await File.findAndCountAll({
          limit: req.limit,
          offset: req.offset,
          order: [['createdAt', 'DESC']],
          where: {
            userID: req.query.uid + '',
          },
        });
        let items = files.map((file) =>
          KVExtractor(file.toJSON(), ['id', 'name']),
        );

        logger.debug(
          `User ${req.user.username} (${req.user.id}) requested files for user ${req.query.uid}. (limit: ${req.limit}, offset: ${req.offset})`,
        );

        return res.status(200).json({ count, items });
      }

      // If the user provided their own id or "me", return their files.
      let { count, rows: files } = await File.findAndCountAll({
        limit: req.limit,
        offset: req.offset,
        order: [['createdAt', 'DESC']],
        where: {
          userID: req.user.id,
        },
      });
      let items = files.map((file) =>
        KVExtractor(file.toJSON(), ['id', 'name']),
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) requested their files. (limit: ${req.limit}, offset: ${req.offset})`,
      );

      return res.status(200).json({ count, items });
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.get(
  // GET /api/files/:id
  '/api/files/:id',
  SessionChecker(),
  async (
    req: Request<{ id: string }, null, null, null>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Find the file.
      let file = await File.findByPk(req.params.id);

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      // If the file does not belong to the user, check if they are staff.
      if (file.userID !== req.user.id) {
        // If they are not staff, return an InvalidFile error. (This is to prevent scraping of files by checking if the response is a 404 or 403.)
        if (!req.user.staff)
          return res.status(404).json(new Errors.InvalidFile());
        else if (
          req.session.permissionFlags !== null &&
          !(req.session.permissionFlags & PermissionFlags.STAFF_READ_FILES)
        )
          return res.status(403).json(new Errors.InsufficientPermissions());
      } else if (
        req.session.permissionFlags !== null &&
        !(req.session.permissionFlags & PermissionFlags.FILE_READ)
      ) {
        return res.status(403).json(new Errors.InsufficientPermissions());
      }

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
  // PUT /api/files/:id/name
  '/api/files/:id/name',
  SessionChecker(),
  AutoTrim(),
  BodyValidator({
    name: 'string',
  }),
  KillSwitch(KillSwitches.FILE_MODIFY),
  async (
    req: Request<{ id: string }, null, { name: string }>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Find the file
      let file = await File.findByPk(req.params.id);

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      // If the file does not belong to the user, check if they are staff.
      if (file.userID !== req.user.id) {
        // If they are not staff, return an InvalidFile error. (This is to prevent scraping of files by checking if the response is a 404 or 403.)
        if (!req.user.staff)
          return res.status(404).json(new Errors.InvalidFile());
        else if (
          req.session.permissionFlags !== null &&
          !(req.session.permissionFlags & PermissionFlags.STAFF_READ_FILES)
        )
          return res.status(403).json(new Errors.InsufficientPermissions());
      } else if (
        req.session.permissionFlags !== null &&
        !(req.session.permissionFlags & PermissionFlags.FILE_READ)
      ) {
        return res.status(403).json(new Errors.InsufficientPermissions());
      }

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
  // DELETE /api/files/:id/name
  '/api/files/:id/name',
  SessionChecker(),
  KillSwitch(KillSwitches.FILE_MODIFY),
  async (
    req: Request<{ id: string }, null, null, null>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>,
  ) => {
    try {
      // Find the file.
      let file = await File.findByPk(req.params.id);

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      // If the file does not belong to the user, check if they are staff.
      if (file.userID !== req.user.id) {
        // If they are not staff, return an InvalidFile error. (This is to prevent scraping of files by checking if the response is a 404 or 403.)
        if (!req.user.staff)
          return res.status(404).json(new Errors.InvalidFile());
        else if (
          req.session.permissionFlags !== null &&
          !(req.session.permissionFlags & PermissionFlags.STAFF_READ_FILES)
        )
          return res.status(403).json(new Errors.InsufficientPermissions());
      } else if (
        req.session.permissionFlags !== null &&
        !(req.session.permissionFlags & PermissionFlags.FILE_READ)
      ) {
        return res.status(403).json(new Errors.InsufficientPermissions());
      }

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
  // PUT /api/files/:id/extension
  '/api/files/:id/extension',
  SessionChecker(),
  AutoTrim(),
  BodyValidator({
    extension: 'string',
  }),
  KillSwitch(KillSwitches.FILE_MODIFY),
  async (
    req: Request<{ id: string }, null, { extension: string }>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>,
  ) => {
    // If the extension the user provided has a leading dot, remove it.
    if (req.body.extension.startsWith('.'))
      req.body.extension = req.body.extension.slice(1);

    // If the extension the user provided has a trailing dot, remove it.
    if (req.body.extension.endsWith('.'))
      req.body.extension = req.body.extension.slice(0, -1);

    try {
      // Find the file.
      let file = await File.findByPk(req.params.id);

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      // If the file does not belong to the user, check if they are staff.
      if (file.userID !== req.user.id) {
        // If they are not staff, return an InvalidFile error. (This is to prevent scraping of files by checking if the response is a 404 or 403.)
        if (!req.user.staff)
          return res.status(404).json(new Errors.InvalidFile());
        else if (
          req.session.permissionFlags !== null &&
          !(req.session.permissionFlags & PermissionFlags.STAFF_READ_FILES)
        )
          return res.status(403).json(new Errors.InsufficientPermissions());
      } else if (
        req.session.permissionFlags !== null &&
        !(req.session.permissionFlags & PermissionFlags.FILE_READ)
      ) {
        return res.status(403).json(new Errors.InsufficientPermissions());
      }

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
  // DELETE /api/files/all
  '/api/files/all',
  SessionChecker(),
  BodyValidator({
    password: new ExtendedValidBodyTypes('string', true),
  }),
  KillSwitch(KillSwitches.FILE_DELETE),
  async (
    req: Request<null, null, { password: string }, { user: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    // If the query does not contain the user parameter, return a MissingFields error.
    if (!req.query.user)
      return res.status(400).json(new Errors.MissingFields(['user']));

    // Check if the user is trying delete their own files.
    if (req.query.user === 'me') {
      // Check if the request body contains the password field. (Only for non-scoped sessions.)
      if (!req.body.password && req.session.permissionFlags === null)
        return res.status(400).json(new Errors.MissingFields(['password']));
      try {
        // Check if the password is correct. (Only for non-scoped sessions.)
        if (
          req.session.permissionFlags === null &&
          !(await Bcrypt.compare(req.body.password, req.user.password))
        )
          return res.status(401).json(new Errors.InvalidPassword());

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
                join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`),
              )
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
          `User ${req.user.username} (${req.user.id}) deleted all of their files.`,
        );

        return res.status(200).json(new Success.DeleteFiles(count));
      } catch (error) {
        logger.error(error);
        return res.status(500).json(new Errors.Internal());
      }
    }

    // If the user is not staff, return an InsufficientPermissions error.
    if (!req.user.staff)
      return res.status(403).json(new Errors.InsufficientPermissions());
    else if (
      req.session.permissionFlags !== null &&
      !(req.session.permissionFlags & PermissionFlags.STAFF_MODIFY_FILES)
    )
      return res.status(403).json(new Errors.InsufficientPermissions());

    try {
      // Check if the user exists.
      let user = await User.findByPk(req.query.user);

      // If the user does not exist, return an InvalidUser error.
      if (!user) return res.status(404).json(new Errors.InvalidUser());

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
              join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`),
            );

          // Delete the file from the disk.
          await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));

          // Delete the file from the database.
          await file.destroy();
        }),
      );

      logger.debug(
        `User ${req.user.username} (${req.user.id}) deleted ${count} files belonging to user ${user.username} (${user.id}).`,
      );

      return res.status(200).json(new Success.DeleteFiles(count));
    } catch (error) {
      logger.error(error);
      return res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/files/:id
  '/api/files/:id',
  SessionChecker(),
  KillSwitch(KillSwitches.FILE_DELETE),
  async (
    req: Request<{ id: string }, null, null, null>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      // Find the file.
      let file = await File.findByPk(req.params.id);

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      // If the file does not belong to the user, check if they are staff.
      if (file.userID !== req.user.id) {
        // If they are not staff, return an InvalidFile error. (This is to prevent scraping of files by checking if the response is a 404 or 403.)
        if (!req.user.staff)
          return res.status(404).json(new Errors.InvalidFile());
        else if (
          req.session.permissionFlags !== null &&
          !(req.session.permissionFlags & PermissionFlags.STAFF_READ_FILES)
        )
          return res.status(403).json(new Errors.InsufficientPermissions());
      } else if (
        req.session.permissionFlags !== null &&
        !(req.session.permissionFlags & PermissionFlags.FILE_READ)
      ) {
        return res.status(403).json(new Errors.InsufficientPermissions());
      }

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
  // DELETE /api/files
  '/api/files',
  SessionChecker(),
  BodyValidator({
    ids: new ExtendedValidBodyTypes('array', false, 'string'),
  }),
  KillSwitch(KillSwitches.FILE_DELETE),
  async (
    req: Request<null, null, { ids: string[] }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
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

      // If the user is not staff, remove any files that do not belong to them and change the count accordingly.
      if (!req.user.staff) {
        files = files.filter((file) => file.userID === req.user.id);
        count = files.length;
      }

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
