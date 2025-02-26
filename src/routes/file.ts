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
import { PermissionFlags } from '../middleware/SessionPermissionChecker.js';
import ReverifyIdentity from '../middleware/ReverifyIdentity.js';
import Ratelimit from '../middleware/Ratelimit.js';

import { Op } from 'sequelize';
import { unlink, rename } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { Request, Response } from 'express';
import ms from 'ms';

logger.debug('Loading: File Routes...');

// TODO: Try and see if this endpoint can be separated into standard user vs staff user.
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
    if (!req.user || !req.session)
      return res.status(401).json(new Errors.InvalidSession());
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

      // If the session being used is scoped, check if it has the required scope
      if (
        req.session.permissionFlags !== null &&
        !(req.session.permissionFlags & PermissionFlags.FILE_READ)
      )
        return res.status(404).json(new Errors.InsufficientPermissions());

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
    if (!req.user || !req.session)
      return res.status(401).json(new Errors.InvalidSession());
    try {
      // Find the file.
      let file = await File.findByPk(req.params.id);

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      // If the file does not belong to the user, check if they are staff.
      if (file.userID !== req.user.id) {
        if (!req.user.staff)
          // InvalidFile error for scrape resistance via the API.
          return res.status(404).json(new Errors.InvalidFile());
        else if (
          req.session.permissionFlags !== null &&
          !(req.session.permissionFlags & PermissionFlags.STAFF_READ_FILES)
        )
          // InvalidFile error for scrape resistance via the API.
          return res.status(404).json(new Errors.InvalidFile());
      } else if (
        req.session.permissionFlags !== null &&
        !(req.session.permissionFlags & PermissionFlags.FILE_READ)
      )
        // InvalidFile error for scrape resistance via the API.
        return res.status(404).json(new Errors.InvalidFile());

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
      let file = await File.findByPk(req.params.id);

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      // If the file does not belong to the user, check if they are staff.
      if (file.userID !== req.user.id) {
        if (!req.user.staff)
          // InvalidFile error for scrape resistance via the API.
          return res.status(404).json(new Errors.InvalidFile());
        else if (
          req.session.permissionFlags !== null &&
          !(req.session.permissionFlags & PermissionFlags.STAFF_READ_FILES)
        )
          // InvalidFile error for scrape resistance via the API.
          return res.status(404).json(new Errors.InvalidFile());
      } else if (
        req.session.permissionFlags !== null &&
        !(req.session.permissionFlags & PermissionFlags.FILE_READ)
      )
        // InvalidFile error for scrape resistance via the API.
        return res.status(404).json(new Errors.InvalidFile());

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
  Ratelimit({
    max: 5,
    window: ms('6h'),
    ignoreStatusCodes: [500],
    storage: ratelimitStore,
  }),
  async (
    req: Request<{ id: string }>,
    res: Response<Cumulonimbus.Structures.File | Cumulonimbus.Structures.Error>,
  ) => {
    if (!req.user || !req.session)
      return res.status(401).json(new Errors.InvalidSession());
    try {
      // Find the file.
      let file = await File.findByPk(req.params.id);

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      // If the file does not belong to the user, check if they are staff.
      if (file.userID !== req.user.id) {
        if (!req.user.staff)
          // InvalidFile error for scrape resistance via the API.
          return res.status(404).json(new Errors.InvalidFile());
        else if (
          req.session.permissionFlags !== null &&
          !(req.session.permissionFlags & PermissionFlags.STAFF_READ_FILES)
        )
          // InvalidFile error for scrape resistance via the API.
          return res.status(404).json(new Errors.InvalidFile());
      } else if (
        req.session.permissionFlags !== null &&
        !(req.session.permissionFlags & PermissionFlags.FILE_READ)
      )
        // InvalidFile error for scrape resistance via the API.
        return res.status(404).json(new Errors.InvalidFile());

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

    try {
      // Find the file.
      let file = await File.findByPk(req.params.id);

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      // If the file does not belong to the user, check if they are staff.
      if (file.userID !== req.user.id) {
        if (!req.user.staff)
          // InvalidFile error for scrape resistance via the API.
          return res.status(404).json(new Errors.InvalidFile());
        else if (
          req.session.permissionFlags !== null &&
          !(req.session.permissionFlags & PermissionFlags.STAFF_READ_FILES)
        )
          // InvalidFile error for scrape resistance via the API.
          return res.status(404).json(new Errors.InvalidFile());
      } else if (
        req.session.permissionFlags !== null &&
        !(req.session.permissionFlags & PermissionFlags.FILE_READ)
      )
        // InvalidFile error for scrape resistance via the API.
        return res.status(404).json(new Errors.InvalidFile());

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
  ReverifyIdentity(),
  KillSwitch(KillSwitches.FILE_DELETE),
  Ratelimit({
    max: 1,
    window: ms('3d'),
    ignoreStatusCodes: [404, 500],
    storage: ratelimitStore,
  }),
  async (
    req: Request<null, null, null, { user: string }>,
    res: Response<
      Cumulonimbus.Structures.Success | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user || !req.session)
      return res.status(401).json(new Errors.InvalidSession());
    // If the user did provide a user, check if they are staff.
    if (req.query.user && req.query.user !== 'me') {
      if (
        !req.user.staff ||
        (req.session.permissionFlags !== null &&
          !(req.session.permissionFlags & PermissionFlags.STAFF_MODIFY_FILES))
      )
        return res.status(403).json(new Errors.InsufficientPermissions());

      // If the user is staff but does not have 2FA enabled, deny the request.
      if (req.user.twoFactorBackupCodes === null)
        return res.status(401).json(new Errors.EndpointRequiresSecondFactor());

      try {
        let user = await User.findByPk(req.query.user);

        // Check if a user with that ID exists
        if (!user) return res.status(404).json(new Errors.InvalidUser());

        // Retrieve all of the user's files.
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
          `User ${req.user.username} (${req.user.id}) deleted all files belonging to user ${user.username} (${user.id}). Count: ${count}`,
        );

        return res.status(200).json(new Success.DeleteFiles(count));
      } catch (error) {
        logger.error(error);
        return res.status(500).json(new Errors.Internal());
      }
    }

    if (
      req.session.permissionFlags !== null &&
      !(req.session.permissionFlags & PermissionFlags.FILE_MODIFY)
    )
      return res.status(403).json(new Errors.InsufficientPermissions());

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
    if (!req.user || !req.session)
      return res.status(401).json(new Errors.InvalidSession());
    try {
      // Find the file.
      let file = await File.findByPk(req.params.id);

      // If the file does not exist, return an InvalidFile error.
      if (!file) return res.status(404).json(new Errors.InvalidFile());

      // If the file does not belong to the user, check if they are staff.
      if (file.userID !== req.user.id) {
        // InvalidFile error for scrape resistance via the API.
        if (!req.user.staff)
          return res.status(404).json(new Errors.InvalidFile());
        else if (
          req.session.permissionFlags !== null &&
          !(req.session.permissionFlags & PermissionFlags.STAFF_MODIFY_FILES)
        )
          // InvalidFile error for scrape resistance via the API.
          return res.status(404).json(new Errors.InvalidFile());
      } else if (
        req.session.permissionFlags !== null &&
        !(req.session.permissionFlags & PermissionFlags.FILE_MODIFY)
      )
        // InvalidFile error for scrape resistance via the API.
        return res.status(404).json(new Errors.InvalidFile());

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
        },
      });

      // If the user is not staff, remove any files that do not belong to them and change the count accordingly.
      if (!req.user.staff) {
        files = files.filter((file) => file.userID === req.user!.id);
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
