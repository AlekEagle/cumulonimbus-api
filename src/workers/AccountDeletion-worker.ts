import File from '../DB/File.js';
import logger from '../utils/LogMachine.js';
import SecondFactor from '../DB/SecondFactor.js';
import Session from '../DB/Session.js';
import User from '../DB/User.js';
import { init as initDB } from '../DB/index.js';

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { unlink } from 'node:fs/promises';
import { workerData } from 'node:worker_threads';

logger.log(
  `Initializing AccountDeletion worker for user: ${workerData.user.username} (${workerData.user.id})`,
);

await initDB();

// Fetch the user from the worker data
try {
  const user = await User.findByPk(workerData.user.id);
  if (!user) {
    throw new Error('User not found');
  }
  logger.debug(`Fetched user: ${user.id}`);

  // Find and delete all SecondFactors belonging to the user
  try {
    const secondFactors = await SecondFactor.findAll({
      where: { user: user.id },
    });
    logger.debug(
      `Found ${secondFactors.length} second factors for user: ${user.id}`,
    );
    await Promise.all(secondFactors.map(async (sf) => await sf.destroy()));
    logger.debug(`Deleted all second factors for user: ${user.id}`);
  } catch (error) {
    logger.error(
      `Error deleting second factors for user: ${user.id} - `,
      error,
    );
    process.exit(1);
  }

  // Find and delete all Sessions belonging to the user
  try {
    const sessions = await Session.findAll({ where: { user: user.id } });
    logger.debug(`Found ${sessions.length} sessions for user: ${user.id}`);
    await Promise.all(sessions.map(async (session) => await session.destroy()));
    logger.debug(`Deleted all sessions for user: ${user.id}`);
  } catch (error) {
    logger.error(`Error deleting sessions for user: ${user.id} - `, error);
    process.exit(1);
  }

  // Find and delete all Files belonging to the user
  try {
    const files = await File.findAll({ where: { userID: user.id } });
    logger.debug(`Found ${files.length} files for user: ${user.id}`);
    await Promise.all(
      files.map(async (file) => {
        // Delete the thumbnail associated with the file, if it exists
        if (
          existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`))
        ) {
          await unlink(
            join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`),
          );
        }
        // Delete the file itself
        if (existsSync(join(process.env.BASE_UPLOAD_PATH, file.id))) {
          await unlink(join(process.env.BASE_UPLOAD_PATH, file.id));
        } else {
          logger.warn(
            `File not found: ${join(process.env.BASE_UPLOAD_PATH, file.id)}`,
          );
        }
        await file.destroy();
        logger.debug(`Deleted file: ${file.id}`);
      }),
    );
    logger.debug(`Deleted all files for user: ${user.id}`);
  } catch (error) {
    logger.error(`Error deleting files for user: ${user.id} - `, error);
    process.exit(1);
  }

  // Finally, delete the user
  try {
    await user.destroy();
    logger.debug(`Deleted user: ${user.id}`);
  } catch (error) {
    logger.error(`Error deleting user: ${user.id} - `, error);
    process.exit(1);
  }

  process.exit(0);
} catch (error) {
  logger.error(`Error fetching user: ${workerData.user.id} - `, error);
  process.exit(1);
}
