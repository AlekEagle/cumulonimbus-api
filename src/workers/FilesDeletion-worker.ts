import File from '../DB/File.js';
import logger from '../utils/LogMachine.js';
import { init as initDB } from '../DB/index.js';

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { unlink } from 'node:fs/promises';
import { workerData } from 'node:worker_threads';

logger.log(
  `Initializing files deletion worker for user: ${workerData.user.username} (${workerData.user.id})`,
);

await initDB();

// Wait a moment to ensure database tables are synced
await new Promise((resolve) => setTimeout(resolve, 1000));

// Fetch all files for the user
try {
  const files = await File.findAll({
    where: {
      userID: workerData.user.id,
    },
  });
  logger.debug(
    `Fetched ${files.length} files for user: ${workerData.user.username} (${workerData.user.id})`,
  );
  await Promise.all(
    files.map(async (file) => {
      // Delete the thumbnail associated with the file, if it exists
      if (
        existsSync(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`))
      ) {
        await unlink(join(process.env.BASE_THUMBNAIL_PATH, `${file.id}.webp`));
      }
      // Delete the file itself
      if (existsSync(join(process.env.BASE_UPLOAD_PATH, `${file.id}`))) {
        await unlink(join(process.env.BASE_UPLOAD_PATH, `${file.id}`));
      }

      // Delete the database record for the file
      await file.destroy();
      logger.debug(`Deleted file: ${file.id}`);
    }),
  );
  logger.log(
    `Completed files deletion for user: ${workerData.user.username} (${workerData.user.id})`,
  );
  process.exit(0);
} catch (error) {
  logger.error(
    `Error deleting files for user: ${workerData.user.username} (${workerData.user.id}) - `,
    error,
  );
  process.exit(1);
}
