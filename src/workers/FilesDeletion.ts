import logger from '../utils/LogMachine.js';
import { sendFilesDeletionFailureEmail } from '../mail/FilesDeletionFailure.js';
import { sendFilesDeletionSuccessEmail } from '../mail/FilesDeletionSuccess.js';
import type User from '../DB/User.js';
import { Worker } from 'node:worker_threads';
import { join } from 'node:path';

const workerScript = join(
  process.cwd(),
  'dist',
  'workers',
  'FilesDeletion-worker.js',
);

const workers: Map<string, Worker> = new Map();

export default async function startFilesDeletionWorker(
  user: User,
  staff?: User,
): Promise<void> {
  logger.info(`Starting files deletion worker for user: ${user.id}`);

  if (workers.has(user.id)) {
    logger.warn(`Files deletion worker already running for user: ${user.id}`);
    return;
  }

  const worker = new Worker(workerScript, {
    workerData: { user: user.toJSON() },
  });

  workers.set(user.id, worker);

  worker.on('exit', async (code) => {
    if (code !== 0) {
      logger.error(
        `Files deletion worker for user ${user.username} (${user.id}) exited with code ${code}`,
      );
      const result = await sendFilesDeletionFailureEmail(user, staff);
      if (!result.success) {
        logger.error(
          `Failed to send files deletion failure email for user ${user.username} (${user.id})`,
          result.error,
        );
      }
    } else {
      const result = await sendFilesDeletionSuccessEmail(user, !!staff);
      if (!result.success) {
        logger.error(
          `Failed to send files deletion success email for user ${user.username} (${user.id})`,
          result.error,
        );
      }
    }
    workers.delete(user.id);
  });
}
