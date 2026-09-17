import logger from '../utils/LogMachine.js';
import { sendAccountDeletionSuccessEmail } from '../mail/AccountDeletionSuccess.js';
import { sendAccountDeletionFailureEmail } from '../mail/AccountDeletionFailure.js';
import type User from '../DB/User.js';
import { Worker } from 'node:worker_threads';
import { join } from 'node:path';

const workerScript = join(
  process.cwd(),
  'dist',
  'workers',
  'AccountDeletion-worker.js',
);

const workers: Map<string, Worker> = new Map();

export default async function startAccountDeletionWorker(
  user: User,
  staff?: User,
): Promise<void> {
  logger.info(
    `Starting account deletion worker for user ${user.username} (${user.id})`,
  );
  if (workers.has(user.id)) {
    logger.warn(
      `Account deletion worker for user ${user.username} (${user.id}) is already running`,
    );
    return;
  }

  const worker = new Worker(workerScript, {
    workerData: { user: user.toJSON(), logLevel: logger.logLevel },
  });
  logger.info(
    `Account deletion worker started for user ${user.username} (${user.id})`,
  );

  workers.set(user.id, worker);

  worker.on('exit', async (code) => {
    if (code !== 0) {
      logger.error(
        `Account deletion worker for user ${user.username} (${user.id}) exited with code ${code}`,
      );
      const result = await sendAccountDeletionFailureEmail(user, staff);
      if (!result.success) {
        logger.error(
          'Failed to send account deletion failure email:',
          result.error,
        );
      }
    } else {
      logger.info(
        `Account deletion worker completed successfully for user ${user.username} (${user.id})`,
      );
      const result = await sendAccountDeletionSuccessEmail(user, !!staff);
      if (!result.success) {
        logger.error(
          'Failed to send account deletion success email:',
          result.error,
        );
      }
    }
    workers.delete(user.id);
  });
}
