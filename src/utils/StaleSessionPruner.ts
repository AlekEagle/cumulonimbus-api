import User from '../DB/User.js';
import Session from '../DB/Session.js';
import { logger } from '../index.js';

import { Op } from 'sequelize';

export default async function pruneAllStaleSessions(): Promise<void> {
  const staleSessionTime = Math.floor(Date.now() / 1000);
  const users = await User.findAll();
  let pruned = 0;
  for (const user of users) {
    const staleSessions = await Session.findAndCountAll({
      where: {
        user: user.id,
        exp: {
          [Op.lt]: staleSessionTime,
        },
      },
    });

    pruned += staleSessions.count;

    await Promise.all(staleSessions.rows.map((session) => session.destroy()));
  }
  logger.info(`Pruned ${pruned} expired session(s)`);
  return;
}
