import User from "../DB/User.js";
import { logger } from "../index.js";

export default async function staleSessionPruner(user: User): Promise<void> {
  const staleSessionTime = Math.floor(Date.now() / 1000);
  if (user.sessions.some((s) => s.exp < staleSessionTime)) {
    const count = user.sessions.filter((s) => s.exp < staleSessionTime).length;
    await user.update({
      sessions: user.sessions.filter((s) => s.exp > staleSessionTime),
    });
    logger.info(
      `Pruned ${count} expired session(s) for user ${user.username} (${user.id})`
    );
  }
  return;
}

export async function pruneAllStaleSessions(): Promise<void> {
  const staleSessionTime = Math.floor(Date.now() / 1000);
  const users = await User.findAll();
  let pruned = 0;
  for (const user of users) {
    if (user.sessions.some((s) => s.exp < staleSessionTime)) {
      const count = user.sessions.filter(
        (s) => s.exp < staleSessionTime
      ).length;
      await user.update({
        sessions: user.sessions.filter((s) => s.exp > staleSessionTime),
      });
      logger.info(
        `Pruned ${count} expired session(s) for user ${user.username} (${user.id})`
      );
      pruned += count;
    }
  }
  logger.info(`Pruned ${pruned} expired session(s)`);
  return;
}
