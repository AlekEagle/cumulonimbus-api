import RedisMessaging from './RedisMessaging.js';
import logger from './LogMachine.js';

let redisMessagingMachine: RedisMessaging | null = null;

function getRedisMessagingMachine(): RedisMessaging | null {
  if (!redisMessagingMachine) {
    if (process.env.REDIS_HOST && process.env.REDIS_PORT) {
      logger.debug('Initializing Redis messaging machine...');
      redisMessagingMachine = new RedisMessaging({
        host: process.env.REDIS_HOST,
        port: parseInt(process.env.REDIS_PORT, 10),
        user: process.env.REDIS_USER,
        pass: process.env.REDIS_PASS,
      });
      logger.debug('Redis messaging machine initialized successfully.');
    } else {
      logger.debug(
        'Redis host or port not specified, Redis messaging machine not initialized.',
      );
      return null;
    }
  }
  return redisMessagingMachine;
}

export default getRedisMessagingMachine();
