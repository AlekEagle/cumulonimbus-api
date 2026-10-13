// Yummy yum yum imports, we love them

// In-house modules because we're cool like that
import './utils/Env.js';
import AuthProvider from './middleware/AuthProvider.js';
import Compression from './middleware/Compression.js';
import DevelopmentCORS from './middleware/DevelopmentCORS.js';
import DeviceDetector from './middleware/DeviceDetector.js';
import Domain from './DB/Domain.js';
import KillSwitch from './middleware/KillSwitch.js';
import logger from './utils/LogMachine.js';
import Ratelimit from './middleware/Ratelimit.js';
import BanHammer from './middleware/BanHammer.js';
import BaseRatelimitStorage from './utils/Ratelimit/Storage/index.js';
import MemoryRatelimitStorage from './utils/Ratelimit/Storage/Memory.js';
import RedisRatelimitStorage from './utils/Ratelimit/Storage/Redis.js';
import pruneAllStaleSessions from './utils/StaleSessionPruner.js';
import { PORT, HOST, API_VERSION } from './utils/Constants.js';
import { initKillSwitches } from './utils/GlobalKillSwitches.js';

// Node modules that are huge and stinky and we don't want to look at them
// (JK we love the developers that made these awesome modules)
import Express, { json } from 'express';
import ms from 'ms';

// Initialize the kill switches
await initKillSwitches();

// Create a new express instance
export const app = Express();

export let ratelimitStore: BaseRatelimitStorage;
if (process.env.REDIS_HOST) {
  logger.debug(
    'Redis host specified, loading Redis-backed ratelimit storage...',
  );
  ratelimitStore = new RedisRatelimitStorage({
    host: process.env.REDIS_HOST,
    port: parseInt(process.env.REDIS_PORT, 10),
    user: process.env.REDIS_USER,
    pass: process.env.REDIS_PASS,
  });
} else {
  logger.debug(
    'No Redis host specified, loading in-memory ratelimit storage...',
  );
  ratelimitStore = new MemoryRatelimitStorage();
}

// Remove the X-Powered-By header because it's stinky and we don't like it
app.disable('x-powered-by');

// Fetch Cloudflare's IP ranges so we know which proxies are trusted
if (process.env.ENV === 'production') {
  try {
    logger.debug('Fetching Cloudflare IP ranges...');
    const cloudflareIPRanges: {
      result: {
        ipv4_cidrs: string[];
        ipv6_cidrs: string[];
      };
      success: boolean;
      errors?: any[];
      messages?: string[];
    } = await (await fetch('https://api.cloudflare.com/client/v4/ips')).json();
    logger.debug('Cloudflare IP ranges fetched successfully.');

    if (!cloudflareIPRanges.success) {
      throw new Error(
        cloudflareIPRanges.messages?.join(', ') ??
          'Failed to fetch Cloudflare IP ranges.',
      );
    }

    // Trust Cloudflare's IP ranges as proxies in production
    app.set('trust proxy', [
      ...cloudflareIPRanges.result.ipv4_cidrs,
      ...cloudflareIPRanges.result.ipv6_cidrs,
    ]);
  } catch (error) {
    logger.error('Failed to fetch Cloudflare IP ranges:', error);
    process.exit(1);
  }
}

// Bloat the express instance with middleware
app.use(
  DevelopmentCORS(),
  Compression(),
  DeviceDetector(),
  json(),
  AuthProvider(),
  Ratelimit({
    storage: ratelimitStore,
    bucket: 'global',
  }),
  BanHammer(),
  KillSwitch(),
);

// Prune all stale sessions every hour
setInterval(pruneAllStaleSessions, ms('1h'));

// Cute little hello world endpoint
app.all('/api/', (_, res) => {
  res.json({ hello: 'world', version: API_VERSION });
});
// Invoke the route importer
import('./routes/index.js');

// listen to things from stuff and things
app.listen(PORT, HOST, () => {
  logger.info(`Listening on port ${PORT}.`);
});

// Check if the default Domain exists, if not create it
const defaultDomain = await Domain.findByPk(process.env.DEFAULT_DOMAIN);
if (!defaultDomain) {
  await Domain.create({
    id: process.env.DEFAULT_DOMAIN,
    subdomains: false,
  });
  logger.info(
    `Default domain ${process.env.DEFAULT_DOMAIN} created in database.`,
  );
}

// TODO: Add way cool E2E tests for the API
