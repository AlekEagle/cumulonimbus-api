// Yummy yum yum imports, we love them

// In-house modules because we're cool like that
import './utils/Env.js';
import AuthProvider from './middleware/AuthProvider.js';
import Compression from './middleware/Compression.js';
import DevelopmentCORS from './middleware/DevelopmentCORS.js';
import DeviceDetector from './middleware/DeviceDetector.js';
import KillSwitch from './middleware/KillSwitch.js';
import Logger, { Level } from './utils/Logger.js';
import Ratelimit from './middleware/Ratelimit.js';
import RatelimitStorage from './utils/RatelimitStorage.js';
import pruneAllStaleSessions from './utils/StaleSessionPruner.js';
import { PORT, API_VERSION } from './utils/Constants.js';
import { initKillSwitches } from './utils/GlobalKillSwitches.js';

// Node modules that are huge and stinky and we don't want to look at them
// (JK we love the developers that made these awesome modules)
import Express, { json } from 'express';
import ms from 'ms';

// Create a new logger instance
export const logger = new Logger(
  process.env.ENV === 'development' ? Level.DEBUG : Level.INFO,
);

// Initialize the kill switches
await initKillSwitches();

// Create a new express instance
export const app = Express();

// Create a new RatelimitStorage Object
export const ratelimitStore = new RatelimitStorage();

// Remove the X-Powered-By header because it's stinky and we don't like it
app.disable('x-powered-by');

// Bloat the express instance with middleware
app.use(
  DevelopmentCORS(),
  Compression(),
  DeviceDetector(),
  json(),
  AuthProvider(),
  Ratelimit({
    storage: ratelimitStore,
  }),
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
app.listen(PORT, () => {
  logger.info(`Listening on port ${PORT}.`);
});

// TODO: Add way cool E2E tests for the API
