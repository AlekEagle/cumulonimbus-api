// Yummy yum yum imports, we love them

// In-house modules because we're cool like that
import './utils/Env.js';
import Logger, { Level } from './utils/Logger.js';
import { PORT, API_VERSION } from './utils/Constants.js';
import DeviceDetector from './middleware/DeviceDetector.js';
import DevelopmentCORS from './middleware/DevelopmentCORS.js';
import Compression from './middleware/Compression.js';
import QueryStringParser from './middleware/QueryStringParser.js';
import AuthProvider from './middleware/AuthProvider.js';
import defaultRateLimitConfig from './utils/RateLimitUtils.js';

// Node modules that are huge and stinky and we don't want to look at them
// (JK we love the developers that made these awesome modules)
import Express, { json } from 'express';
import ExpressRateLimit from 'express-rate-limit';
import { pruneAllStaleSessions } from './utils/StaleSessionPruner.js';

// Create a new logger instance
export const logger = new Logger(
  process.env.ENV === 'development' ? Level.DEBUG : Level.INFO,
);

// Create a new express instance
export const app = Express();

// Remove the X-Powered-By header because it's stinky and we don't like it
app.disable('x-powered-by');

// Bloat the express instance with middleware
app.use(
  DevelopmentCORS,
  Compression,
  DeviceDetector,
  QueryStringParser({
    keyWithNoValueIsBool: true,
    ignoreKeyWithNoValue: false,
  }),
  json(),
  AuthProvider,
  ExpressRateLimit(defaultRateLimitConfig),
);

// Prune all stale sessions every hour
setInterval(pruneAllStaleSessions, 1000 * 60 * 60);

// Cute little hello world endpoint
app.all('/api/', (_, res) => {
  res.json({ hello: 'world', version: API_VERSION });
});
// Invoke the route importer
import('./routes/index.js');

// listen to things from stuff and things
app.listen(PORT, () => {
  logger.info(`Listening on port ${PORT}`);
});
