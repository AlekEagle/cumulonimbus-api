import { logger, app } from '../index.js';
import { Level } from '../utils/Logger.js';
import { Errors } from '../utils/TemplateResponses.js';
import AutoTrim from '../middleware/AutoTrim.js';
import SessionChecker from '../middleware/SessionChecker.js';
import BodyValidator, {
  ExtendedValidBodyTypes,
} from '../middleware/BodyValidator.js';
import SessionPermissionChecker, {
  PermissionFlags,
} from '../middleware/SessionPermissionChecker.js';

import { Request, Response } from 'express';

logger.debug('Loading: Utility Routes...');

app.get(
  // GET /api/loglevel
  '/api/loglevel',
  SessionChecker(true),
  async (
    req: Request,
    res: Response<
      Cumulonimbus.Structures.LogLevel | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());

    console.log(logger.logLevel, Level.DEBUG, Level[Level.DEBUG]);

    // Return the log level.
    return res.status(200).json({
      name: Level[logger.logLevel],
    });
  },
);

app.patch(
  // PATCH /api/loglevel
  '/api/loglevel',
  AutoTrim(),
  SessionChecker(true),
  SessionPermissionChecker(PermissionFlags.STAFF_MODIFY_LOGLEVEL),
  BodyValidator({
    name: 'string',
  }),
  async (
    req: Request<null, null, { name: string }>,
    res: Response<
      Cumulonimbus.Structures.LogLevel | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());

    // Check if the log level provided is valid.
    const level = Level[req.body.name.toUpperCase() as keyof typeof Level];
    if (level === undefined)
      return res.status(400).json(new Errors.InvalidLogLevel());

    // Set the log level.
    logger.logLevel = level;

    // Return the log level.
    return res.status(200).json({
      name: Level[logger.logLevel],
    });
  },
);
