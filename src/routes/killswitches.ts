import { logger, app } from '../index.js';
import { Errors, Success } from '../utils/TemplateResponses.js';
import SessionChecker from '../middleware/SessionChecker.js';
import {
  KillSwitches,
  setKillSwitch,
  getKillSwitches,
} from '../utils/GlobalKillSwitches.js';

import { Request, Response } from 'express';

logger.debug('Loading: Kill switches Route...');

app.get(
  // GET /api/killswitches
  '/api/killswitches',
  SessionChecker(true),
  async (
    req,
    res: Response<
      Cumulonimbus.Structures.KillSwitchList | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      const killSwitches = await getKillSwitches();

      logger.debug(
        `User ${req.user.username} (${req.user.id}) fetched kill switches`,
      );

      res.status(200).json({
        count: killSwitches.length,
        items: killSwitches,
      });
    } catch (e) {
      logger.error(e);
      res.status(500).json(new Errors.Internal());
    }
  },
);

app.put(
  // PUT /api/killswitches/:id
  '/api/killswitches/:id(\\d+)',
  SessionChecker(true),
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.KillSwitchList | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      const killSwitch = Number(req.params.id);

      logger.info(
        `User ${req.user.username} (${req.user.id}) enabled kill switch ${KillSwitches[killSwitch]}(${killSwitch})`,
      );

      const result = await setKillSwitch(killSwitch, true);

      res.status(200).json({
        count: result.length,
        items: result,
      });
    } catch (e) {
      logger.error(e);
      res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/killswitches/:id
  '/api/killswitches/:id(\\d+)',
  SessionChecker(true),
  async (
    req: Request<{ id: string }>,
    res: Response<
      Cumulonimbus.Structures.KillSwitchList | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      const killSwitch = Number(req.params.id);

      logger.info(
        `User ${req.user.username} (${req.user.id}) disabled kill switch ${KillSwitches[killSwitch]}(${killSwitch})`,
      );

      const result = await setKillSwitch(killSwitch, false);

      res.status(200).json({
        count: result.length,
        items: result,
      });
    } catch (e) {
      logger.error(e);
      res.status(500).json(new Errors.Internal());
    }
  },
);

app.delete(
  // DELETE /api/killswitches
  '/api/killswitches',
  SessionChecker(true),
  async (
    req,
    res: Response<
      Cumulonimbus.Structures.KillSwitchList | Cumulonimbus.Structures.Error
    >,
  ) => {
    try {
      logger.info(
        `User ${req.user.username} (${req.user.id}) disabled all kill switches`,
      );

      await Promise.all(
        Object.keys(KillSwitches).map((key) =>
          setKillSwitch(Number(key), false),
        ),
      );

      const result = await getKillSwitches();

      res.status(200).json({
        count: result.length,
        items: result,
      });
    } catch (e) {
      logger.error(e);
      res.status(500).json(new Errors.Internal());
    }
  },
);
