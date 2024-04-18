import { getKillSwitch, KillSwitches } from '../utils/GlobalKillSwitches.js';
import { logger } from '../index.js';
import { Errors } from '../utils/TemplateResponses.js';
import type { RequestHandler } from 'express';

export default function KillSwitch(
  feature: KillSwitches = KillSwitches.GLOBAL,
): RequestHandler {
  return async function (req, res, next) {
    let killSwitchTriggered = -1;

    if (await getKillSwitch(KillSwitches.GLOBAL))
      killSwitchTriggered = KillSwitches.GLOBAL;

    if (killSwitchTriggered === -1 && (await getKillSwitch(feature)))
      killSwitchTriggered = feature;

    if (killSwitchTriggered !== -1) {
      if (req.user?.staff) {
        logger.info(
          `Kill switch ${KillSwitches[killSwitchTriggered]}(${killSwitchTriggered}) triggered but user is staff. Ignoring.`,
        );
        return next();
      }
      logger.warn(
        `Kill switch ${
          KillSwitches[killSwitchTriggered]
        }(${killSwitchTriggered}) triggered.${
          req.user ? ` User: ${req.user.username}(${req.user.id})` : ''
        }`,
      );
      return res
        .status(503)
        .json(new Errors.ServiceUnavailable(killSwitchTriggered));
    }
    logger.debug(
      `Kill switch ${KillSwitches[feature]}(${feature}) not triggered and global kill switch not triggered.`,
    );
    return next();
  };
}
