import GlobalKillSwitches from '../DB/GlobalKillSwitches.js';
import { logger } from '../index.js';

// These Switches will not affect staff accounts
export enum KillSwitches {
  // Account related killSwitches
  ACCOUNT_CREATE,
  ACCOUNT_MODIFY,
  ACCOUNT_DELETE,
  ACCOUNT_EMAIL_VERIFY, // This will NOT affect account banned emails
  ACCOUNT_LOGIN,
  // File related killSwitches
  FILE_CREATE,
  FILE_MODIFY,
  FILE_DELETE,
  // The Global KillSwitch
  GLOBAL,
}

export type KillSwitch<T extends KillSwitches = KillSwitches> = {
  id: T;
  name: (keyof typeof KillSwitches)[T];
  state: boolean;
};

export type KillSwitchList = Array<KillSwitch>;

// Find or create all the kill switches in the database and log their state
export async function initKillSwitches() {
  logger.info('Initializing kill switches...');
  // Filter out the enum keys that are not numbers
  for (const killSwitch in Object.keys(KillSwitches).filter(
    (v) => !isNaN(Number(v)),
  )) {
    await GlobalKillSwitches.findOrCreate({
      where: { id: killSwitch },
    }).then(([killSwitchDB, created]) => {
      if (created) {
        logger.info(
          `KillSwitch ${KillSwitches[killSwitch]}(${killSwitch}): ${killSwitchDB.state}`,
        );
      } else {
        logger.info(
          `KillSwitch ${KillSwitches[killSwitch]}(${killSwitch}): ${killSwitchDB.state}`,
        );
      }
    });
  }
  logger.info('All kill switches initialized.');
}

// Set the state of a kill switch in the database and cache
export async function setKillSwitch(
  killSwitch: KillSwitches,
  state: boolean,
): Promise<KillSwitchList> {
  if (KillSwitches[killSwitch] === undefined) {
    throw new Error('Invalid kill switch');
  }
  await GlobalKillSwitches.upsert({ id: killSwitch, state });
  logger.info(
    `KillSwitch ${KillSwitches[killSwitch]}(${killSwitch}) set to: ${state}`,
  );
  return await getKillSwitches();
}

// Get the state of a kill switch from the cache
export async function getKillSwitch(
  killSwitch: KillSwitches,
): Promise<boolean> {
  return (await GlobalKillSwitches.findByPk(killSwitch))!.state;
}

// Get all the kill switches from the cache
export async function getKillSwitches(): Promise<KillSwitchList> {
  return (await GlobalKillSwitches.findAll())
    .map((ks) => {
      return {
        id: ks.id,
        name: KillSwitches[ks.id],
        state: ks.state,
      };
    })
    .sort((a, b) => a.id - b.id);
}
