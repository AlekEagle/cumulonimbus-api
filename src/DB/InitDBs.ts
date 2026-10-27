import { initUser } from './User.js';
import { initSession } from './Session.js';
import { initSecondFactor } from './SecondFactor.js';
import { initInstruction } from './Instruction.js';
import { initGlobalKillSwitches } from './GlobalKillSwitches.js';
import { initDomain } from './Domain.js';
import { initFile } from './File.js';

export default async function initDBs() {
  await initUser();
  await initSession();
  await initSecondFactor();
  await initInstruction();
  await initGlobalKillSwitches();
  await initDomain();
  await initFile();
}
