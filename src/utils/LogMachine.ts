import Logger, { Level } from './Logger.js';

const logMachine = new Logger(
  process.env.ENV === 'development' ? Level.DEBUG : Level.INFO,
);

export default logMachine;
