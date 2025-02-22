import Chalk from 'chalk';
import { Console } from 'node:console';
import * as NodeUtil from 'node:util';
export enum Level {
  NONE = 0,
  ERROR = 1,
  WARN = 2,
  INFO = 3,
  DEBUG = 4,
}
function addZero(n: number): string {
  return n >= 0 && n < 10 ? '0' + n : n + '';
}
function date(): string {
  let now = new Date();
  return [
    [
      addZero(now.getDate()),
      addZero(now.getMonth() + 1),
      now.getFullYear(),
    ].join('/'),
    [
      addZero(now.getHours()),
      addZero(now.getMinutes()),
      addZero(now.getSeconds()),
    ].join(':'),
  ].join(' ');
}

type LoggerConstructor = Level | 'none' | 'error' | 'warn' | 'info' | 'debug';

export default class Logger extends Console {
  private __logLevel: Level;
  private timestamp: boolean;
  get logLevel(): Level {
    return this.__logLevel;
  }
  private get timestampRender(): string {
    return `${this.timestamp ? `${Chalk.bgBlue(date())} ` : ''}`;
  }
  set logLevel(level: Level) {
    super.log(
      this.timestampRender +
        Chalk.rgb(74, 69, 220)('[LOGLEVEL]') +
        Chalk.reset(' The log level has been changed from ') +
        Chalk.rgb(74, 69, 220)(Level[this.__logLevel]) +
        Chalk.reset(' to ') +
        Chalk.rgb(74, 69, 220)(Level[level]),
    );
    this.__logLevel = level;
  }

  constructor(logLevel: LoggerConstructor, timestamps: boolean = true) {
    super({
      stdout: process.stdout,
      stderr: process.stderr,
    });
    this.timestamp = timestamps;
    if (typeof logLevel === 'string') {
      switch (logLevel as string) {
        case 'none':
          this.__logLevel = Level.NONE;
          break;
        case 'error':
          this.__logLevel = Level.ERROR;
          break;
        case 'warn':
          this.__logLevel = Level.WARN;
          break;
        case 'info':
          this.__logLevel = Level.INFO;
          break;
        case 'debug':
          this.__logLevel = Level.DEBUG;
          break;
      }
    } else this.__logLevel = logLevel as Level;
  }

  error(message: any, ...optionalParams: any[]) {
    if (this.logLevel < Level.ERROR) return;
    super.error(
      this.timestampRender +
        Chalk.rgb(214, 78, 207)('[ERROR]') +
        ' ' +
        Chalk.reset(
          typeof message !== 'string' ? NodeUtil.inspect(message) : message,
        ),
      optionalParams.length > 0
        ? optionalParams
            .map((p) => (typeof p !== 'string' ? NodeUtil.inspect(p) : p))
            .join(' ')
        : '',
    );
  }

  warn(message: any, ...optionalParams: any[]) {
    if (this.logLevel < Level.WARN) return;
    super.log(
      this.timestampRender +
        Chalk.rgb(177, 170, 55)('[WARN]') +
        ' ' +
        Chalk.reset(
          typeof message !== 'string' ? NodeUtil.inspect(message) : message,
        ),
      optionalParams.length > 0
        ? optionalParams
            .map((p) => (typeof p !== 'string' ? NodeUtil.inspect(p) : p))
            .join(' ')
        : '',
    );
  }

  log(message: any, ...optionalParams: any[]) {
    if (this.logLevel < Level.INFO) return;
    super.log(
      this.timestampRender +
        Chalk.rgb(47, 184, 55)('[INFO]') +
        ' ' +
        Chalk.reset(
          typeof message !== 'string' ? NodeUtil.inspect(message) : message,
        ),
      optionalParams.length > 0
        ? optionalParams
            .map((p) => (typeof p !== 'string' ? NodeUtil.inspect(p) : p))
            .join(' ')
        : '',
    );
  }

  info(message: any, ...optionalParams: any[]) {
    this.log(message, ...optionalParams);
  }

  debug(message: any, ...optionalParams: any[]) {
    if (this.logLevel < Level.DEBUG) return;
    super.log(
      this.timestampRender +
        Chalk.rgb(74, 69, 220)('[DEBUG]') +
        ' ' +
        Chalk.reset(
          typeof message !== 'string' ? NodeUtil.inspect(message) : message,
        ),
      optionalParams.length > 0
        ? optionalParams
            .map((p) => (typeof p !== 'string' ? NodeUtil.inspect(p) : p))
            .join(' ')
        : '',
    );
  }

  trace(message: any, ...optionalParams: any[]) {
    if (this.logLevel > Level.DEBUG) return;
    super.trace(
      this.timestampRender +
        Chalk.rgb(30, 186, 198)('[TRACE]') +
        ' ' +
        Chalk.reset(
          typeof message !== 'string' ? NodeUtil.inspect(message) : message,
        ),
      optionalParams.length > 0
        ? optionalParams
            .map((p) => (typeof p !== 'string' ? NodeUtil.inspect(p) : p))
            .join(' ')
        : '',
    );
  }
}
