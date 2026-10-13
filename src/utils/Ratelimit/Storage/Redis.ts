import BaseRatelimitStorage, {
  RatelimitEntry,
  RatelimitSubject,
  RatelimitData,
} from './index.js';
import logger from '../../LogMachine.js';

import { createClient } from 'redis';

export default class RedisRatelimitStorage extends BaseRatelimitStorage {
  public static subjectToKey(subject: RatelimitSubject): string {
    return `ratelimit:${subject.bucket}:${subject.subject}`;
  }

  private client;
  private ready;

  constructor(options: {
    host: string;
    port: number;
    user?: string;
    pass?: string;
  }) {
    logger.debug('Initializing RedisRatelimitStorage');
    super(0);
    this.client = createClient({
      socket: {
        host: options.host,
        port: options.port,
      },
      username: options.user,
      password: options.pass,
    });
    this.ready = this.client.connect();
  }

  public async prune() {
    // NOOP, redis handles expiration automatically
    return 0;
  }

  public async has(subject: RatelimitSubject) {
    await this.ready;
    return (
      (await this.client.exists(
        RedisRatelimitStorage.subjectToKey(subject),
      )) === 1
    );
  }

  public async get(subject: RatelimitSubject) {
    await this.ready;
    const rawData = await this.client.hGetAll(
      RedisRatelimitStorage.subjectToKey(subject),
    );
    if (Object.keys(rawData).length === 0) {
      return null;
    }
    return this.hydrate(subject, rawData);
  }

  public async set(subject: RatelimitSubject, data: RatelimitData) {
    const key = RedisRatelimitStorage.subjectToKey(subject);
    const fields: Record<string, string> = {
      max: String(data.max),
      expiresAt: String(data.expiresAt.getTime()),
    };
    for (const [ts, cost] of Object.entries(data.requests)) {
      fields[`req:${ts}`] = String(cost);
    }

    const ttl = data.expiresAt.getTime() - Date.now();
    if (ttl <= 0) {
      throw new Error(
        `Cannot set ratelimit entry with non-positive TTL for entry (bucket: ${subject.bucket}, subject: ${subject.subject})`,
      );
    }
    await this.ready;
    await this.client
      .multi()
      .del(key)
      .hSet(key, fields)
      .pExpire(key, ttl)
      .exec();

    return new RatelimitEntry(subject, data, this);
  }

  public async delete(subject: RatelimitSubject) {
    const entry = await this.get(subject).catch(() => null);
    if (entry) {
      await this.ready;
      await this.client.del(RedisRatelimitStorage.subjectToKey(subject));
    }
    return entry;
  }

  private hydrate(
    subject: RatelimitSubject,
    raw: Record<string, string>,
  ): RatelimitEntry {
    const data: RatelimitData = {
      expiresAt: new Date(Number(raw.expiresAt)),
      max: Number(raw.max),
      requests: {},
    };
    for (const [field, cost] of Object.entries(raw)) {
      if (field.startsWith('req:')) {
        data.requests[Number(field.slice(4))] = Number(cost);
      }
    }
    return new RatelimitEntry(subject, data, this);
  }
}
