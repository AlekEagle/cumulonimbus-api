// Custom Cumulonimbus Ratelimit Middleware
import { logger } from '../index.js';
import { Errors } from '../utils/TemplateResponses.js';
import RatelimitStorage, {
  RatelimitStorageObject,
} from '../utils/RatelimitStorage.js';

import { RequestHandler, Request, Response } from 'express';

const alwaysIgnoredStatusCodes = [429];

export interface RatelimitOptions {
  /**
   * The duration of the window in milliseconds.
   */
  window: number;
  /**
   * The maximum number of requests a client can make in the window.
   */
  max: number | Cumulonimbus.Utilities.ValueDeterminingMiddleware<number>;
  /**
   * An array of status codes that should not be counted towards the ratelimit.
   */
  ignoreStatusCodes: number[];
  /**
   * An object that contains options related to burst ratelimiting.
   */
  burst: {
    /**
     * The number of requests that can be made in a burst before the punishment is applied.
     */
    max: number;
    /**
     * The duration of the burst window in milliseconds.
     */
    window: number;
  };
  /**
   * A storage object to use for storing ratelimit data. Creates a new one if not provided.
   */
  storage: RatelimitStorage;
}

export const defaultRatelimitOptions: Omit<RatelimitOptions, 'storage'> = {
  window: 60e3, // 1 minute
  max: 100,
  ignoreStatusCodes: [500, 501, 503],
  burst: {
    max: 3,
    window: 1e3, // 1 second
  },
};

function IPResolver(req: Request): string {
  return (
    (Array.isArray(req.headers['x-forwarded-for'])
      ? req.headers['x-forwarded-for'][0]
      : req.headers['x-forwarded-for']) || req.ip!
  );
}

function appendRatelimitHeaders(res: Response): void {
  if (!res.ratelimit)
    // We can't append ratelimit headers if there's no ratelimit object. This shouldn't happen but better safe than sorry.
    throw new Error(
      'Tried to add ratelimit headers when no ratelimit object was present!',
    );
  // Have we already set the headers?
  if (res.ratelimit.headersSet) {
    // If we have, we don't need to do anything.
    logger.debug(
      `Ratelimit headers already set for request: ${res.ratelimit.requestTime}`,
      res.ratelimit.subject,
    );
    return;
  }
  // If we haven't already set the headers, set them now.
  // Append our standard ratelimit headers.
  res.header('RateLimit-Limit', res.ratelimit.data.max.toString());
  res.header(
    'RateLimit-Remaining',
    (
      res.ratelimit.data.max -
      Object.values(res.ratelimit.data.requests).reduce((a, b) => a + b, 0)
    ).toString(),
  );
  res.header(
    'RateLimit-Reset',
    Math.floor(
      (res.ratelimit.data.expiresAt.getTime() - Date.now()) / 1000,
    ).toString(),
  );
  // Mark the headers as set.
  res.ratelimit.headersSet = true;
}

export default function Ratelimit(
  _opts: Partial<RatelimitOptions> = {},
): RequestHandler {
  // Create the options object.
  const options: RatelimitOptions = {
    window: _opts.window || defaultRatelimitOptions.window,
    max: _opts.max || defaultRatelimitOptions.max,
    ignoreStatusCodes:
      _opts.ignoreStatusCodes || defaultRatelimitOptions.ignoreStatusCodes,
    burst: {
      max: _opts.burst?.max || defaultRatelimitOptions.burst.max,
      window: _opts.burst?.window || defaultRatelimitOptions.burst.window,
    },
    storage: _opts.storage || new RatelimitStorage(),
  };
  logger.debug('Initializing Ratelimit Middleware...');
  return async (req, res, next) => {
    const subject = {
        ip: IPResolver(req),
        route: req.route?.path as string | null,
        uid: req.user?.id || null,
      },
      requestTime = Date.now();
    logger.debug('Processing request for: ', subject);
    // Construct the ratelimit object for the response object.
    let ratelimit: RatelimitStorageObject;
    if (!options.storage.has(subject)) {
      // Create a new ratelimit object if one doesn't exist.
      ratelimit = options.storage.create(subject, {
        expiresAt: new Date(requestTime + options.window),
        requests: {},
        max:
          typeof options.max === 'function'
            ? await options.max(req, res)
            : options.max,
      });
    } else ratelimit = options.storage.get(subject)!;
    res.ratelimit = {
      headersSet: false,
      skipped: false,
      get requestTime() {
        return requestTime;
      },
      get subject() {
        return subject;
      },
      get data() {
        return ratelimit.data;
      },
    };
    // res.send override to track the status code of the response.
    // If res._originalSend already exists, it's already been overridden by a Ratelimit middleware, so we don't need to override it again.
    if (!res._originalSend) res._originalSend = res.send;
    res.send = function (body) {
      logger.debug(`Sending response for request: ${requestTime}`, subject);
      if (
        ![...options.ignoreStatusCodes, ...alwaysIgnoredStatusCodes].includes(
          res.statusCode,
        ) &&
        !res.ratelimit!.skipped
      ) {
        ratelimit.pushRequest(requestTime);
        appendRatelimitHeaders(res);
      } else {
        res.header('RateLimit-Skipped', 'true');
      }
      return res._originalSend!.call(this, body);
    };

    const now = Date.now(),
      // Check if the ratelimit quota has been exceeded. (Standard Ratelimit)
      standardQuotaExceeded =
        Object.values(ratelimit.data.requests).reduce((a, b) => a + b, 0) >=
        ratelimit.data.max,
      // Check if the burst window has been exceeded.
      burstQuotaExceeded =
        Object.entries(ratelimit.data.requests)
          .filter(([a]) => now - Number(a) <= options.burst.window)
          .reduce((a, b) => a + b[1], 0) >= options.burst.max;
    if (standardQuotaExceeded || burstQuotaExceeded) {
      appendRatelimitHeaders(res);
      if (standardQuotaExceeded) {
        logger.debug(
          `Standard Ratelimit exceeded for request: ${requestTime}`,
          subject,
        );
        res.header('RateLimit-Reason', 'standard');
      } else if (burstQuotaExceeded) {
        logger.debug(
          `Burst Ratelimit exceeded for request: ${requestTime}`,
          subject,
        );
        res.header('RateLimit-Reason', 'burst');
        // Identify which requests are within the burst window.
        const burstRequests = Object.entries(ratelimit.data.requests).filter(
          ([a]) => now - Number(a) <= options.burst.window,
        );
        // Find the earliest request that when out of the burst window, will allow the burst ratelimit to be lifted.
        // We sort by the timestamp, and then select the most recent request that when moved out of the burst window, will allow the burst ratelimit to be lifted.
        const earliestRequest = burstRequests.sort(
          ([a], [b]) => Number(a) - Number(b),
        )[burstRequests.length - options.burst.max];
        // Override RateLimit-Reset with the time until the burst ratelimit is lifted in seconds if it's sooner than the standard ratelimit.
        if (
          Number(earliestRequest[0]) + options.burst.window - now <
          ratelimit.data.expiresAt.getTime() - now
        ) {
          res.header(
            'RateLimit-Reset',
            Math.ceil(
              (Number(earliestRequest[0]) + options.burst.window - now) / 1000,
            ).toString(),
          );
        }
      }
      res.status(429)._originalSend!(new Errors.RateLimited());
      return;
    } else next();
  };
}
