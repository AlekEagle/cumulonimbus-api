import { Errors } from '../utils/TemplateResponses.js';
import BaseRatelimitStorage, {
  RatelimitEntry,
} from '../utils/Ratelimit/Storage/index.js';
import {
  RATELIMIT_ALWAYS_IGNORED_STATUS_CODES,
  RATELIMIT_WINDOW,
  RATELIMIT_MAX_REQUESTS,
  RATELIMIT_BURST_MAX,
  RATELIMIT_BURST_WINDOW,
} from '../utils/Constants.js';
import MemoryRatelimitStorage from '../utils/Ratelimit/Storage/Memory.js';
import logger from '../utils/LogMachine.js';
import type { RequestHandler, Request, Response, Send } from 'express';

/**
 * The options for configuring the rate limiting middleware.
 * @property window - The time window for rate limiting in milliseconds.
 * @property max - The maximum number of requests allowed within the time window. Can be a static number or a function that determines the value dynamically.
 * @property ignoreStatusCodes - An array of HTTP status codes to ignore when counting requests.
 * @property burst - Configuration for burst rate limiting, including the maximum number of requests and the burst window.
 * @property storage - The storage mechanism for tracking rate limit data.
 * @property ipAddrIsPreferredSubject - A boolean indicating whether the IP address should be used as the preferred subject for rate limiting.
 * @property bucket - An identifier to share a quota across multiple routes. Overrides the default route-based quota if specified.
 */
export interface RatelimitOptions {
  window: number;
  max: number | Cumulonimbus.Utilities.ValueDeterminingMiddleware<number>;
  ignoreStatusCodes: number[];
  burst: { max: number; window: number };
  storage: BaseRatelimitStorage;
  ipAddrIsPreferredSubject: boolean;
  bucket: string;
}

export const defaultRatelimitOptions: Omit<RatelimitOptions, 'storage'> = {
  window: RATELIMIT_WINDOW,
  max: RATELIMIT_MAX_REQUESTS,
  ignoreStatusCodes: RATELIMIT_ALWAYS_IGNORED_STATUS_CODES,
  burst: { max: RATELIMIT_BURST_MAX, window: RATELIMIT_BURST_WINDOW },
  ipAddrIsPreferredSubject: false,
  bucket: 'global',
};

function IPResolver(req: Request) {
  return req.ip ?? req.socket.remoteAddress ?? 'unknown';
}

function appendHeaders(res: Response): void {
  if (!res.ratelimit)
    throw new Error(
      'Unable to find Ratelimit information on Response. This should not happen!',
    );

  if (res.ratelimit.headersSet) {
    // Someone called the headerAppender after the headers were already set.
    logger.warn(
      'Ratelimit headers have already been set on the response. This should not happen!',
    );
    return;
  }

  // Set the ratelimit headers in the response.
  res.setHeader('RateLimit-Limit', String(res.ratelimit.data.max));
  res.setHeader(
    'RateLimit-Remaining',
    String(
      res.ratelimit.data.max -
        Object.values(res.ratelimit.data.requests).reduce(
          (acc, curr) => acc + curr,
          0,
        ),
    ),
  );
  res.setHeader('RateLimit-Bucket', String(res.ratelimit.subject.bucket));
  // Skip setting the reset header if it has already been set by burst quota.
  if (!res.getHeader('RateLimit-Reset'))
    res.setHeader(
      'RateLimit-Reset',
      String(
        Math.floor(
          (res.ratelimit.data.expiresAt.getTime() - Date.now()) / 1000,
        ),
      ),
    );
  res.ratelimit.headersSet = true;
}

export default function Ratelimit(
  opts: Partial<RatelimitOptions> = {},
): RequestHandler {
  // Construct options
  const options: RatelimitOptions = {
    ...defaultRatelimitOptions,
    ...opts,
    burst: { ...defaultRatelimitOptions.burst, ...opts.burst },
    storage: opts.storage ?? new MemoryRatelimitStorage(),
  };
  logger.debug('Ratelimit constructed for bucket: ' + options.bucket);
  return async (req, res, next) => {
    const resolvedIP = IPResolver(req),
      receivedAt = Date.now();
    // Construct subject for Ratelimits
    const subject = {
      bucket: options.bucket,
      subject: options.ipAddrIsPreferredSubject
        ? resolvedIP
        : (req.user?.id ?? resolvedIP),
    };
    // If the subject resolves down to 'unknown', send them funny song
    if (subject.subject === 'unknown') {
      res.status(400).send('https://youtu.be/snKJPEVbQoE?t=20');
      return;
    }
    // Determine max requests
    const max =
      typeof options.max === 'function'
        ? await options.max(req, res)
        : options.max;

    let rlEntry: RatelimitEntry | null = null;
    if ((rlEntry = await options.storage.get(subject)) === null) {
      rlEntry = await options.storage.set(subject, {
        expiresAt: new Date(receivedAt + options.window),
        requests: {},
        max,
      });
    }
    // Append ratelimit object to the response
    res.ratelimit = {
      headersSet: false,
      skipped: false,
      get requestTime() {
        return receivedAt;
      },
      get subject() {
        return subject;
      },
      get data() {
        return rlEntry.data;
      },
    };

    // Override the default `res.end` so we can handle final ratelimit header setting.
    if (!res._originalSend) res._originalSend = res.send.bind(res);
    const patchedSend: Send = (body) => {
      logger.debug(
        `Sending response for bucket: ${subject.bucket} and subject: ${subject.subject}`,
      );
      if (!res.ratelimit)
        throw new Error(
          'Ratelimit object is missing on response for bucket: ' +
            subject.bucket +
            ' and subject: ' +
            subject.subject,
        );

      // Should we ignore this one boss?
      if (
        [
          ...options.ignoreStatusCodes,
          ...RATELIMIT_ALWAYS_IGNORED_STATUS_CODES,
        ].includes(res.statusCode) ||
        res.ratelimit.skipped
      ) {
        res.header('RateLimit-Skipped', 'true');
      } else {
        rlEntry.pushRequest(receivedAt);
        appendHeaders(res);
      }
      return res._originalSend!(body);
    };
    res.send = patchedSend;

    // Did we exceed the standard ratelimit quota?
    const standardQuotaExceeded =
        Object.values(rlEntry.data.requests).reduce(
          (acc, curr) => acc + curr,
          0,
        ) >= rlEntry.data.max,
      // Did we exceed the burst ratelimit quota?
      burstQuotaExceeded =
        Object.entries(rlEntry.data.requests)
          // Filter requests that fall within the burst window
          .filter(
            ([timestamp]) =>
              receivedAt - Number(timestamp) <= options.burst.window,
          )
          // Count them up to see if the burst quota is exceeded.
          .reduce((acc, [_, curr]) => acc + curr, 0) >= options.burst.max;

    // Did we exceed any ratelimit quota?
    if (standardQuotaExceeded || burstQuotaExceeded) {
      if (standardQuotaExceeded) {
        logger.debug(
          `Standard ratelimit exceeded for bucket: ${subject.bucket} and subject: ${subject.subject}`,
        );
        res.header('RateLimit-Reason', 'standard');
      } else if (burstQuotaExceeded) {
        logger.debug(
          `Burst ratelimit exceeded for bucket: ${subject.bucket} and subject: ${subject.subject}`,
        );
        res.header('RateLimit-Reason', 'burst');

        // Get requests that fall within the burst window.
        const burstWindowRequests = Object.entries(rlEntry.data.requests)
          .filter(
            ([timestamp]) =>
              receivedAt - Number(timestamp) <= options.burst.window,
          )
          // Sort the burst window requests by timestamp in ascending order.
          .sort(
            ([timestampA], [timestampB]) =>
              Number(timestampA) - Number(timestampB),
          );

        res.header(
          'RateLimit-Reset',
          String(
            Math.ceil(
              (Number(burstWindowRequests[0][0]) +
                options.burst.window -
                receivedAt) /
                1000,
            ),
          ),
        );
      }
      res.status(429).json(new Errors.RateLimited());
      return;
    } else next();
  };
}
