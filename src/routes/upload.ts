import { app, ratelimitStore } from '../index.js';
import logger from '../utils/LogMachine.js';
import { Errors } from '../utils/TemplateResponses.js';
import File from '../DB/File.js';
import SessionChecker from '../middleware/SessionChecker.js';
import {
  FILENAME_LENGTH,
  MAX_FILE_SIZE_BYTES,
  MAX_LIBMAGIC_SCAN_BYTES,
  NESTED_CONTAINERS,
  LIBMAGIC_CONTAINERS,
} from '../utils/Constants.js';
import KillSwitch from '../middleware/KillSwitch.js';
import { KillSwitches } from '../utils/GlobalKillSwitches.js';
import SessionPermissionChecker, {
  PermissionFlags,
} from '../middleware/SessionPermissionChecker.js';
import Ratelimit from '../middleware/Ratelimit.js';

import Multer from 'multer';
import ms from 'ms';
import { LibmagicIO } from 'libmagic-ffi';
import { Request, RequestHandler, Response } from 'express';
import { createWriteStream } from 'node:fs';
import { fileTypeFromBuffer } from 'file-type';
import { join } from 'node:path';
import { randomInt } from 'node:crypto';
import { rm } from 'node:fs/promises';

logger.debug('Loading: Upload Route...');

// Lazy load Libmagic so that a missing system library does not crash the route.
let libmagic: LibmagicIO | undefined;
let libmagicTried = false;
function getLibmagic(): LibmagicIO | undefined {
  if (!libmagicTried) {
    libmagicTried = true;
    try {
      libmagic = new LibmagicIO({ checkInsideCompressedFiles: true });
    } catch (err) {
      logger.error(
        'libmagic unavailable; compressed-tarball nesting will not be detected:',
        err,
      );
    }
  }
  return libmagic;
}

function filenameGen(): string {
  const alphabet =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
  let result = '';

  Array.from({ length: FILENAME_LENGTH }).forEach(() => {
    result += alphabet.charAt(randomInt(alphabet.length));
  });

  return result;
}

/**
 * Content-based extension detection. The stored extension is always chosen by
 * the server from file content; user-supplied filenames and MIME types are
 * display-only and never influence the stored path.
 */
async function detectExtension(buffer: Buffer): Promise<string> {
  const detected = await fileTypeFromBuffer(buffer);
  if (!detected) return 'bin';

  // file-type resolves everything except containers it cannot see through.
  if (!NESTED_CONTAINERS.has(detected.ext)) return detected.ext;

  // Follow the compression and read the description, e.g.
  // "POSIX tar archive (XZ compressed data, checksum CRC64)".
  const magic = getLibmagic();
  if (!magic) return detected.ext;

  const description = await magic.detectBuffer(
    buffer.subarray(0, MAX_LIBMAGIC_SCAN_BYTES),
  );
  // Fall back to the detected extension if libmagic fails or is unavailable.
  if (!description || description.startsWith('ERROR:')) return detected.ext;

  // Description format is "<inner type> (<container>)"; the greedy match takes
  // the outermost (last) parenthesized group as the container.
  const match = /^(.*) \(([^()]*)\)$/.exec(description);
  if (!match || !/tar/i.test(match[1])) return detected.ext;

  const container = LIBMAGIC_CONTAINERS.find(([pattern]) =>
    pattern.test(match[2]),
  );
  return container ? `tar.${container[1]}` : detected.ext;
}

/**
 * Multer rejects oversized files as a middleware error (LIMIT_FILE_SIZE),
 * which would otherwise fall through to the generic 500 handler. Catch it
 * here and return our own error response instead.
 */
function multerUpload(): RequestHandler {
  const upload = Multer({
    limits: { fileSize: MAX_FILE_SIZE_BYTES },
  }).single('file');

  return (req, res, next) => {
    upload(req, res, (err) => {
      if ((err as { code?: string } | undefined)?.code === 'LIMIT_FILE_SIZE')
        return res.status(413).json(new Errors.BodyTooLarge());
      next(err);
    });
  };
}

/**
 * Write the buffer to disk. Rejects (and removes the partial file) on write
 * failure instead of crashing on an unhandled stream 'error' event.
 */
function saveFile(buffer: Buffer, path: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const writeStream = createWriteStream(path);
    writeStream.on('error', (err) => {
      writeStream.destroy();
      rm(path, { force: true }).catch((cleanupErr) => logger.error(cleanupErr));
      reject(err);
    });
    writeStream.on('close', resolve);
    writeStream.end(buffer);
  });
}

app.post(
  // POST /api/upload
  '/api/upload',
  SessionChecker(),
  SessionPermissionChecker(PermissionFlags.UPLOAD_FILE),
  multerUpload(),
  KillSwitch(KillSwitches.FILE_CREATE),
  Ratelimit({
    max: 100,
    window: ms('5m'),
    ignoreStatusCodes: [400, 500],
    burst: {
      max: 5,
      window: ms('10s'),
    },
    storage: ratelimitStore,
  }),
  async (
    req: Request,
    res: Response<
      Cumulonimbus.Structures.SuccessfulUpload | Cumulonimbus.Structures.Error
    >,
  ) => {
    if (!req.user) return res.status(401).json(new Errors.InvalidSession());
    // Check if the user is verified
    if (!req.user.verifiedAt)
      return res.status(403).json(new Errors.EmailNotVerified());

    try {
      // Check if file is present
      if (!req.file && !req.body.file)
        return res.status(400).json(new Errors.MissingFields(['file']));

      const buffer = req.file ? req.file.buffer : Buffer.from(req.body.file);

      // Before we do any work with this buffer, check if it exceeds the maximum allowed size.
      if (buffer.length > MAX_FILE_SIZE_BYTES)
        return res.status(413).json(new Errors.BodyTooLarge());

      const filename = filenameGen();
      const fileExtension = await detectExtension(buffer);
      const storedName = `${filename}.${fileExtension}`;

      // Persist the file before recording it, so the database never points at
      // a file that failed to save.
      await saveFile(buffer, join(process.env.BASE_UPLOAD_PATH, storedName));

      // Create a new file in the database. The original filename is kept as a
      // display-only name and never influences the stored path or extension.
      await File.create({
        id: storedName,
        name: req.file?.originalname ?? null,
        userID: req.user.id,
        size: req.file?.size ?? buffer.length,
      });

      logger.debug(
        `User ${req.user.username} (${req.user.id}) uploaded ${storedName} (${buffer.length} bytes)${
          req.file?.originalname
            ? ` originally named ${req.file.originalname}`
            : ''
        }`,
      );

      return res.status(201).json({
        url: `https://${req.user.subdomain ? `${req.user.subdomain}.` : ''}${
          req.user.domain
        }/${storedName}`,
        manage: `${process.env.FRONTEND_BASE_URL}/dashboard/file?id=${storedName}`,
        thumbnail: `${process.env.THUMBNAIL_BASE_URL}/${storedName}`,
      });
    } catch (err) {
      logger.error(err);
      return res.status(500).json(new Errors.Internal());
    }
  },
);
