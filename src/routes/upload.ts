import { logger, app } from "../index.js";
import { Errors } from "../utils/TemplateResponses.js";
import File from "../DB/File.js";

import Multer from "multer";
import { Response } from "express";
import { Readable } from "node:stream";
import { createWriteStream } from "node:fs";
import {
  FILENAME_LENGTH,
  TROUBLESOME_FILE_EXTENSIONS,
} from "../utils/Constants.js";
import { join } from "node:path";
import { randomInt } from "node:crypto";
import { ReadableStreamWithFileType, fileTypeStream } from "file-type";

logger.debug("Loading: Upload Route...");

function filenameGen(): string {
  let alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
  let result = "";

  Array.from({ length: FILENAME_LENGTH }).forEach(() => {
    result += alphabet.charAt(randomInt(alphabet.length));
  });

  return result;
}

function createReadableStream(buf: Buffer): Readable {
  const readable = new Readable();
  readable.push(buf);
  readable._read = () => {};
  return readable;
}

app.post(
  // POST /api/upload
  "/api/upload",
  Multer().single("file"),
  async (
    req,
    res: Response<
      Cumulonimbus.Structures.SuccessfulUpload | Cumulonimbus.Structures.Error
    >
  ) => {
    try {
      // Check if the user is logged in
      if (!req.user) return res.status(401).json(new Errors.InvalidSession());

      // Check if file is present
      if (!req.file && !req.body.file)
        return res.status(400).json(new Errors.MissingFields(["file"]));

      // Cram the file into a stream
      let file: ReadableStreamWithFileType,
        filename = filenameGen(),
        fileExtension = "bin";
      if (req.file)
        file = await fileTypeStream(createReadableStream(req.file.buffer));
      else
        file = await fileTypeStream(
          createReadableStream(Buffer.from(req.body.file))
        );

      // If we have access to the original filename:
      if (req.file && req.file.originalname) {
        // Check if it ends with an extension that file-type fails to properly detect
        if (
          TROUBLESOME_FILE_EXTENSIONS.some((ext) =>
            req.file.originalname.endsWith(ext)
          )
        )
          fileExtension = TROUBLESOME_FILE_EXTENSIONS.find((ext) =>
            req.file.originalname.endsWith(ext)
          );
        // If it doesn't have a troublesome file extension, go ahead and check if file-type has one for us
        else if (file.fileType)
          fileExtension = file.fileType.ext; // Use the extension from file-type
        // In case file-type can't determine the proper file extension, attempt to use the extension from the original file name and log a warning.
        else {
          fileExtension =
            req.file.originalname.split(".").slice(1).join(".") || "bin";
          logger.warn(
            `User ${req.user.username} (${req.user.id}) uploaded a file that did not end with a troublesome extension, but file-type failed to determine a suitable extension.\nOriginal filename: ${req.file.originalname}\nExtension used: ${fileExtension}`
          );
        }
      } else {
        // If we don't have access to the original file name, use the extension that file-type provides or fallback to "bin"
        if (file.fileType) fileExtension = file.fileType.ext;
        else
          logger.warn(
            `User ${req.user.username} (${req.user.id}) uploaded a file that file-type failed to determine a suitable file extension. Unfortunately, we don't have the original filename, so it will default to "bin".`
          );
      }

      // Open a write stream to save the file
      const writeStream = createWriteStream(
        join(process.env.BASE_UPLOAD_PATH, `${filename}.${fileExtension}`)
      );

      // Pipe the file into the write stream and close it when done
      file.pipe(writeStream);
      file.on("end", writeStream.close);

      // Create a new file in the database
      await File.create({
        id: `${filename}.${fileExtension}`,
        name: req.file.originalname ? req.file.originalname : null,
        userID: req.user.id,
        size: req.file.size || req.body.file.length,
      });

      logger.debug(
        `User ${req.user.username} (${
          req.user.id
        }) uploaded ${filename}.${fileExtension} (${req.file.size} bytes)${
          req.file.originalname
            ? ` originally named ${req.file.originalname}`
            : ""
        }`
      );

      return res.status(201).json({
        url: `https://${req.user.subdomain ? `${req.user.subdomain}.` : ""}${
          req.user.domain
        }/${filename}.${fileExtension}`,
        manage: `${process.env.FRONTEND_BASE_URL}/dashboard/file?id=${filename}.${fileExtension}`,
        thumbnail: `${process.env.THUMBNAIL_BASE_URL}/${filename}.${fileExtension}`,
      });
    } catch (err) {
      logger.error(err);
      return res.status(500).json(new Errors.Internal());
    }
  }
);
