import { logger, app } from "../../index.js";
import { Errors, Success } from "../../utils/TemplateResponses.js";
import File from "../../DB/File.js";

import Multer from "multer";
import { Response } from "express";
import { Readable } from "node:stream";
import { createWriteStream } from "node:fs";
import {
  FILENAME_LENGTH,
  TROUBLESOME_FILE_EXTENSIONS,
} from "../../utils/Constants.js";
import { join } from "node:path";
import { randomInt } from "node:crypto";
import { ReadableStreamWithFileType, fileTypeStream } from "file-type";

logger.debug("Loading unprivileged/upload.ts...");

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

      // If we have access to the original filename, check if it ends with an extension
      // the FileType library struggles with. If it does, use the original file extension
      // instead of the one the library gives us.
      if (
        req.file &&
        TROUBLESOME_FILE_EXTENSIONS.some((ext) =>
          req.file.originalname.endsWith(ext)
        )
      )
        fileExtension = TROUBLESOME_FILE_EXTENSIONS.find((ext) =>
          req.file.originalname.endsWith(ext)
        );
      else if (file.fileType) fileExtension = file.fileType.ext;

      // Open a write stream to save the file
      const writeStream = createWriteStream(
        join(process.env.BASE_UPLOAD_PATH, `${filename}.${fileExtension}`)
      );

      // Pipe the file into the write stream
      file.pipe(writeStream);

      // Close the write stream when the file is done uploading
      file.on("end", () => {
        writeStream.end();
      });

      // Create a new file in the database
      await File.create({
        filename: `${filename}.${fileExtension}`,
        userID: req.user.id,
        size: req.file.size || req.body.file.length,
      });

      return res.status(201).json({
        url: `https://${req.user.subdomain ? `${req.user.subdomain}.` : ""}${
          req.user.domain
        }/${filename}.${fileExtension}`,
        manage: `${process.env.FRONTEND_BASE_URL}/dashboard/file?filename=${filename}.${fileExtension}`,
        thumbnail: `${process.env.THUMBNAIL_BASE_URL}/${filename}.${fileExtension}`,
      });
    } catch (err) {
      logger.error(err);
      return res.status(500).json(new Errors.Internal());
    }
  }
);
