import Multer from "multer";
import File from "../../utils/DB/File.js";
import { ResponseConstructors } from "../../utils/RequestUtils.js";
import * as FileType from "file-type";
import { randomInt } from "crypto";
import { createWriteStream } from "node:fs";
import { Readable } from "node:stream";

const FILE_EXT = /\.[a-z0-9.-]+$/i;

function newString(length: number) {
  var text = "";
  var possible =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

  for (var i = 0; i < length; i++)
    text += possible.charAt(randomInt(possible.length));

  return text;
}

function createReadableStream(buf: Buffer): Readable {
  const readable = new Readable();
  readable.push(buf);
  readable._read = () => {};
  return readable;
}

const UploadEndpoint: Cumulonimbus.APIEndpointModule = [
  {
    method: "post",
    path: "/upload",
    preHandlers: Multer().single("file"),
    async handler(
      req: Cumulonimbus.Request<{ file: any }>,
      res: Cumulonimbus.Response<Cumulonimbus.Structures.SuccessfulUpload>
    ) {
      if (!req.user)
        res.status(401).json(new ResponseConstructors.Errors.InvalidSession());
      else {
        if (!req.file && !req.body.file)
          res
            .status(400)
            .json(new ResponseConstructors.Errors.MissingFields(["file"]));
        else {
          if (req.file) {
            let filename = newString(10),
              fileStream = createReadableStream(req.file.buffer),
              fileType: FileType.FileTypeResult;

            try {
              fileType = await FileType.fileTypeFromBuffer(req.file.buffer);
            } catch (e) {
              console.error(e);
            }
            let fileExt;
            if (!fileType) {
              if (req.file.originalname.match(FILE_EXT) === null) {
                if (getEncoding(req.file.buffer) === "binary") fileExt = "bin";
                else fileExt = "txt";
              } else
                fileExt = req.file.originalname.match(FILE_EXT)[0].slice(1);
            } else fileExt = fileType.ext;
            const wStream = createWriteStream(
              `/var/www-uploads/${filename}.${fileExt}`
            );
            (fileStream as Readable).pipe(wStream, { end: true });
            await File.create({
              filename: `${filename}.${fileExt}`,
              size: req.file.size,
              userID: req.user.id,
            });
            res.status(201).json({
              url: `https://${
                req.user.subdomain ? `${req.user.subdomain}.` : ""
              }${req.user.domain}/${filename}.${fileExt}`,
              manage: `https://alekeagle.me/dashboard/file?id=${filename}.${fileExt}`,
              thumbnail: `https://previews.alekeagle.me/${filename}.${fileExt}`,
            });
          } else {
            let filename = newString(10),
              buf = Buffer.from(req.body.file),
              fileExt,
              fileStream = createReadableStream(buf);
            if (getEncoding(buf) === "binary") fileExt = "bin";
            else fileExt = "txt";
            const wStream = createWriteStream(
              `/var/www-uploads/${filename}.${fileExt}`
            );
            fileStream.pipe(wStream, { end: true });
            await File.create({
              filename: `${filename}.${fileExt}`,
              size: buf.length,
              userID: req.user.id,
            });
            res.status(201).json({
              url: `https://${
                req.user.subdomain ? `${req.user.subdomain}.` : ""
              }${req.user.domain}/${filename}.${fileExt}`,
              manage: `https://alekeagle.me/dashboard/file?id=${filename}.${fileExt}`,
              thumbnail: `https://previews.alekeagle.me/${filename}.${fileExt}`,
            });
          }
        }
      }
    },
  },
];

export default UploadEndpoint;
