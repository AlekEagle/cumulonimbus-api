const DeviceDetector = (await import("node-device-detector")).default;
const ClientHints = (await import("node-device-detector/client-hints.js"))
  .default;
import { Request, NextFunction, Response } from "express";

// @ts-ignore
const detector = new DeviceDetector({
  clientIndexes: true,
  deviceIndexes: true,
});
// @ts-ignore
const clientHints = new ClientHints();

export default function (req: Request, _: Response, next: NextFunction) {
  const hints = clientHints.parse(req.headers);
  req.useragent = detector.detect(req.headers["user-agent"], hints);
  next();
}
